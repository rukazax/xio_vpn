//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 *
 * Adapted for the XIO desktop engine: the owning-process permit is keyed on
 * the current token user SID instead of the WireGuard service SID. See
 * README.md for the exact delta from upstream.
 */

package xiofirewall

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func runTransaction(session uintptr, operation wfpObjectInstaller) error {
	err := fwpmTransactionBegin0(session, 0)
	if err != nil {
		return wrapErr(err)
	}

	err = operation(session)
	if err != nil {
		fwpmTransactionAbort0(session)
		return wrapErr(err)
	}

	err = fwpmTransactionCommit0(session)
	if err != nil {
		fwpmTransactionAbort0(session)
		return wrapErr(err)
	}

	return nil
}

func createWtFwpmDisplayData0(name, description string) (*wtFwpmDisplayData0, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, wrapErr(err)
	}

	descriptionPtr, err := windows.UTF16PtrFromString(description)
	if err != nil {
		return nil, wrapErr(err)
	}

	return &wtFwpmDisplayData0{
		name:        namePtr,
		description: descriptionPtr,
	}, nil
}

func filterWeight(weight uint8) wtFwpValue0 {
	return wtFwpValue0{
		_type: cFWP_UINT8,
		value: uintptr(weight),
	}
}

func wrapErr(err error) error {
	if _, ok := err.(syscall.Errno); !ok {
		return err
	}
	_, file, line, ok := runtime.Caller(1)
	if !ok {
		return fmt.Errorf("Firewall error at unknown location: %w", err)
	}
	return fmt.Errorf("Firewall error at %s:%d: %w", file, line, err)
}

// currentProcessUserSID returns the SID of the user that owns the current
// process token. An interactive desktop engine holds no service SID
// (S-1-5-80-*), so the upstream helper failed here with ERROR_NO_SUCH_GROUP.
func currentProcessUserSID() (*windows.SID, error) {
	var processToken windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &processToken)
	if err != nil {
		return nil, wrapErr(err)
	}
	defer processToken.Close()
	user, err := processToken.GetTokenUser()
	if err != nil {
		return nil, wrapErr(err)
	}
	sid := user.User.Sid
	if sid == nil || !sid.IsValid() {
		return nil, wrapErr(errors.New("current process token has no valid user SID"))
	}
	return sid, nil
}

// getCurrentProcessUserSecurityDescriptor builds the ALE_USER_ID condition
// value: a DACL granting FWP_ACTRL_MATCH_FILTER to this process's user SID.
// Combined with the ALE_APP_ID condition in rules.go it restricts the permit
// to this executable running as this user. Failure to resolve the identity is
// fatal to the caller, keeping the firewall fail-closed.
func getCurrentProcessUserSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	sid, err := currentProcessUserSID()
	if err != nil {
		return nil, err
	}

	access := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: cFWP_ACTRL_MATCH_FILTER,
		AccessMode:        windows.GRANT_ACCESS,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}
	dacl, err := windows.ACLFromEntries(access, nil)
	if err != nil {
		return nil, wrapErr(err)
	}
	sd, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, wrapErr(err)
	}
	err = sd.SetDACL(dacl, true, false)
	if err != nil {
		return nil, wrapErr(err)
	}
	sd, err = sd.ToSelfRelative()
	if err != nil {
		return nil, wrapErr(err)
	}
	runtime.KeepAlive(sid)
	return sd, nil
}

func getCurrentProcessAppID() (*wtFwpByteBlob, error) {
	currentFile, err := os.Executable()
	if err != nil {
		return nil, wrapErr(err)
	}

	curFilePtr, err := windows.UTF16PtrFromString(currentFile)
	if err != nil {
		return nil, wrapErr(err)
	}

	var appID *wtFwpByteBlob
	err = fwpmGetAppIdFromFileName0(curFilePtr, unsafe.Pointer(&appID))
	if err != nil {
		return nil, wrapErr(err)
	}
	return appID, nil
}

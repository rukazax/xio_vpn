//go:build windows

/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.
 *
 * Adapted for the XIO desktop engine: XIO display names, serialized session
 * state, and a process-identity permit instead of a service-SID permit. See
 * README.md for the exact delta from upstream.
 */

package xiofirewall

import (
	"errors"
	"net/netip"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type wfpObjectInstaller func(uintptr) error

// Fundamental XIO-specific WFP objects.
type baseObjects struct {
	provider windows.GUID
	filters  windows.GUID
}

var (
	wfpSessionLock sync.Mutex
	wfpSession     uintptr
)

func createWfpSession() (uintptr, error) {
	sessionDisplayData, err := createWtFwpmDisplayData0("XIO", "XIO dynamic WFP session")
	if err != nil {
		return 0, wrapErr(err)
	}

	session := wtFwpmSession0{
		displayData:          *sessionDisplayData,
		flags:                cFWPM_SESSION_FLAG_DYNAMIC,
		txnWaitTimeoutInMSec: windows.INFINITE,
	}

	sessionHandle := uintptr(0)

	err = fwpmEngineOpen0(nil, cRPC_C_AUTHN_WINNT, nil, &session, unsafe.Pointer(&sessionHandle))
	if err != nil {
		return 0, wrapErr(err)
	}

	return sessionHandle, nil
}

func registerBaseObjects(session uintptr) (*baseObjects, error) {
	bo := &baseObjects{}
	var err error
	bo.provider, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}
	bo.filters, err = windows.GenerateGUID()
	if err != nil {
		return nil, wrapErr(err)
	}

	//
	// Register provider.
	//
	{
		displayData, err := createWtFwpmDisplayData0("XIO", "XIO WFP provider")
		if err != nil {
			return nil, wrapErr(err)
		}
		provider := wtFwpmProvider0{
			providerKey: bo.provider,
			displayData: *displayData,
		}
		err = fwpmProviderAdd0(session, &provider, 0)
		if err != nil {
			// TODO: cleanup entire call chain of these if failure?
			return nil, wrapErr(err)
		}
	}

	//
	// Register filters sublayer.
	//
	{
		displayData, err := createWtFwpmDisplayData0("XIO filters", "Permissive and blocking filters")
		if err != nil {
			return nil, wrapErr(err)
		}
		sublayer := wtFwpmSublayer0{
			subLayerKey: bo.filters,
			displayData: *displayData,
			providerKey: &bo.provider,
			weight:      ^uint16(0),
		}
		err = fwpmSubLayerAdd0(session, &sublayer, 0)
		if err != nil {
			return nil, wrapErr(err)
		}
	}

	return bo, nil
}

// EnableFirewall installs the fail-closed filter set: only the owning engine
// process, the TUN interface, loopback, DHCP and NDP stay permitted; all other
// IPv4 and IPv6 traffic is blocked. The WFP session is dynamic, so every
// provider, sublayer and filter vanishes when the engine closes the handle or
// the process exits. A failed transaction is aborted and the session closed
// before returning, so callers never run with a partial policy.
func EnableFirewall(luid uint64, doNotRestrict bool, restrictToDNSServers []netip.Addr) error {
	wfpSessionLock.Lock()
	defer wfpSessionLock.Unlock()

	if wfpSession != 0 {
		return errors.New("the firewall has already been enabled")
	}

	session, err := createWfpSession()
	if err != nil {
		return wrapErr(err)
	}

	objectInstaller := func(session uintptr) error {
		baseObjects, err := registerBaseObjects(session)
		if err != nil {
			return wrapErr(err)
		}

		err = permitOwningProcess(session, baseObjects, 15)
		if err != nil {
			return wrapErr(err)
		}

		if !doNotRestrict {
			if len(restrictToDNSServers) > 0 {
				err = blockDNS(restrictToDNSServers, session, baseObjects, 15, 14)
				if err != nil {
					return wrapErr(err)
				}
			}

			err = permitLoopback(session, baseObjects, 13)
			if err != nil {
				return wrapErr(err)
			}

			err = permitTunInterface(session, baseObjects, 12, luid)
			if err != nil {
				return wrapErr(err)
			}

			err = permitDHCPIPv4(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			err = permitDHCPIPv6(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			err = permitNdp(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}

			/* TODO: actually evaluate if this does anything and if we need this. It's layer 2; our other rules are layer 3.
			 *  In other words, if somebody complains, try enabling it. For now, keep it off.
			err = permitHyperV(session, baseObjects, 12)
			if err != nil {
				return wrapErr(err)
			}
			*/

			err = blockAll(session, baseObjects, 0)
			if err != nil {
				return wrapErr(err)
			}
		}

		return nil
	}

	err = runTransaction(session, objectInstaller)
	if err != nil {
		fwpmEngineClose0(session)
		return wrapErr(err)
	}

	wfpSession = session
	return nil
}

func DisableFirewall() {
	wfpSessionLock.Lock()
	defer wfpSessionLock.Unlock()

	if wfpSession != 0 {
		fwpmEngineClose0(wfpSession)
		wfpSession = 0
	}
}

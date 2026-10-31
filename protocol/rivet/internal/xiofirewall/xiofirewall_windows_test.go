//go:build windows

package xiofirewall

import (
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// aclWithFirstAce mirrors the ACL header followed by an access-allowed ACE so
// tests can inspect the DACL without reimplementing GetAce.
type aclWithFirstAce struct {
	Revision byte
	Sbz1     byte
	AclSize  uint16
	AceCount uint16
	Sbz2     uint16

	AceType  byte
	AceFlags byte
	AceSize  uint16
	Mask     uint32
	SidStart uint32
}

func tokenUserSID(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	return user.User.Sid
}

// The upstream helper aborted with ERROR_NO_SUCH_GROUP in any non-service
// process. This is the regression guard for that defect.
func TestCurrentProcessUserSIDNeedsNoServiceGroup(t *testing.T) {
	sid, err := currentProcessUserSID()
	if err != nil {
		if errors.Is(err, windows.ERROR_NO_SUCH_GROUP) {
			t.Fatalf("service SID lookup is still required: %v", err)
		}
		t.Fatalf("currentProcessUserSID: %v", err)
	}
	if !sid.IsValid() {
		t.Fatal("current user SID is invalid")
	}
	if !sid.Equals(tokenUserSID(t)) {
		t.Fatalf("SID %s does not match token user %s", sid, tokenUserSID(t))
	}
}

func TestCurrentProcessUserSecurityDescriptor(t *testing.T) {
	sid, err := currentProcessUserSID()
	if err != nil {
		t.Fatalf("currentProcessUserSID: %v", err)
	}
	sd, err := getCurrentProcessUserSecurityDescriptor()
	if err != nil {
		t.Fatalf("getCurrentProcessUserSecurityDescriptor: %v", err)
	}
	if sd == nil || !sd.IsValid() {
		t.Fatal("security descriptor is nil or invalid")
	}
	if sd.Length() == 0 {
		t.Fatal("security descriptor has zero length")
	}
	control, _, err := sd.Control()
	if err != nil {
		t.Fatalf("Control: %v", err)
	}
	if control&windows.SE_SELF_RELATIVE == 0 {
		t.Fatal("security descriptor is not self-relative")
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	if acl == nil || acl.AceCount != 1 {
		t.Fatalf("expected exactly one ACE, got %+v", acl)
	}
	ace := (*aclWithFirstAce)(unsafe.Pointer(acl))
	if ace.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
		t.Fatalf("ACE type = %d, want access-allowed", ace.AceType)
	}
	if ace.Mask != cFWP_ACTRL_MATCH_FILTER {
		t.Fatalf("ACE mask = %#x, want FWP_ACTRL_MATCH_FILTER", ace.Mask)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if !aceSID.IsValid() || !aceSID.Equals(sid) {
		t.Fatalf("ACE SID %v does not match token user %v", aceSID, sid)
	}
	if int(ace.AceSize) != 8+int(sid.Len()) {
		t.Fatalf("ACE size = %d, want %d", ace.AceSize, 8+sid.Len())
	}
}

func TestCurrentProcessAppID(t *testing.T) {
	appID, err := getCurrentProcessAppID()
	if err != nil {
		t.Fatalf("getCurrentProcessAppID: %v", err)
	}
	defer fwpmFreeMemory0(unsafe.Pointer(&appID))
	if appID == nil || appID.size == 0 || appID.data == nil {
		t.Fatalf("invalid APP_ID blob: %+v", appID)
	}
}

func TestIdentityConditions(t *testing.T) {
	appID := wtFwpByteBlob{size: 4}
	sd := wtFwpByteBlob{size: 8}
	conditions := identityConditions(&appID, &sd)

	if got := conditions[0].fieldKey; got != cFWPM_CONDITION_ALE_APP_ID {
		t.Fatalf("condition 0 field = %v, want ALE_APP_ID", got)
	}
	if conditions[0].matchType != cFWP_MATCH_EQUAL {
		t.Fatalf("condition 0 match = %d, want equal", conditions[0].matchType)
	}
	if conditions[0].conditionValue._type != cFWP_BYTE_BLOB_TYPE {
		t.Fatalf("condition 0 type = %d, want byte blob", conditions[0].conditionValue._type)
	}
	if conditions[0].conditionValue.value != uintptr(unsafe.Pointer(&appID)) {
		t.Fatal("condition 0 does not point at the APP_ID blob")
	}

	if got := conditions[1].fieldKey; got != cFWPM_CONDITION_ALE_USER_ID {
		t.Fatalf("condition 1 field = %v, want ALE_USER_ID", got)
	}
	if conditions[1].matchType != cFWP_MATCH_EQUAL {
		t.Fatalf("condition 1 match = %d, want equal", conditions[1].matchType)
	}
	if conditions[1].conditionValue._type != cFWP_SECURITY_DESCRIPTOR_TYPE {
		t.Fatalf("condition 1 type = %d, want security descriptor", conditions[1].conditionValue._type)
	}
	if conditions[1].conditionValue.value != uintptr(unsafe.Pointer(&sd)) {
		t.Fatal("condition 1 does not point at the security descriptor blob")
	}
}

func TestFilterWeight(t *testing.T) {
	w := filterWeight(15)
	if w._type != cFWP_UINT8 {
		t.Fatalf("weight type = %d, want UINT8", w._type)
	}
	if w.value != 15 {
		t.Fatalf("weight value = %d, want 15", w.value)
	}
}

func TestNoActiveSessionDuringTests(t *testing.T) {
	// Automated tests must never install WFP objects; EnableFirewall is only
	// exercised by packaging/acceptance runs on a disposable host.
	if wfpSession != 0 {
		t.Fatal("test suite observed an active WFP session")
	}
}

package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The shared-namespace claim fixture is a Linux flock here; the Windows variant is
// exercised by GOOS=windows build/vet only (no execution proof on this host).
func TestPolicySharedResourceClaimExcludesSecondHelper(t *testing.T) {
	claimPath := filepath.Join(t.TempDir(), "resource-fixture.lock")
	owner := uint32(os.Geteuid())
	claim, err := claimHelperFile(claimPath, owner)
	if err != nil {
		t.Fatal(err)
	}
	plan := testPlanBytes(t, testPlan())
	first := &Runtime{newPolicyNonce: func() (string, error) { return testInstance, nil }}
	first.policy.observe = func() ResourceEvidence { return ResourcesClean }
	if err := first.BindStoreIdentity(testStore); err != nil {
		t.Fatal(err)
	}
	if err := first.BindClientOnly(false); err != nil {
		t.Fatal(err)
	}
	first.BindResourceClaim()
	firstInstance, err := first.policyInstanceNonce()
	if err != nil {
		t.Fatal(err)
	}
	firstRequest := policyRequestFor(t, firstInstance, plan, testGeneration, testTxID, nil)
	validatePlanRequest(t, first, firstRequest)
	if ack, err := first.PolicyReconcile(firstRequest); err != nil || ack["state"] != "ready" {
		t.Fatalf("first helper: %v %v", ack, err)
	}
	// A second helper with a DIFFERENT product store observes the same clean host
	// but cannot claim the shared fixed namespace.
	secondClaim, err := claimHelperFile(claimPath, owner)
	if secondClaim != nil {
		_ = secondClaim.Close()
		t.Fatal("second helper claimed the shared resource namespace")
	}
	if !errors.Is(err, ErrPolicyBusy) {
		t.Fatalf("second claim error %v, want POLICY_BUSY", err)
	}
	second := &Runtime{newPolicyNonce: func() (string, error) { return testOtherGen, nil }}
	second.policy.observe = func() ResourceEvidence { return ResourcesClean }
	if err := second.BindStoreIdentity(strings.Repeat("2", 64)); err != nil {
		t.Fatal(err)
	}
	if err := second.BindClientOnly(false); err != nil {
		t.Fatal(err)
	}
	secondInstance, err := second.policyInstanceNonce()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.PolicyReconcile(policyRequestFor(t, secondInstance, plan, testGeneration, testTxID, nil)); !errors.Is(err, ErrPolicyUnsupported) {
		t.Fatalf("second helper admitted without the shared claim: %v", err)
	}
	// Handover: once the first helper releases the namespace, the second may claim
	// and reconcile. Only one of them can ever be ready at a time.
	if err := claim.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := claimHelperFile(claimPath, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	second.BindResourceClaim()
	secondRequest := policyRequestFor(t, secondInstance, plan, testGeneration, testTxID, nil)
	secondRequest.StoreIdentity = strings.Repeat("2", 64)
	validatePlanRequest(t, second, secondRequest)
	if ack, err := second.PolicyReconcile(secondRequest); err != nil || ack["state"] != "ready" {
		t.Fatalf("namespace handover: %v %v", ack, err)
	}
}

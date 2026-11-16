package desktop

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

// admissionFixture builds a Runtime whose policy admission is ready and whose
// setup pipeline is fully faked, so a rejected activation can be proven to have
// performed zero effects.
type admissionFixture struct {
	runtime  *Runtime
	instance string
	prepares *atomic.Int32
	starts   *atomic.Int32
}

func newAdmissionFixture(t *testing.T, raw string) *admissionFixture {
	t.Helper()
	journal, err := os.CreateTemp(t.TempDir(), "admission-journal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	prepares, starts := &atomic.Int32{}, &atomic.Int32{}
	r := &Runtime{newPolicyNonce: func() (string, error) { return testInstance, nil }}
	r.policy.observe = func() ResourceEvidence { return ResourcesClean }
	if err := r.BindStoreIdentity(testStore); err != nil {
		t.Fatal(err)
	}
	if err := r.BindClientOnly(false); err != nil {
		t.Fatal(err)
	}
	r.BindResourceClaim()
	r.setupOps = &runtimeSetupOps{
		admin: func() bool { return true },
		prepare: func(setup *setupLease) (*networkState, error) {
			prepares.Add(1)
			return &networkState{setup: setup, lock: -1, journal: journal, physical4: true,
				cache: map[string]string{}, resolvers: []string{"192.0.2.2:53"},
				run: func(string, ...string) ([]byte, error) { return nil, nil }}, nil
		},
		start: func(*setupLease, Profile, *networkState) (func(), func() string, error) {
			starts.Add(1)
			return func() {}, func() string { return `{"active":true}` }, nil
		},
	}
	instance, err := r.policyInstanceNonce()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.DisconnectTimeout(1000) })
	return &admissionFixture{runtime: r, instance: instance, prepares: prepares, starts: starts}
}

func (f *admissionFixture) publishManualPlan(t *testing.T, raw string) {
	t.Helper()
	plan := testPlan()
	plan["profiles"] = []map[string]any{{"id": "fixture", "protocol": "awg", "endpoint": "192.0.2.1:51820", "configDigest": policyConfigDigest(raw)}}
	bytes := testPlanBytes(t, plan)
	request := policyRequestFor(t, f.instance, bytes, testGeneration, testTxID, nil)
	validatePlanRequest(t, f.runtime, request)
	ack, err := f.runtime.PolicyReconcile(request)
	if err != nil || ack["state"] != "ready" {
		t.Fatalf("reconcile manual plan: %v %v", ack, err)
	}
}

func (f *admissionFixture) receipt(t *testing.T, mutate func(map[string]any)) string {
	t.Helper()
	receipt := map[string]any{
		"version":         policyVersion,
		"storeIdentity":   testStore,
		"instanceNonce":   f.instance,
		"controllerNonce": testController,
		"transactionId":   testTxID,
		"planGeneration":  testGeneration,
	}
	if mutate != nil {
		mutate(receipt)
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func (f *admissionFixture) assertNoEffects(t *testing.T) {
	t.Helper()
	if f.prepares.Load() != 0 || f.starts.Load() != 0 {
		t.Fatalf("rejected activation caused effects: prepare=%d start=%d", f.prepares.Load(), f.starts.Load())
	}
	if f.runtime.current != nil {
		t.Fatal("rejected activation installed a session")
	}
}

func TestPolicyActivationRequiresReceiptOnceOwnershipBegan(t *testing.T) {
	raw := numericAWG(domainAWG)
	fixture := newAdmissionFixture(t, raw)
	fixture.publishManualPlan(t, raw)
	// Legacy activation must not become a silent automatic fallback.
	if _, err := fixture.runtime.ConnectWithPolicy("fixture", "awg", raw, 1000, 1000, `{"mode":"selectedOnly"}`); !errors.Is(err, ErrPolicyUnsupported) {
		t.Fatalf("legacy activation after ownership: %v", err)
	}
	fixture.assertNoEffects(t)
}

func TestPolicyActivationRejectsDigestMismatchBeforeEffects(t *testing.T) {
	raw := numericAWG(domainAWG)
	fixture := newAdmissionFixture(t, raw)
	fixture.publishManualPlan(t, raw)
	for name, tampered := range map[string]string{
		"trailing newline": raw + "\n",
		"trimmed":          strings.TrimSuffix(raw, "\n"),
		"reformatted":      strings.Replace(raw, " = ", "=", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.runtime.ConnectWithPolicyReceipt("fixture", "awg", tampered, 1000, 1000, `{"mode":"selectedOnly"}`, fixture.receipt(t, nil)); !errors.Is(err, ErrPolicyStale) {
				t.Fatalf("digest mismatch did not fence activation: %v", err)
			}
			fixture.assertNoEffects(t)
		})
	}
	// The exact saved bytes still activate, so the fence is not permanent.
	if _, err := fixture.runtime.ConnectWithPolicyReceipt("fixture", "awg", raw, 30000, 5000, `{"mode":"selectedOnly"}`, fixture.receipt(t, nil)); err != nil {
		t.Fatalf("exact committed bytes rejected: %v", err)
	}
	if fixture.prepares.Load() != 1 || fixture.starts.Load() != 1 {
		t.Fatalf("valid activation effects: prepare=%d start=%d", fixture.prepares.Load(), fixture.starts.Load())
	}
}

func TestPolicyActivationRejectsReceiptIdentityMismatch(t *testing.T) {
	raw := numericAWG(domainAWG)
	fixture := newAdmissionFixture(t, raw)
	fixture.publishManualPlan(t, raw)
	for name, mutate := range map[string]func(map[string]any){
		"instance":   func(receipt map[string]any) { receipt["instanceNonce"] = testOtherGen },
		"store":      func(receipt map[string]any) { receipt["storeIdentity"] = strings.Repeat("9", 64) },
		"controller": func(receipt map[string]any) { receipt["controllerNonce"] = testOtherGen },
		"transaction": func(receipt map[string]any) {
			receipt["transactionId"] = testOtherTx
		},
		"generation":    func(receipt map[string]any) { receipt["planGeneration"] = testOtherGen },
		"receipt ver 2": func(receipt map[string]any) { receipt["version"] = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := fixture.runtime.ConnectWithPolicyReceipt("fixture", "awg", raw, 1000, 1000, `{"mode":"selectedOnly"}`, fixture.receipt(t, mutate))
			if !errors.Is(err, ErrPolicyStale) && !errors.Is(err, ErrPolicyInvalid) {
				t.Fatalf("identity mismatch admitted: %v", err)
			}
			fixture.assertNoEffects(t)
		})
	}
	// Malformed attachment JSON is invalid, never ignored.
	if _, err := fixture.runtime.ConnectWithPolicyReceipt("fixture", "awg", raw, 1000, 1000, `{"mode":"selectedOnly"}`, `{"version":1}`); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("malformed receipt: %v", err)
	}
	fixture.assertNoEffects(t)
}

func TestPolicyActivationRejectsForeignCandidate(t *testing.T) {
	raw := numericAWG(domainAWG)
	fixture := newAdmissionFixture(t, raw)
	fixture.publishManualPlan(t, raw)
	if _, err := fixture.runtime.ConnectWithPolicyReceipt("other", "awg", raw, 1000, 1000, `{"mode":"selectedOnly"}`, fixture.receipt(t, nil)); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("candidate outside the committed plan: %v", err)
	}
	if _, err := fixture.runtime.ConnectWithPolicyReceipt("fixture", "rivet-h3", raw, 1000, 1000, `{"mode":"selectedOnly"}`, fixture.receipt(t, nil)); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("protocol outside the committed plan: %v", err)
	}
	fixture.assertNoEffects(t)
}

func TestPolicyActivationRejectedWhileWriterOwned(t *testing.T) {
	raw := numericAWG(domainAWG)
	fixture := newAdmissionFixture(t, raw)
	fixture.publishManualPlan(t, raw)
	plan := testPlan()
	plan["profiles"] = []map[string]any{{"id": "fixture", "protocol": "awg", "endpoint": "192.0.2.1:51820", "configDigest": policyConfigDigest(raw)}}
	request := policyRequestFor(t, fixture.instance, testPlanBytes(t, plan), testOtherGen, testOtherTx, mustSpan(t, testGeneration))
	if _, err := fixture.runtime.PolicyBegin(request); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.runtime.ConnectWithPolicyReceipt("fixture", "awg", raw, 1000, 1000, `{"mode":"selectedOnly"}`, fixture.receipt(t, nil)); !errors.Is(err, ErrPolicyBusy) {
		t.Fatalf("activation during policy reservation: %v", err)
	}
	fixture.assertNoEffects(t)
}

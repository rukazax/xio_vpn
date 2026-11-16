package desktop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func numericAWG2(raw string) string {
	return strings.Replace(raw, "fr-host.fr", "192.0.2.2", 1)
}

func newPolicyTestRuntime(t *testing.T, evidence func() ResourceEvidence) (*Runtime, string) {
	t.Helper()
	r := &Runtime{newPolicyNonce: func() (string, error) { return testInstance, nil }}
	if evidence != nil {
		r.policy.observe = evidence
	}
	if err := r.BindStoreIdentity(testStore); err != nil {
		t.Fatal(err)
	}
	if err := r.BindClientOnly(false); err != nil {
		t.Fatal(err)
	}
	// Versioned publication requires the shared fixed-resource claim as well as the
	// launch store binding.
	r.BindResourceClaim()
	instance, err := r.policyInstanceNonce()
	if err != nil {
		t.Fatal(err)
	}
	return r, instance
}

func policyRequestFor(t *testing.T, instance string, plan json.RawMessage, generation, transaction string, expected *string) PolicyRequest {
	t.Helper()
	request := testRequest(t, plan, generation, transaction, expected)
	request.InstanceNonce = instance
	return request
}

func mustSpan(t *testing.T, value string) *string {
	t.Helper()
	return &value
}

// testConfigFor returns the saved configuration bytes whose digest the shared
// test plan advertises. It is only a fixture lookup, never a production rule.
func testConfigFor(t *testing.T, profile policyProfile) string {
	t.Helper()
	switch hex.EncodeToString(profile.Digest[:]) {
	case policyConfigDigest(testAWGConfig):
		return testAWGConfig
	case policyConfigDigest(numericAWG(domainAWG)):
		return numericAWG(domainAWG)
	case policyConfigDigest(numericAWG2(domainAWG)):
		return numericAWG2(domainAWG)
	case policyConfigDigest(syntheticXrayConfig):
		return syntheticXrayConfig
	}
	t.Fatalf("no fixture config for profile %q", profile.ID)
	return ""
}

func validationEnvelopeFor(t *testing.T, plan *policyPlan, transaction, generation string) json.RawMessage {
	t.Helper()
	document := validationDocumentWithReceipt(plan, transaction, generation)
	documentBytes, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(documentBytes)
	configs := make([]map[string]any, len(plan.Profiles))
	for i, profile := range plan.Profiles {
		configs[i] = map[string]any{
			"id":          profile.ID,
			"bytesBase64": base64.StdEncoding.EncodeToString([]byte(testConfigFor(t, profile))),
		}
	}
	envelope := map[string]any{
		"schema":              1,
		"documentDigest":      hex.EncodeToString(digest[:]),
		"documentBytesBase64": base64.StdEncoding.EncodeToString(documentBytes),
		"configs":             configs,
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// validationDocumentFor derives a consistent durable document from the plan. It
// exists only to let the pre-validation helper tests exercise the mandatory
// validation path; the projection-specific tests craft their documents by hand.
func validationDocumentFor(plan *policyPlan) map[string]any {
	profiles := make([]map[string]any, len(plan.Profiles))
	owned := make(map[string]any, len(plan.Profiles))
	for i, profile := range plan.Profiles {
		profiles[i] = map[string]any{"id": profile.ID, "name": profile.ID, "protocol": profile.Protocol, "endpoint": profile.Endpoint}
		owned[fmt.Sprintf("k%d", i)] = profile.ID
	}
	document := map[string]any{
		"schema":   2,
		"profiles": profiles,
		"users": []map[string]any{{
			"id": "user-1", "name": "User", "serverId": "server-1",
			"profileIds": owned, "revoked": false, "admin": false, "userLimit": 0,
		}},
		"legalRecord": map[string]any{
			"revision": acceptedConsentRevision, "timestamp": "2026-11-06T09:00:00Z",
			"textSha256": strings.Repeat("a", 64), "language": "ru",
		},
		"connectionPolicy":       map[string]any{"mode": plan.Mode, "roundMillis": plan.PolicyRound},
		"priorityProtocol":       plan.PriorityProtocol,
		"siteCheckEnabled":       plan.SiteCheck,
		"checkSite":              plan.Site,
		"protocolTimeoutSeconds": plan.TimeoutSeconds,
		"vpnDisclosure":          plan.VPNDisclosure,
	}
	if plan.SelectedID != nil {
		document["selected"] = *plan.SelectedID
	} else {
		document["selected"] = nil
	}
	return document
}

// validationDocumentWithReceipt adds the mandatory receipt identity, which is
// itself one of the strictly validated authority objects.
func validationDocumentWithReceipt(plan *policyPlan, transaction, generation string) map[string]any {
	document := validationDocumentFor(plan)
	document["connectionPlanReceipt"] = map[string]any{
		"schema":         1,
		"transactionId":  transaction,
		"planGeneration": generation,
		"plan":           json.RawMessage(plan.raw),
	}
	return document
}

func validatePlanRequest(t *testing.T, r *Runtime, request PolicyRequest) {
	t.Helper()
	plan, err := parsePolicyPlan(request.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.PolicyValidate(request, validationEnvelopeFor(t, plan, request.TransactionID, request.PlanGeneration)); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func reconcilePlan(t *testing.T, r *Runtime, instance string, plan json.RawMessage, generation, transaction string) map[string]any {
	t.Helper()
	request := policyRequestFor(t, instance, plan, generation, transaction, nil)
	validatePlanRequest(t, r, request)
	ack, err := r.PolicyReconcile(request)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if ack["state"] != "ready" {
		t.Fatalf("reconcile state %v, want ready", ack["state"])
	}
	return ack
}

func reconcileClean(t *testing.T, r *Runtime, instance string, plan json.RawMessage) map[string]any {
	t.Helper()
	return reconcilePlan(t, r, instance, plan, testGeneration, testTxID)
}

func TestPolicyLaunchBindingIsReportedAndImmutable(t *testing.T) {
	r := &Runtime{newPolicyNonce: func() (string, error) { return testInstance, nil }}
	caps, err := r.PolicyCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	if caps["launchBound"] != false {
		t.Fatalf("unbound helper claims a launch binding: %v", caps)
	}
	if err := r.BindStoreIdentity(testStore); err != nil {
		t.Fatal(err)
	}
	caps, err = r.PolicyCapabilities()
	if err != nil || caps["launchBound"] != true || caps["state"] != "blocked" {
		t.Fatalf("launch binding not reported honestly: %v %v", caps, err)
	}
	if caps["resourceClaimed"] != false {
		t.Fatalf("resource claim reported without one: %v", caps)
	}
	r.BindResourceClaim()
	caps, err = r.PolicyCapabilities()
	if err != nil || caps["resourceClaimed"] != true {
		t.Fatalf("shared resource claim not reported: %v %v", caps, err)
	}
	if err := r.BindStoreIdentity(strings.Repeat("9", 64)); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("launch binding replaced: %v", err)
	}
}

func TestPolicyFreshRuntimeRequiresReconcile(t *testing.T) {
	r, instance := newPolicyTestRuntime(t, func() ResourceEvidence { return ResourcesClean })
	caps, err := r.PolicyCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	if caps["version"] != policyVersion || caps["instanceNonce"] != instance {
		t.Fatalf("capabilities identity: %v", caps)
	}
	if caps["state"] != "blocked" || caps["resourceState"] != string(ResourcesUnknown) {
		t.Fatalf("a fresh Runtime must be blocked with unknown resources: %v", caps)
	}
	begin := policyRequestFor(t, instance, testPlanBytes(t, testPlan()), testGeneration, testTxID, nil)
	if _, err := r.PolicyBegin(begin); err == nil {
		t.Fatal("fresh Runtime published without reconciliation")
	} else {
		expectPolicyError(t, err, ErrPolicyUnknown)
	}
	caps, err = r.PolicyCapabilities()
	if err != nil || caps["state"] != "blocked" {
		t.Fatalf("failed begin changed readiness: %v %v", caps, err)
	}
	// A clean, known host is the normal happy path: reconcile makes it ready.
	ack := reconcileClean(t, r, instance, testPlanBytes(t, testPlan()))
	if len(ack) != 6 {
		t.Fatalf("ACK has %d fields, want exactly 6: %v", len(ack), ack)
	}
	state, err := r.PolicyState()
	if err != nil {
		t.Fatal(err)
	}
	if state["state"] != "ready" || state["resourceState"] != string(ResourcesClean) {
		t.Fatalf("reconciled state: %v", state)
	}
	receipt, ok := state["receipt"].(map[string]any)
	if !ok || receipt["planGeneration"] != testGeneration || receipt["storeIdentity"] != testStore {
		t.Fatalf("committed receipt: %v", state)
	}
}

func TestPolicyCommitOnlyAfterBeginAndExpectedGeneration(t *testing.T) {
	r, instance := newPolicyTestRuntime(t, func() ResourceEvidence { return ResourcesClean })
	plan := testPlanBytes(t, testPlan())
	reconcileClean(t, r, instance, plan)
	// expectedGeneration is an exact CAS, not an ordering integer.
	staleExpected := policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testOtherGen))
	if _, err := r.PolicyBegin(staleExpected); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("wrong expected generation: %v", err)
	}
	request := policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration))
	ack, err := r.PolicyBegin(request)
	if err != nil {
		t.Fatal(err)
	}
	if ack["state"] != "pending" || len(ack) != 6 {
		t.Fatalf("begin ACK: %v", ack)
	}
	validatePlanRequest(t, r, request)
	// A second writer while reserved is busy, never silently queued.
	if _, err := r.PolicyBegin(policyRequestFor(t, instance, plan, testGeneration, "22222222222222222222222222222222", mustSpan(t, testOtherGen))); err == nil {
		t.Fatal("second writer admitted during reservation")
	} else {
		expectPolicyError(t, err, ErrPolicyBusy)
	}
	if _, err := r.PolicyCommit(policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration))); err != nil {
		t.Fatal(err)
	}
	state, err := r.PolicyState()
	if err != nil {
		t.Fatal(err)
	}
	if state["state"] != "ready" || state["receipt"].(map[string]any)["planGeneration"] != testOtherGen {
		t.Fatalf("commit did not publish: %v", state)
	}
	// The old generation can no longer be reserved.
	old := policyRequestFor(t, instance, plan, "33333333333333333333333333333333", "44444444444444444444444444444444", mustSpan(t, testGeneration))
	if _, err := r.PolicyBegin(old); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("retired generation re-reserved: %v", err)
	}
}

func TestPolicyNonCleanEvidenceBlocksWithoutReady(t *testing.T) {
	for _, evidence := range []ResourceEvidence{ResourcesOwned, ResourcesUnknown} {
		t.Run(string(evidence), func(t *testing.T) {
			current := evidence
			r, instance := newPolicyTestRuntime(t, func() ResourceEvidence { return current })
			plan := testPlanBytes(t, testPlan())
			request := policyRequestFor(t, instance, plan, testGeneration, testTxID, nil)
			validatePlanRequest(t, r, request)
			ack, err := r.PolicyReconcile(request)
			if err != nil {
				t.Fatal(err)
			}
			if ack["state"] != "blocked" {
				t.Fatalf("non-clean evidence reported %v", ack["state"])
			}
			state, err := r.PolicyState()
			if err != nil {
				t.Fatal(err)
			}
			if state["state"] != "blocked" || state["resourceState"] != string(evidence) {
				t.Fatalf("blocked state: %v", state)
			}
			if state["receipt"] != nil {
				t.Fatalf("blocked helper published a receipt: %v", state)
			}
			// Recovery is explicit: after the failed transaction settles, a fresh
			// publication with clean evidence makes the helper ready.
			current = ResourcesClean
			reconcilePlan(t, r, instance, plan, testGeneration, testOtherTx)
		})
	}
}

func TestPolicyPhysicalObservationRunsOutsideRuntimeMutex(t *testing.T) {
	r, instance := newPolicyTestRuntime(t, func() ResourceEvidence { return ResourcesClean })
	plan := testPlanBytes(t, testPlan())
	reconcileClean(t, r, instance, plan)
	request := policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration))
	if _, err := r.PolicyBegin(request); err != nil {
		t.Fatal(err)
	}
	validatePlanRequest(t, r, request)
	entered, release := make(chan struct{}), make(chan struct{})
	var observations atomic.Int32
	r.policy.observe = func() ResourceEvidence {
		if observations.Add(1) == 1 {
			close(entered)
			<-release
		}
		return ResourcesClean
	}
	done := make(chan map[string]any, 1)
	go func() {
		ack, err := r.PolicyCommit(policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration)))
		if err != nil {
			done <- map[string]any{"error": err.Error()}
			return
		}
		done <- ack
	}()
	<-entered
	// The physical observation must not hold the Runtime admission mutex.
	if !r.mu.TryLock() {
		t.Fatal("read-only resource observation held the Runtime mutex")
	}
	r.mu.Unlock()
	state, err := r.PolicyState()
	if err != nil {
		t.Fatal(err)
	}
	if state["state"] != "pending" || len(state) == 0 {
		t.Fatalf("in-flight commit reported: %v", state)
	}
	if _, err := r.PolicyBegin(policyRequestFor(t, instance, plan, "55555555555555555555555555555555", "66666666666666666666666666666666", mustSpan(t, testOtherGen))); !errors.Is(err, ErrPolicyBusy) {
		t.Fatalf("writer admitted a successor while IO was outstanding: %v", err)
	}
	close(release)
	select {
	case result := <-done:
		if result["state"] != "ready" {
			t.Fatalf("commit after observation: %v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("commit did not settle")
	}
}

func TestPolicyAbortKeepsPhysicalOwnershipUntilSettled(t *testing.T) {
	r, instance := newPolicyTestRuntime(t, func() ResourceEvidence { return ResourcesClean })
	plan := testPlanBytes(t, testPlan())
	reconcileClean(t, r, instance, plan)
	request := policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration))
	if _, err := r.PolicyBegin(request); err != nil {
		t.Fatal(err)
	}
	validatePlanRequest(t, r, request)
	entered, release := make(chan struct{}), make(chan struct{})
	r.policy.observe = func() ResourceEvidence {
		close(entered)
		<-release
		return ResourcesClean
	}
	commitDone := make(chan map[string]any, 1)
	go func() {
		ack, err := r.PolicyCommit(policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration)))
		if err != nil {
			commitDone <- map[string]any{"error": err.Error()}
			return
		}
		commitDone <- ack
	}()
	<-entered
	abortDone := make(chan error, 1)
	go func() {
		ack, err := r.PolicyAbort(PolicyAbortRequest{Version: policyVersion, InstanceNonce: instance, TransactionID: testOtherTx})
		if err == nil && ack["state"] != "blocked" {
			err = policyStale("abort ACK %v", ack["state"])
		}
		abortDone <- err
	}()
	select {
	case err := <-abortDone:
		t.Fatalf("abort released ownership before physical IO settled: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case result := <-commitDone:
		if result["state"] != "blocked" {
			t.Fatalf("revoked commit produced %v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("commit did not settle")
	}
	if err := <-abortDone; err != nil {
		t.Fatalf("abort: %v", err)
	}
	state, err := r.PolicyState()
	if err != nil {
		t.Fatal(err)
	}
	if state["state"] != "blocked" {
		t.Fatalf("abort resurrected ready state: %v", state)
	}
	// A blocked helper exposes the committed generation only as a CAS input; the
	// six-field receipt must not be present as activation authority.
	if state["receipt"] != nil {
		t.Fatalf("blocked helper offered an activation receipt: %v", state)
	}
	if state["casGeneration"] != testGeneration {
		t.Fatalf("expected-generation CAS input lost: %v", state)
	}
	// The previous committed plan stays recorded for expectedGeneration CAS, but
	// a blocked helper cannot admit it.
	receipt := &policyReceipt{
		Version: policyVersion, StoreIdentity: testStore, InstanceNonce: instance,
		ControllerNonce: testController, TransactionID: testTxID, PlanGeneration: testGeneration,
	}
	r.mu.Lock()
	admissionErr := r.admitPolicyLocked("fixture", "awg", domainAWG, receipt)
	r.mu.Unlock()
	if !errors.Is(admissionErr, ErrPolicyStale) {
		t.Fatalf("blocked helper admitted the old receipt: %v", admissionErr)
	}
	// A late commit can never revive the revoked transaction.
	if _, err := r.PolicyCommit(policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration))); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("late commit after abort: %v", err)
	}
	// An exact retry of the aborted transaction re-ACKs the settled blocked
	// receipt; it can never return ready or a new generation.
	replayed, err := r.PolicyAbort(PolicyAbortRequest{Version: policyVersion, InstanceNonce: instance, TransactionID: testOtherTx})
	if err != nil || replayed["state"] != "blocked" {
		t.Fatalf("replayed abort: %v %v", replayed, err)
	}
	if replayed["planGeneration"] != testOtherGen || replayed["transactionId"] != testOtherTx {
		t.Fatalf("replayed abort identity: %v", replayed)
	}
}

func TestPolicyIdempotentRetryAndContentBinding(t *testing.T) {
	var observations atomic.Int32
	r, instance := newPolicyTestRuntime(t, func() ResourceEvidence { observations.Add(1); return ResourcesClean })
	plan := testPlanBytes(t, testPlan())
	reconcileClean(t, r, instance, plan)
	request := policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration))
	if _, err := r.PolicyBegin(request); err != nil {
		t.Fatal(err)
	}
	validatePlanRequest(t, r, request)
	if _, err := r.PolicyCommit(request); err != nil {
		t.Fatal(err)
	}
	if observations.Load() != 2 { // one reconcile + one commit
		t.Fatalf("unexpected observation count %d", observations.Load())
	}
	ack, err := r.PolicyCommit(request)
	if err != nil || ack["state"] != "ready" {
		t.Fatalf("idempotent retry: %v %v", ack, err)
	}
	if observations.Load() != 2 {
		t.Fatal("idempotent retry repeated physical work")
	}
	// Same transaction id with different plan content is rejected.
	changed := testPlan()
	changed["priorityProtocol"] = "rivet-h3"
	changedRequest := policyRequestFor(t, instance, testPlanBytes(t, changed), testOtherGen, testOtherTx, mustSpan(t, testGeneration))
	if _, err := r.PolicyCommit(changedRequest); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("different content under one transaction: %v", err)
	}
	if _, err := r.PolicyAbort(PolicyAbortRequest{Version: policyVersion, InstanceNonce: instance, TransactionID: request.TransactionID}); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("abort of committed transaction: %v", err)
	}
	// Reserved content cannot be swapped before commit.
	next := policyRequestFor(t, instance, plan, "77777777777777777777777777777777", "88888888888888888888888888888888", mustSpan(t, testOtherGen))
	if _, err := r.PolicyBegin(next); err != nil {
		t.Fatal(err)
	}
	validatePlanRequest(t, r, next)
	swapped := policyRequestFor(t, instance, testPlanBytes(t, changed), "77777777777777777777777777777777", "88888888888888888888888888888888", mustSpan(t, testOtherGen))
	if _, err := r.PolicyCommit(swapped); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("reserved content swapped: %v", err)
	}
	if _, err := r.PolicyAbort(PolicyAbortRequest{Version: policyVersion, InstanceNonce: instance, TransactionID: next.TransactionID}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyIdentityFencing(t *testing.T) {
	r, instance := newPolicyTestRuntime(t, func() ResourceEvidence { return ResourcesClean })
	plan := testPlanBytes(t, testPlan())
	otherStore := "9999999999999999999999999999999999999999999999999999999999999999"

	wrongInstance := policyRequestFor(t, instance, plan, testGeneration, testTxID, nil)
	wrongInstance.InstanceNonce = testOtherGen
	if _, err := r.PolicyReconcile(wrongInstance); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("wrong instance nonce: %v", err)
	}
	if _, err := r.PolicyBegin(wrongInstance); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("wrong instance nonce begin: %v", err)
	}
	reconcileClean(t, r, instance, plan)
	wrongStore := policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration))
	wrongStore.StoreIdentity = otherStore
	if _, err := r.PolicyBegin(wrongStore); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("store identity mismatch: %v", err)
	}
	// A launch binding cannot be replaced by an RPC.
	bound := &Runtime{newPolicyNonce: func() (string, error) { return testInstance, nil }}
	bound.policy.observe = func() ResourceEvidence { return ResourcesClean }
	if err := bound.BindStoreIdentity(otherStore); err != nil {
		t.Fatal(err)
	}
	if err := bound.BindClientOnly(false); err != nil {
		t.Fatal(err)
	}
	bound.BindResourceClaim()
	instance2, err := bound.policyInstanceNonce()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bound.PolicyReconcile(policyRequestFor(t, instance2, plan, testGeneration, testTxID, nil)); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("launch binding replaced: %v", err)
	}
	if err := bound.BindStoreIdentity(testStore); err == nil {
		t.Fatal("launch binding replaced by a second bind")
	}
}

func TestPolicyBeginRejectsActiveOrDirtyRuntime(t *testing.T) {
	r, instance := newPolicyTestRuntime(t, func() ResourceEvidence { return ResourcesClean })
	plan := testPlanBytes(t, testPlan())
	reconcileClean(t, r, instance, plan)
	request := policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration))
	r.mu.Lock()
	r.current = &session{id: "fixture", protocol: "awg"}
	r.mu.Unlock()
	if _, err := r.PolicyBegin(request); !errors.Is(err, ErrPolicyBusy) {
		t.Fatalf("active session allowed policy begin: %v", err)
	}
	r.mu.Lock()
	r.current = nil
	r.mu.Unlock()
	r.cleanupPending.Store(true)
	if _, err := r.PolicyBegin(request); !errors.Is(err, ErrPolicyBusy) {
		t.Fatalf("pending cleanup allowed policy begin: %v", err)
	}
	r.cleanupPending.Store(false)
	if _, err := r.PolicyBegin(request); err != nil {
		t.Fatal(err)
	}
	validatePlanRequest(t, r, request)
}

func TestPolicyQueriesDoNotBlockOrClaimReadiness(t *testing.T) {
	r, instance := newPolicyTestRuntime(t, func() ResourceEvidence { return ResourcesClean })
	plan := testPlanBytes(t, testPlan())
	reconcileClean(t, r, instance, plan)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.PolicyState(); !errors.Is(err, ErrPolicyBusy) {
		t.Fatalf("state query while admission busy: %v", err)
	}
	caps, err := r.PolicyCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	if caps["state"] != "pending" || caps["resourceState"] != string(ResourcesUnknown) || caps["busy"] != true {
		t.Fatalf("busy capabilities claimed readiness: %v", caps)
	}
}

func TestPolicyVersionedRPCRequiresLaunchAndResourceClaims(t *testing.T) {
	plan := testPlanBytes(t, testPlan())
	r := &Runtime{newPolicyNonce: func() (string, error) { return testInstance, nil }}
	r.policy.observe = func() ResourceEvidence { return ResourcesClean }
	instance, err := r.policyInstanceNonce()
	if err != nil {
		t.Fatal(err)
	}
	request := policyRequestFor(t, instance, plan, testGeneration, testTxID, nil)
	// An unbound helper never adopts a store identity from an RPC.
	if _, err := r.PolicyReconcile(request); !errors.Is(err, ErrPolicyUnsupported) {
		t.Fatalf("unbound helper reconciled: %v", err)
	}
	if _, err := r.PolicyBegin(request); !errors.Is(err, ErrPolicyUnsupported) {
		t.Fatalf("unbound helper began: %v", err)
	}
	if _, err := r.PolicyAbort(PolicyAbortRequest{Version: policyVersion, InstanceNonce: instance, TransactionID: testTxID}); !errors.Is(err, ErrPolicyUnsupported) {
		t.Fatalf("unbound helper aborted: %v", err)
	}
	// The launch store binding alone is not enough: the shared fixed-resource
	// claim is a separate prerequisite.
	if err := r.BindStoreIdentity(testStore); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PolicyReconcile(request); !errors.Is(err, ErrPolicyUnsupported) {
		t.Fatalf("helper without the shared resource claim reconciled: %v", err)
	}
	r.BindResourceClaim()
	if _, err := r.PolicyReconcile(request); !errors.Is(err, ErrPolicyUnsupported) {
		t.Fatalf("helper without the client-only build identity reconciled: %v", err)
	}
	if err := r.BindClientOnly(false); err != nil {
		t.Fatal(err)
	}
	validatePlanRequest(t, r, request)
	ack, err := r.PolicyReconcile(request)
	if err != nil || ack["state"] != "ready" {
		t.Fatalf("claimed helper did not reconcile: %v %v", ack, err)
	}
}

func TestPolicyAbortRequestIsStrict(t *testing.T) {
	r, instance := newPolicyTestRuntime(t, func() ResourceEvidence { return ResourcesClean })
	for name, request := range map[string]PolicyAbortRequest{
		"version":     {Version: 2, InstanceNonce: instance, TransactionID: testTxID},
		"instance":    {Version: policyVersion, InstanceNonce: "nope", TransactionID: testTxID},
		"transaction": {Version: policyVersion, InstanceNonce: instance, TransactionID: "nope"},
	} {
		if _, err := r.PolicyAbort(request); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("%s: %v, want POLICY_INVALID", name, err)
		}
	}
}

func TestPolicyStateExposesFiniteDiagnosticsOnly(t *testing.T) {
	clean := func() ResourceEvidence { return ResourcesOwned }
	r, instance := newPolicyTestRuntime(t, clean)
	plan := testPlanBytes(t, testPlan())
	request := policyRequestFor(t, instance, plan, testGeneration, testTxID, nil)
	validatePlanRequest(t, r, request)
	if _, err := r.PolicyReconcile(request); err != nil {
		t.Fatal(err)
	}
	state, err := r.PolicyState()
	if err != nil {
		t.Fatal(err)
	}
	if state["error"] != policyErrorEvidenceOwned || state["state"] != "blocked" {
		t.Fatalf("owned evidence diagnostics: %v", state)
	}
	if state["receipt"] != nil || state["casGeneration"] != nil {
		t.Fatalf("blocked helper exposed activation/CAS state: %v", state)
	}
	if state["pendingTransaction"] != nil {
		t.Fatalf("settled helper reports a pending transaction: %v", state)
	}
}

func TestPolicyWriterTimeoutRetainsOwnershipAndSettlesBlocked(t *testing.T) {
	r, instance := newPolicyTestRuntime(t, func() ResourceEvidence { return ResourcesClean })
	r.policy.settleDelay = 60 * time.Millisecond
	plan := testPlanBytes(t, testPlan())
	reconcileClean(t, r, instance, plan)
	request := policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration))
	if _, err := r.PolicyBegin(request); err != nil {
		t.Fatal(err)
	}
	validatePlanRequest(t, r, request)
	entered, release := make(chan struct{}), make(chan struct{})
	r.policy.observe = func() ResourceEvidence {
		close(entered)
		<-release
		return ResourcesClean
	}
	commitDone := make(chan map[string]any, 1)
	go func() {
		ack, err := r.PolicyCommit(policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration)))
		if err != nil {
			commitDone <- map[string]any{"error": err.Error()}
			return
		}
		commitDone <- ack
	}()
	<-entered
	abort := PolicyAbortRequest{Version: policyVersion, InstanceNonce: instance, TransactionID: testOtherTx}
	start := time.Now()
	if _, err := r.PolicyAbort(abort); !errors.Is(err, ErrPolicyBusy) {
		t.Fatalf("abort past the settlement budget: %v", err)
	}
	if elapsed := time.Since(start); elapsed < r.policy.settleDelay {
		t.Fatalf("abort returned without waiting for the bounded settlement: %v", elapsed)
	}
	// A timed-out caller never releases the physical writer.
	state, err := r.PolicyState()
	if err != nil {
		t.Fatal(err)
	}
	if state["state"] != "pending" {
		t.Fatalf("writer released after the caller timed out: %v", state)
	}
	successor := policyRequestFor(t, instance, plan, "77777777777777777777777777777777", "88888888888888888888888888888888", mustSpan(t, testOtherGen))
	if _, err := r.PolicyBegin(successor); !errors.Is(err, ErrPolicyBusy) {
		t.Fatalf("successor admitted while the writer was owned: %v", err)
	}
	close(release)
	if result := <-commitDone; result["state"] != "blocked" {
		t.Fatalf("revoked commit settled as %v", result)
	}
	// The settled blocked receipt is repeatable but can never become ready.
	ack, err := r.PolicyAbort(abort)
	if err != nil || ack["state"] != "blocked" {
		t.Fatalf("settled blocked re-ACK: %v %v", ack, err)
	}
	state, err = r.PolicyState()
	if err != nil || state["state"] != "blocked" || state["receipt"] != nil {
		t.Fatalf("state after settlement: %v %v", state, err)
	}
}

func TestPolicyHelperRestartNeverResurrectsOldReceipt(t *testing.T) {
	first, firstInstance := newPolicyTestRuntime(t, func() ResourceEvidence { return ResourcesClean })
	plan := testPlanBytes(t, testPlan())
	reconcileClean(t, first, firstInstance, plan)
	receipt := &policyReceipt{
		Version: policyVersion, StoreIdentity: testStore, InstanceNonce: firstInstance,
		ControllerNonce: testController, TransactionID: testTxID, PlanGeneration: testGeneration,
	}
	// A restart is a new process: same store and claim, new instance nonce.
	second := &Runtime{newPolicyNonce: func() (string, error) { return testOtherGen, nil }}
	second.policy.observe = func() ResourceEvidence { return ResourcesClean }
	if err := second.BindStoreIdentity(testStore); err != nil {
		t.Fatal(err)
	}
	if err := second.BindClientOnly(false); err != nil {
		t.Fatal(err)
	}
	second.BindResourceClaim()
	caps, err := second.PolicyCapabilities()
	if err != nil || caps["state"] != "blocked" || caps["instanceNonce"] != testOtherGen {
		t.Fatalf("restarted helper identity: %v %v", caps, err)
	}
	state, err := second.PolicyState()
	if err != nil {
		t.Fatal(err)
	}
	if state["receipt"] != nil || state["casGeneration"] != nil {
		t.Fatalf("restart resurrected the previous committed state: %v", state)
	}
	second.mu.Lock()
	admissionErr := second.admitPolicyLocked("fixture", "awg", domainAWG, receipt)
	second.mu.Unlock()
	if !errors.Is(admissionErr, ErrPolicyStale) {
		t.Fatalf("old-instance receipt admitted after restart: %v", admissionErr)
	}
	// Only an explicit reconcile on the new instance makes it ready.
	secondInstance, err := second.policyInstanceNonce()
	if err != nil {
		t.Fatal(err)
	}
	reconcileClean(t, second, secondInstance, plan)
}

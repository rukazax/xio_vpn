package desktop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Synthetic, non-credential configuration examples for the cross-language
// validation golden: they are complete enough for the pure ParseProfile parser and
// align with the profile protocol/endpoint metadata.
const (
	syntheticAWGConfig = "[Interface]\nPrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAddress = 10.77.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0\n"
	syntheticAWGSHA    = "69d0ab3ea486c545ae7db09a397077111a5a8e5b772bc42d089396ce2f6fcb1e"

	syntheticXrayConfig = `{"protocol":"xray","outbound":{"protocol":"vless","settings":{"vnext":[{"address":"203.0.113.9","port":443,"users":[{"id":"b3b2eb49-e41f-41df-9761-0956785a236b","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.invalid"}}}}`
	syntheticXraySHA    = "ce9195ddaac8d239d25fc77a72419401ea459daf7382fc319a23fe38859c0905"
)

func TestValidationSyntheticConfigsAreParseable(t *testing.T) {
	for name, tc := range map[string]struct {
		protocol, raw, digest, endpoint string
	}{
		"awg":  {"awg", syntheticAWGConfig, syntheticAWGSHA, "203.0.113.9:51820"},
		"xray": {"xray", syntheticXrayConfig, syntheticXraySHA, "203.0.113.9:443"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := policyConfigDigest(tc.raw); got != tc.digest {
				t.Fatalf("digest %s, want %s", got, tc.digest)
			}
			profile, err := ParseProfile(tc.protocol, tc.raw)
			if err != nil {
				t.Fatalf("pure parser rejected the synthetic example: %v", err)
			}
			if len(profile.Endpoints) != 1 || profile.Endpoints[0] != tc.endpoint {
				t.Fatalf("endpoint %v, want %s", profile.Endpoints, tc.endpoint)
			}
		})
	}
}

func newValidationRuntime(t *testing.T, clientOnly bool) (*Runtime, string) {
	t.Helper()
	r := &Runtime{newPolicyNonce: func() (string, error) { return testInstance, nil }}
	r.policy.observe = func() ResourceEvidence { return ResourcesClean }
	if err := r.BindStoreIdentity(testStore); err != nil {
		t.Fatal(err)
	}
	if err := r.BindClientOnly(clientOnly); err != nil {
		t.Fatal(err)
	}
	r.BindResourceClaim()
	instance, err := r.policyInstanceNonce()
	if err != nil {
		t.Fatal(err)
	}
	return r, instance
}

// automaticValidationPlan offers two eligible AWG candidates owned by one user.
func automaticValidationPlan(clientOnly bool) map[string]any {
	plan := testPlan()
	plan["policy"] = map[string]any{"mode": "automatic", "roundMillis": 30000}
	plan["selectedId"] = "a"
	plan["ids"] = []string{"a", "b"}
	plan["clientOnly"] = clientOnly
	plan["profiles"] = []map[string]any{
		{"id": "a", "protocol": "awg", "endpoint": "203.0.113.9:51820", "configDigest": policyConfigDigest(testAWGConfig)},
		{"id": "b", "protocol": "awg", "endpoint": "192.0.2.2:51820", "configDigest": policyConfigDigest(numericAWG2(domainAWG))},
	}
	return plan
}

func validationObject(t *testing.T, document map[string]any, plan *policyPlan, configs map[string]string) json.RawMessage {
	t.Helper()
	documentBytes, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(documentBytes)
	entries := make([]map[string]any, len(plan.Profiles))
	for i, profile := range plan.Profiles {
		config, ok := configs[profile.ID]
		if !ok {
			t.Fatalf("no config for %q", profile.ID)
		}
		entries[i] = map[string]any{"id": profile.ID, "bytesBase64": base64.StdEncoding.EncodeToString([]byte(config))}
	}
	raw, err := json.Marshal(map[string]any{
		"schema":              1,
		"documentDigest":      hex.EncodeToString(digest[:]),
		"documentBytesBase64": base64.StdEncoding.EncodeToString(documentBytes),
		"configs":             entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validationObjectFromPlan(t *testing.T, plan *policyPlan, transaction, generation string) json.RawMessage {
	t.Helper()
	configs := make(map[string]string, len(plan.Profiles))
	for _, profile := range plan.Profiles {
		configs[profile.ID] = testConfigFor(t, profile)
	}
	return validationObject(t, validationDocumentWithReceipt(plan, transaction, generation), plan, configs)
}

func parsePlanOrFail(t *testing.T, raw json.RawMessage) *policyPlan {
	t.Helper()
	plan, err := parsePolicyPlan(raw)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestPolicyValidateEnablesCommitAndReconcile(t *testing.T) {
	r, instance := newValidationRuntime(t, false)
	plan := testPlanBytes(t, automaticValidationPlan(false))
	// Sequence A: validate the durable snapshot, then reconcile to READY.
	reconcile := policyRequestFor(t, instance, plan, testGeneration, testTxID, nil)
	validatePlanRequest(t, r, reconcile)
	ack, err := r.PolicyReconcile(reconcile)
	if err != nil || ack["state"] != "ready" {
		t.Fatalf("reconcile after validation: %v %v", ack, err)
	}
	// Sequence B: begin, application rename/readback, validate, commit.
	commit := policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration))
	if _, err := r.PolicyBegin(commit); err != nil {
		t.Fatal(err)
	}
	validate := validationObjectFromPlan(t, parsePlanOrFail(t, plan), testOtherTx, testOtherGen)
	validateACK, err := r.PolicyValidate(commit, validate)
	if err != nil {
		t.Fatal(err)
	}
	if len(validateACK) != 5 || validateACK["transactionId"] != testOtherTx ||
		validateACK["documentDigest"] == "" {
		t.Fatalf("validate ACK shape: %v", validateACK)
	}
	commitACK, err := r.PolicyCommit(commit)
	if err != nil || commitACK["state"] != "ready" {
		t.Fatalf("commit after validation: %v %v", commitACK, err)
	}
	state, err := r.PolicyState()
	if err != nil {
		t.Fatal(err)
	}
	if receipt := state["receipt"].(map[string]any); receipt["planGeneration"] != testOtherGen {
		t.Fatalf("committed receipt: %v", state)
	}
}

func TestPolicyCommitAndReconcileRequireValidation(t *testing.T) {
	r, instance := newValidationRuntime(t, false)
	plan := testPlanBytes(t, automaticValidationPlan(false))
	if _, err := r.PolicyReconcile(policyRequestFor(t, instance, plan, testGeneration, testTxID, nil)); !errors.Is(err, ErrPolicyUnverified) {
		t.Fatalf("reconcile without validation: %v", err)
	}
	reconcile := policyRequestFor(t, instance, plan, testGeneration, testTxID, nil)
	validatePlanRequest(t, r, reconcile)
	if _, err := r.PolicyReconcile(reconcile); err != nil {
		t.Fatal(err)
	}
	commit := policyRequestFor(t, instance, plan, testOtherGen, testOtherTx, mustSpan(t, testGeneration))
	if _, err := r.PolicyBegin(commit); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PolicyCommit(commit); !errors.Is(err, ErrPolicyUnverified) {
		t.Fatalf("commit without validation: %v", err)
	}
	// The reserve still exists, so a later validation can complete it.
	if _, err := r.PolicyValidate(commit, validationObjectFromPlan(t, parsePlanOrFail(t, plan), testOtherTx, testOtherGen)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.PolicyCommit(commit); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyValidationExpires(t *testing.T) {
	r, instance := newValidationRuntime(t, false)
	r.policy.validationTTL = 10 * time.Millisecond
	plan := testPlanBytes(t, automaticValidationPlan(false))
	reconcile := policyRequestFor(t, instance, plan, testGeneration, testTxID, nil)
	validatePlanRequest(t, r, reconcile)
	time.Sleep(20 * time.Millisecond)
	if _, err := r.PolicyReconcile(reconcile); !errors.Is(err, ErrPolicyUnverified) {
		t.Fatalf("expired validation still admitted: %v", err)
	}
	// A fresh validation works again.
	validatePlanRequest(t, r, reconcile)
	if _, err := r.PolicyReconcile(reconcile); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRevocationInvalidatesValidation(t *testing.T) {
	r, instance := newValidationRuntime(t, false)
	plan := testPlanBytes(t, automaticValidationPlan(false))
	reconcile := policyRequestFor(t, instance, plan, testGeneration, testTxID, nil)
	validatePlanRequest(t, r, reconcile)
	// Revocation of an unrelated transaction still clears the transient record;
	// a fresh validation is required afterwards.
	if _, err := r.PolicyAbort(PolicyAbortRequest{Version: policyVersion, InstanceNonce: instance, TransactionID: testOtherTx}); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("abort of an unknown transaction: %v", err)
	}
	if _, err := r.PolicyReconcile(reconcile); !errors.Is(err, ErrPolicyUnverified) {
		t.Fatalf("validation survived a revocation: %v", err)
	}
}

func TestPolicyValidationRejectsMismatchedSnapshots(t *testing.T) {
	planMap := automaticValidationPlan(false)
	planRaw := testPlanBytes(t, planMap)
	plan := parsePlanOrFail(t, planRaw)
	baseConfigs := map[string]string{
		"a": testAWGConfig,
		"b": numericAWG2(domainAWG),
	}
	cases := []struct {
		name     string
		document func(map[string]any)
		configs  func(map[string]string)
		want     error
	}{
		{
			name: "selected revoked",
			document: func(document map[string]any) {
				document["users"].([]map[string]any)[0]["revoked"] = true
			},
			want: ErrPolicyStale,
		},
		{
			name: "candidate missing from document",
			document: func(document map[string]any) {
				document["profiles"] = document["profiles"].([]map[string]any)[:1]
			},
			want: ErrPolicyStale,
		},
		{
			name: "priority protocol drift",
			document: func(document map[string]any) {
				document["priorityProtocol"] = "rivet-h3"
			},
			want: ErrPolicyStale,
		},
		{
			name: "stale legal record",
			document: func(document map[string]any) {
				document["legalRecord"].(map[string]any)["timestamp"] = "2026-11-06T09:00:00"
			},
			want: ErrPolicyStale,
		},
		{
			name: "wrong consent revision",
			document: func(document map[string]any) {
				document["legalRecord"].(map[string]any)["revision"] = "2026-01-01"
			},
			want: ErrPolicyStale,
		},
		{
			name: "connection policy drift",
			document: func(document map[string]any) {
				document["connectionPolicy"].(map[string]any)["mode"] = "selectedOnly"
			},
			want: ErrPolicyStale,
		},
		{
			name: "receipt identity drift",
			document: func(document map[string]any) {
				document["connectionPlanReceipt"] = map[string]any{
					"schema":         1,
					"transactionId":  testOtherTx,
					"planGeneration": testGeneration,
					"plan":           planMap,
				}
			},
			want: ErrPolicyStale,
		},
		{
			name: "config bytes changed",
			configs: func(configs map[string]string) {
				configs["a"] = strings.Replace(testAWGConfig, "10.77.0.2", "10.77.0.3", 1)
			},
			want: ErrPolicyStale,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, instance := newValidationRuntime(t, false)
			document := validationDocumentWithReceipt(plan, testTxID, testGeneration)
			configs := map[string]string{"a": baseConfigs["a"], "b": baseConfigs["b"]}
			if tc.document != nil {
				tc.document(document)
			}
			if tc.configs != nil {
				tc.configs(configs)
			}
			request := policyRequestFor(t, instance, planRaw, testGeneration, testTxID, nil)
			if _, err := r.PolicyValidate(request, validationObject(t, document, plan, configs)); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	// A configuration whose bytes match the offered digest but cannot be parsed by
	// the pure protocol parser is invalid, never silently admitted.
	t.Run("unusable config with matching digest", func(t *testing.T) {
		broken := "not a config"
		custom := automaticValidationPlan(false)
		custom["profiles"].([]map[string]any)[1]["configDigest"] = policyConfigDigest(broken)
		raw := testPlanBytes(t, custom)
		plan := parsePlanOrFail(t, raw)
		document := validationDocumentWithReceipt(plan, testTxID, testGeneration)
		r, instance := newValidationRuntime(t, false)
		request := policyRequestFor(t, instance, raw, testGeneration, testTxID, nil)
		configs := map[string]string{"a": testAWGConfig, "b": broken}
		if _, err := r.PolicyValidate(request, validationObject(t, document, plan, configs)); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("got %v, want POLICY_INVALID", err)
		}
	})
}

func TestOfferedOrderMixedProtocolOracle(t *testing.T) {
	// Exact accepted-source oracle (connection_plan_test.dart, "mixed-protocol
	// ordering oracle"): document order awg1,x2,x3,r3,c4,h5,o6, all but o6 on the
	// selected endpoint, preferred protocol rivet-h3. Expected offered ids:
	// awg1 (selected), h5 (preference 0), x2/x3 (xray 1, source order), r3
	// (rivet-s1 2), c4 (cloak 3), o6 (other endpoint last).
	documentOrder := []string{"awg1", "x2", "x3", "r3", "c4", "h5", "o6"}
	specs := []struct{ id, protocol, endpoint string }{
		{"awg1", "awg", "same.invalid:1"},
		{"x2", "xray", "same.invalid:1"},
		{"x3", "xray", "same.invalid:1"},
		{"r3", "rivet-s1", "same.invalid:1"},
		{"c4", "cloak", "same.invalid:1"},
		{"h5", "rivet-h3", "same.invalid:1"},
		{"o6", "xray", "other.invalid:2"},
	}
	profiles := make(map[string]documentProfile, len(specs))
	owned := make(map[string]string, len(specs))
	for i, spec := range specs {
		profiles[spec.id] = documentProfile{ID: spec.id, Protocol: spec.protocol, Endpoint: spec.endpoint}
		owned[fmt.Sprintf("k%d", i)] = spec.id
	}
	owner := &documentUser{ID: "user", ProfileIDs: owned}
	selected := "awg1"
	priority := "rivet-h3"
	planWith := func(ids ...string) *policyPlan {
		return &policyPlan{SelectedID: &selected, Mode: "automatic", PriorityProtocol: &priority, IDs: ids}
	}
	supported := restrictedNetworkProtocols
	if err := checkOfferedCandidateOrder(planWith("awg1", "h5", "x2", "x3", "r3", "c4", "o6"),
		documentOrder, profiles, owner, false, supported); err != nil {
		t.Fatalf("accepted mixed-protocol order rejected: %v", err)
	}
	for name, ids := range map[string][]string{
		"source order without preference": {"awg1", "x2", "x3", "r3", "c4", "h5", "o6"},
		"fallback before variant":         {"awg1", "h5", "x2", "x3", "r3", "o6", "c4"},
		"xray after rivet-s1":             {"awg1", "h5", "r3", "x2", "x3", "c4", "o6"},
		"tie order inverted":              {"awg1", "h5", "x3", "x2", "r3", "c4", "o6"},
		"variant ahead of preference":     {"awg1", "x2", "h5", "x3", "r3", "c4", "o6"},
	} {
		t.Run(name, func(t *testing.T) {
			if err := checkOfferedCandidateOrder(planWith(ids...), documentOrder, profiles, owner, false, supported); !errors.Is(err, ErrPolicyStale) {
				t.Fatalf("expected POLICY_STALE, got %v", err)
			}
		})
	}
	// Dropped non-selected candidates remain an ordered subsequence.
	if err := checkOfferedCandidateOrder(planWith("awg1", "h5", "x3", "r3", "o6"),
		documentOrder, profiles, owner, false, supported); err != nil {
		t.Fatalf("legal subsequence rejected: %v", err)
	}
	// The helper's own capability list (no cloak) makes a cloak candidate
	// ineligible, so an otherwise-order-valid plan containing c4 is rejected.
	if err := checkOfferedCandidateOrder(planWith("awg1", "h5", "x2", "x3", "r3", "c4", "o6"),
		documentOrder, profiles, owner, false, helperSupportedProtocols()); !errors.Is(err, ErrPolicyStale) {
		t.Fatalf("unsupported cloak candidate admitted: %v", err)
	}
	// Preference table matches the accepted source.
	for protocol, want := range map[string]int{
		"rivet-h3": 0, "xray": 1, "rivet-s1": 2, "cloak": 3, "awg": 4, "unknown": 100,
	} {
		if got := protocolPreference(protocol, "rivet-h3"); got != want {
			t.Fatalf("preference(%s) = %d, want %d", protocol, got, want)
		}
	}
}

func TestDartBlankMatrix(t *testing.T) {
	// Parent-probed Dart 3.13.5 trim() matrix: these code points are blank when a
	// string contains only them; the negative list must stay non-blank.
	blank := []rune{
		0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x0020, 0x0085, 0x00A0,
		0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006,
		0x2007, 0x2008, 0x2009, 0x200A, 0x2028, 0x2029, 0x202F, 0x205F,
		0x3000, 0xFEFF,
	}
	for _, r := range blank {
		if !dartBlank(string(r)) {
			t.Fatalf("U+%04X should be blank", r)
		}
	}
	for _, r := range []rune{0x0000, 0x001C, 0x001D, 0x001E, 0x001F, 0x180E, 0x200B} {
		if dartBlank(string(r)) {
			t.Fatalf("U+%04X should not be blank", r)
		}
	}
	if !dartBlank("") {
		t.Fatal("empty string should be blank")
	}
	if !dartBlank("\uFEFF\t\u3000\n") {
		t.Fatal("mixed Dart whitespace should be blank")
	}
	if dartBlank("\uFEFFx") || dartBlank("\u200B") {
		t.Fatal("mixed/non-Dart-whitespace should not be blank")
	}
	// The reason this predicate exists: Go's TrimSpace misses U+FEFF.
	if strings.TrimSpace("\uFEFF") == "" {
		t.Fatal("Go TrimSpace now trims U+FEFF; update the predicate rationale")
	}
}

func TestPolicyValidationRejectsDartBlankConfig(t *testing.T) {
	// A configuration of only Dart-blank code points (here a lone BOM) is not a
	// usable config. Go's TrimSpace would keep it, so the Dart predicate must run.
	blankConfig := "\uFEFF"
	planMap := testPlan()
	planMap["profiles"].([]map[string]any)[0]["configDigest"] = policyConfigDigest(blankConfig)
	raw := testPlanBytes(t, planMap)
	plan := parsePlanOrFail(t, raw)
	document := validationDocumentWithReceipt(plan, testTxID, testGeneration)
	r, instance := newValidationRuntime(t, false)
	request := policyRequestFor(t, instance, raw, testGeneration, testTxID, nil)
	configs := map[string]string{"fixture": blankConfig}
	if _, err := r.PolicyValidate(request, validationObject(t, document, plan, configs)); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("Dart-blank config accepted: %v", err)
	}
}

func TestPolicyValidationDocumentCapBoundary(t *testing.T) {
	planMap := automaticValidationPlan(false)
	raw := testPlanBytes(t, planMap)
	plan := parsePlanOrFail(t, raw)
	configs := map[string]string{"a": testAWGConfig, "b": numericAWG2(domainAWG)}
	withFiller := func(size int) map[string]any {
		document := validationDocumentWithReceipt(plan, testTxID, testGeneration)
		document["unrelatedSetting"] = strings.Repeat("a", size)
		return document
	}
	base, err := json.Marshal(validationDocumentWithReceipt(plan, testTxID, testGeneration))
	if err != nil {
		t.Fatal(err)
	}
	// Compute the filler size that makes the exact marshaled document equal to the
	// decoded-size cap (base64 overhead is the transport budget, not this cap).
	filler := policyValidationDocumentLimit - len(base) - len(`,"unrelatedSetting":""`)
	document := withFiller(filler)
	encoded, _ := json.Marshal(document)
	filler += policyValidationDocumentLimit - len(encoded)
	document = withFiller(filler)
	encoded, _ = json.Marshal(document)
	if len(encoded) != policyValidationDocumentLimit {
		t.Fatalf("document %d bytes, want %d", len(encoded), policyValidationDocumentLimit)
	}
	r, instance := newValidationRuntime(t, false)
	request := policyRequestFor(t, instance, raw, testGeneration, testTxID, nil)
	if _, err := r.PolicyValidate(request, validationObject(t, document, plan, configs)); err != nil {
		t.Fatalf("document at the cap rejected: %v", err)
	}
	over := withFiller(filler + 1)
	if _, err := r.PolicyValidate(request, validationObject(t, over, plan, configs)); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("document one byte over the cap: %v", err)
	}
}

func TestPolicyValidationRecomputesProtocolPreferenceOrder(t *testing.T) {
	// Document order: awg1, awg2, xr1 — all on the selected endpoint. The accepted
	// builder reorders the same-endpoint variants by restricted protocolPreference
	// (xray first unless priorityProtocol says otherwise) with document order only
	// as the tie-break, so a plan in document order must be rejected when the
	// preference order differs.
	document := func(t *testing.T, plan *policyPlan) map[string]any {
		t.Helper()
		doc := validationDocumentWithReceipt(plan, testTxID, testGeneration)
		doc["profiles"] = []map[string]any{
			{"id": "awg1", "name": "home", "protocol": "awg", "endpoint": "203.0.113.9:51820"},
			{"id": "awg2", "name": "second", "protocol": "awg", "endpoint": "203.0.113.9:51820"},
			{"id": "xr1", "name": "xray", "protocol": "xray", "endpoint": "203.0.113.9:51820"},
		}
		doc["users"] = []map[string]any{{
			"id": "user-1", "name": "User", "serverId": "server-1",
			"profileIds": map[string]any{"a": "awg1", "b": "awg2", "c": "xr1"},
			"revoked":    false, "admin": false, "userLimit": 0,
		}}
		return doc
	}
	configs := map[string]string{
		"awg1": testAWGConfig,
		"awg2": numericAWG2(domainAWG),
		"xr1":  syntheticXrayConfig,
	}
	planFor := func(priority *string, ids ...string) map[string]any {
		plan := testPlan()
		plan["policy"] = map[string]any{"mode": "automatic", "roundMillis": 30000}
		plan["selectedId"] = "awg1"
		plan["priorityProtocol"] = priority
		plan["ids"] = ids
		profiles := make([]map[string]any, len(ids))
		for i, id := range ids {
			endpoint := "203.0.113.9:51820"
			protocol := "awg"
			digest := policyConfigDigest(testAWGConfig)
			switch id {
			case "awg2":
				digest = policyConfigDigest(numericAWG2(domainAWG))
			case "xr1":
				protocol = "xray"
				digest = policyConfigDigest(syntheticXrayConfig)
			}
			profiles[i] = map[string]any{"id": id, "protocol": protocol, "endpoint": endpoint, "configDigest": digest}
		}
		plan["profiles"] = profiles
		return plan
	}
	run := func(t *testing.T, planMap map[string]any, wantErr error) {
		t.Helper()
		raw := testPlanBytes(t, planMap)
		plan := parsePlanOrFail(t, raw)
		r, instance := newValidationRuntime(t, false)
		request := policyRequestFor(t, instance, raw, testGeneration, testTxID, nil)
		_, err := r.PolicyValidate(request, validationObject(t, document(t, plan), plan, configs))
		if wantErr == nil {
			if err != nil {
				t.Fatalf("preference order rejected: %v", err)
			}
			return
		}
		if !errors.Is(err, wantErr) {
			t.Fatalf("got %v, want %v", err, wantErr)
		}
	}
	defaultPreference := mustSpan(t, "xray")
	awgPreference := mustSpan(t, "awg")
	// Default priority (xray): variants are xr1 then awg2.
	run(t, planFor(defaultPreference, "awg1", "xr1", "awg2"), nil)
	run(t, planFor(defaultPreference, "awg1", "awg2", "xr1"), ErrPolicyStale)
	// Explicit awg priority inverts the intra-group order.
	run(t, planFor(awgPreference, "awg1", "awg2", "xr1"), nil)
	run(t, planFor(awgPreference, "awg1", "xr1", "awg2"), ErrPolicyStale)
	// Dropped non-selected candidates keep the subsequence semantics valid.
	run(t, planFor(defaultPreference, "awg1", "awg2"), nil)
}

func TestPolicyValidationEnvelopeAndOrder(t *testing.T) {
	planMap := automaticValidationPlan(true)
	planRaw := testPlanBytes(t, planMap)
	plan := parsePlanOrFail(t, planRaw)
	document := validationDocumentWithReceipt(plan, testTxID, testGeneration)
	// A third eligible candidate appears only because clientOnly allows it.
	document["profiles"] = append(document["profiles"].([]map[string]any),
		map[string]any{"id": "c", "name": "C", "protocol": "awg", "endpoint": "192.0.2.3:51820"})
	configs := map[string]string{
		"a": testAWGConfig,
		"b": numericAWG2(domainAWG),
	}
	t.Run("client-only mismatch", func(t *testing.T) {
		r, instance := newValidationRuntime(t, false) // helper bound to false
		request := policyRequestFor(t, instance, planRaw, testGeneration, testTxID, nil)
		if _, err := r.PolicyValidate(request, validationObject(t, document, plan, configs)); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("plan/client-only mismatch: %v", err)
		}
	})
	t.Run("ordered subsequence", func(t *testing.T) {
		r, instance := newValidationRuntime(t, true)
		request := policyRequestFor(t, instance, planRaw, testGeneration, testTxID, nil)
		if _, err := r.PolicyValidate(request, validationObject(t, document, plan, configs)); err != nil {
			t.Fatalf("valid subsequence: %v", err)
		}
	})
	t.Run("out of order candidate", func(t *testing.T) {
		// Offer [a, c] although the document order places b before c: still a
		// subsequence (a, c) would be valid, so use [a, b] plus c out of order in
		// the plan: [a, b] is a subsequence, so instead offer [a, c, b] which is not.
		overtaken := automaticValidationPlan(true)
		overtaken["ids"] = []string{"a", "c", "b"}
		overtaken["profiles"] = []map[string]any{
			{"id": "a", "protocol": "awg", "endpoint": "203.0.113.9:51820", "configDigest": policyConfigDigest(testAWGConfig)},
			{"id": "c", "protocol": "awg", "endpoint": "192.0.2.3:51820", "configDigest": policyConfigDigest(numericAWG2(domainAWG))},
			{"id": "b", "protocol": "awg", "endpoint": "192.0.2.2:51820", "configDigest": policyConfigDigest(numericAWG2(domainAWG))},
		}
		overtakenPlan := parsePlanOrFail(t, testPlanBytes(t, overtaken))
		r, instance := newValidationRuntime(t, true)
		request := policyRequestFor(t, instance, testPlanBytes(t, overtaken), testGeneration, testTxID, nil)
		overtakenConfigs := map[string]string{"a": testAWGConfig, "b": numericAWG2(domainAWG), "c": numericAWG2(domainAWG)}
		if _, err := r.PolicyValidate(request, validationObject(t, document, overtakenPlan, overtakenConfigs)); !errors.Is(err, ErrPolicyStale) {
			t.Fatalf("out-of-order plan: %v", err)
		}
	})
}

func TestPolicyValidationRejectsMalformedEnvelopes(t *testing.T) {
	r, instance := newValidationRuntime(t, false)
	planRaw := testPlanBytes(t, automaticValidationPlan(false))
	request := policyRequestFor(t, instance, planRaw, testGeneration, testTxID, nil)
	plan := parsePlanOrFail(t, planRaw)
	document := validationDocumentWithReceipt(plan, testTxID, testGeneration)
	configs := map[string]string{"a": testAWGConfig, "b": numericAWG2(domainAWG)}

	valid := validationObject(t, document, plan, configs)
	var validMap map[string]any
	if err := json.Unmarshal(valid, &validMap); err != nil {
		t.Fatal(err)
	}
	clone := func(mutate func(map[string]any)) json.RawMessage {
		copied, _ := json.Marshal(mutateCopy(validMap, mutate))
		return copied
	}
	for name, envelope := range map[string]json.RawMessage{
		"unknown key":   clone(func(value map[string]any) { value["extra"] = 1 }),
		"wrong schema":  clone(func(value map[string]any) { value["schema"] = 2 }),
		"bad digest":    clone(func(value map[string]any) { value["documentDigest"] = "xyz" }),
		"wrong digest":  clone(func(value map[string]any) { value["documentDigest"] = strings.Repeat("b", 64) }),
		"config id set": clone(func(value map[string]any) { value["configs"] = []any{} }),
	} {
		if _, err := r.PolicyValidate(request, envelope); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// Duplicate JSON keys anywhere in the document are rejected.
	duplicated := strings.Replace(string(marshalDocument(t, document)), `"selected":"a"`, `"selected":"a","selected":"a"`, 1)
	duplicateEnvelope := validationObject(t, nil, plan, configs)
	var duplicateMap map[string]any
	_ = json.Unmarshal(duplicateEnvelope, &duplicateMap)
	duplicateMap["documentBytesBase64"] = base64.StdEncoding.EncodeToString([]byte(duplicated))
	digest := sha256.Sum256([]byte(duplicated))
	duplicateMap["documentDigest"] = hex.EncodeToString(digest[:])
	raw, _ := json.Marshal(duplicateMap)
	if _, err := r.PolicyValidate(request, raw); err == nil {
		t.Fatal("duplicate document keys accepted")
	}
}

func mutateCopy(source map[string]any, mutate func(map[string]any)) map[string]any {
	raw, _ := json.Marshal(source)
	var copied map[string]any
	_ = json.Unmarshal(raw, &copied)
	mutate(copied)
	return copied
}

func marshalDocument(t *testing.T, document map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

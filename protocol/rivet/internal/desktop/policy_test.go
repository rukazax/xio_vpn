package desktop

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const (
	testStore      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testController = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testInstance   = "cccccccccccccccccccccccccccccccc"
	testTxID       = "dddddddddddddddddddddddddddddddd"
	testGeneration = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	testOtherGen   = "ffffffffffffffffffffffffffffffff"
	testOtherTx    = "11111111111111111111111111111111"
	testDigest     = "39f8033617d67670c707dde7332ad7e616ef4902d4b7e6cf797e102af1611389"
)

// testAWGConfig is a valid saved AWG configuration whose digest is used by the
// shared test plan; validation tests hash these exact bytes.
var testAWGConfig = strings.Replace(domainAWG, "fr-host.fr", "203.0.113.9", 1)

func numericAWG(raw string) string {
	return strings.Replace(raw, "fr-host.fr", "192.0.2.1", 1)
}

// testPlan returns a complete, valid WIRE-V2 manual plan object. Callers mutate
// the returned map to express one specific invalidity.
func testPlan() map[string]any {
	return map[string]any{
		"schema":           2,
		"selectedId":       "fixture",
		"ids":              []string{"fixture"},
		"profiles":         []map[string]any{{"id": "fixture", "protocol": "awg", "endpoint": "203.0.113.9:51820", "configDigest": policyConfigDigest(testAWGConfig)}},
		"routing":          nil,
		"priorityProtocol": nil,
		"policy":           map[string]any{"mode": "selectedOnly", "roundMillis": 30000},
		"site":             "https://example.invalid/",
		"siteCheckEnabled": false,
		"timeoutSeconds":   15,
		"roundMillis":      30000,
		"clientOnly":       false,
		"consentRevision":  "2026-10-18",
		"vpnDisclosure":    nil,
	}
}

func testPlanBytes(t *testing.T, plan map[string]any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testRequest(t *testing.T, plan json.RawMessage, generation, transaction string, expected *string) PolicyRequest {
	t.Helper()
	return PolicyRequest{
		Version:            policyVersion,
		StoreIdentity:      testStore,
		ControllerNonce:    testController,
		InstanceNonce:      testInstance,
		TransactionID:      transaction,
		PlanGeneration:     generation,
		ExpectedGeneration: expected,
		Plan:               plan,
	}
}

func expectPolicyError(t *testing.T, err error, code error) {
	t.Helper()
	if !errors.Is(err, code) {
		t.Fatalf("got %v, want %v", err, code)
	}
}

func TestPolicyConfigDigestMatchesWIREV2Goldens(t *testing.T) {
	// Parent-verified golden fixtures: a trailing newline is part of the bytes.
	cases := []struct{ name, raw, want string }{
		{"awg trailing LF", "[Interface]\nAddress = 10.7.0.2/32\nDNS = 9.9.9.9\nPrivateKey = priv\n[Peer]\nPublicKey = pub\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0\n", "39f8033617d67670c707dde7332ad7e616ef4902d4b7e6cf797e102af1611389"},
		{"awg without trailing LF", "[Interface]\nAddress = 10.7.0.2/32\nDNS = 9.9.9.9\nPrivateKey = priv\n[Peer]\nPublicKey = pub\nEndpoint = 203.0.113.9:51820\nAllowedIPs = 0.0.0.0/0", "b5e42d837f2cb7c753fe7434430003707486498d92ab39e51af562696182b34d"},
		{"vless json", `{"protocol":"vless","serverName":"example.invalid","port":443}`, "c40bb489a48a897507a8a486f6403b631ed8b518d9077a7a9102058cfc2c9542"},
		{"empty", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyConfigDigest(tc.raw); got != tc.want {
				t.Fatalf("digest %s, want %s", got, tc.want)
			}
		})
	}
}

func TestPolicyPlanStrictness(t *testing.T) {
	with := func(mutate func(map[string]any)) json.RawMessage {
		plan := testPlan()
		mutate(plan)
		return testPlanBytes(t, plan)
	}
	valid := with(func(map[string]any) {})
	accepted := map[string]json.RawMessage{
		"valid manual": valid,
		"priority protocol": with(func(plan map[string]any) {
			plan["priorityProtocol"] = "rivet-h3"
		}),
		"automatic selected first": with(func(plan map[string]any) {
			plan["policy"] = map[string]any{"mode": "automatic", "roundMillis": 30000}
		}),
		"manual unusable selection with no candidates": with(func(plan map[string]any) {
			plan["ids"] = []string{}
			plan["profiles"] = []map[string]any{}
		}),
	}
	for name, raw := range accepted {
		if _, err := parsePolicyPlan(raw); err != nil {
			t.Fatalf("%s rejected: %v", name, err)
		}
	}
	invalid := map[string]json.RawMessage{
		"schema 1":        with(func(plan map[string]any) { plan["schema"] = 1 }),
		"schema float":    with(func(plan map[string]any) { plan["schema"] = json.RawMessage("2.0") }),
		"unknown key":     with(func(plan map[string]any) { plan["extra"] = true }),
		"missing routing": with(func(plan map[string]any) { delete(plan, "routing") }),
		"non-null routing": with(func(plan map[string]any) {
			plan["routing"] = map[string]any{"mode": "all", "packages": []string{}, "networks": []string{}, "domains": []string{}}
		}),
		"priority protocol wrong type": with(func(plan map[string]any) { plan["priorityProtocol"] = 7 }),
		"policy round": with(func(plan map[string]any) {
			plan["policy"] = map[string]any{"mode": "selectedOnly", "roundMillis": 29999}
		}),
		"top round":     with(func(plan map[string]any) { plan["roundMillis"] = 29999 }),
		"timeout low":   with(func(plan map[string]any) { plan["timeoutSeconds"] = 4 }),
		"timeout high":  with(func(plan map[string]any) { plan["timeoutSeconds"] = 61 }),
		"http site":     with(func(plan map[string]any) { plan["site"] = "http://example.invalid/" }),
		"site userinfo": with(func(plan map[string]any) { plan["site"] = "https://user@example.invalid/" }),
		"uppercase digest": with(func(plan map[string]any) {
			plan["profiles"] = []map[string]any{{"id": "fixture", "protocol": "awg", "endpoint": "203.0.113.9:51820", "configDigest": strings.ToUpper(testDigest)}}
		}),
		"short digest": with(func(plan map[string]any) {
			plan["profiles"] = []map[string]any{{"id": "fixture", "protocol": "awg", "endpoint": "203.0.113.9:51820", "configDigest": testDigest[:63]}}
		}),
		"protocol alias": with(func(plan map[string]any) {
			plan["profiles"] = []map[string]any{{"id": "fixture", "protocol": "vless", "endpoint": "203.0.113.9:443", "configDigest": testDigest}}
		}),
		"duplicate candidate": with(func(plan map[string]any) { plan["ids"] = []string{"fixture", "fixture"} }),
		"profile order": with(func(plan map[string]any) {
			plan["profiles"] = []map[string]any{{"id": "other", "protocol": "awg", "endpoint": "203.0.113.9:51820", "configDigest": testDigest}}
		}),
		"manual multi candidate": with(func(plan map[string]any) {
			plan["ids"] = []string{"fixture", "other"}
			plan["profiles"] = []map[string]any{
				{"id": "fixture", "protocol": "awg", "endpoint": "203.0.113.9:51820", "configDigest": testDigest},
				{"id": "other", "protocol": "awg", "endpoint": "203.0.113.9:51821", "configDigest": testDigest},
			}
		}),
		"manual selection mismatch": with(func(plan map[string]any) { plan["selectedId"] = "other" }),
		"automatic selection not first": with(func(plan map[string]any) {
			plan["policy"] = map[string]any{"mode": "automatic", "roundMillis": 30000}
			plan["ids"] = []string{"other", "fixture"}
			plan["profiles"] = []map[string]any{
				{"id": "other", "protocol": "awg", "endpoint": "203.0.113.9:51821", "configDigest": testDigest},
				{"id": "fixture", "protocol": "awg", "endpoint": "203.0.113.9:51820", "configDigest": testDigest},
			}
		}),
		"ids null":      with(func(plan map[string]any) { plan["ids"] = nil }),
		"profiles null": with(func(plan map[string]any) { plan["profiles"] = nil }),
		"profile unknown key": with(func(plan map[string]any) {
			plan["profiles"] = []map[string]any{{"id": "fixture", "protocol": "awg", "endpoint": "203.0.113.9:51820", "configDigest": testDigest, "extra": 1}}
		}),
		"clientOnly string":    with(func(plan map[string]any) { plan["clientOnly"] = "false" }),
		"vpnDisclosure number": with(func(plan map[string]any) { plan["vpnDisclosure"] = 1 }),
		"disclosure missing":   with(func(plan map[string]any) { delete(plan, "vpnDisclosure") }),
		"trailing data":        json.RawMessage(string(valid) + "{}"),
		"top-level array":      json.RawMessage("[]"),
		"null plan":            json.RawMessage("null"),
		"duplicate key":        json.RawMessage(strings.Replace(string(valid), `"schema":2`, `"schema":2,"schema":2`, 1)),
	}
	for name, raw := range invalid {
		_, err := parsePolicyPlan(raw)
		if !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("%s: got %v, want POLICY_INVALID", name, err)
		}
	}
}

func TestPolicyPlanTooManyCandidates(t *testing.T) {
	plan := testPlan()
	ids, profiles := make([]string, 0, 17), make([]map[string]any, 0, 17)
	for i := 0; i < 17; i++ {
		id := "profile" + string(rune('a'+i))
		ids = append(ids, id)
		profiles = append(profiles, map[string]any{"id": id, "protocol": "awg", "endpoint": "203.0.113.9:51820", "configDigest": testDigest})
	}
	plan["ids"] = ids
	plan["profiles"] = profiles
	plan["policy"] = map[string]any{"mode": "automatic", "roundMillis": 30000}
	if _, err := parsePolicyPlan(testPlanBytes(t, plan)); !errors.Is(err, ErrPolicyInvalid) {
		t.Fatalf("17 candidates accepted: %v", err)
	}
}

func TestPolicyPlanFingerprintIsCanonical(t *testing.T) {
	first := testPlan()
	first["priorityProtocol"] = "xray"
	second := testPlan()
	second["priorityProtocol"] = "xray"
	// Reordering keys and adding whitespace must not change replay identity.
	rawFirst, _ := json.Marshal(first)
	rawSecond := json.RawMessage(`{ "vpnDisclosure": null, "priorityProtocol": "xray", "schema": 2, ` +
		`"selectedId": "fixture", "ids": ["fixture"], "profiles": [{"id": "fixture", "protocol": "awg", ` +
		`"endpoint": "203.0.113.9:51820", "configDigest": "` + policyConfigDigest(testAWGConfig) + `"}], "routing": null, ` +
		`"policy": {"roundMillis": 30000, "mode": "selectedOnly"}, "site": "https://example.invalid/", ` +
		`"siteCheckEnabled": false, "timeoutSeconds": 15, "roundMillis": 30000, "clientOnly": false, ` +
		`"consentRevision": "2026-10-18"}`)
	one, err := parsePolicyPlan(rawFirst)
	if err != nil {
		t.Fatal(err)
	}
	two, err := parsePolicyPlan(rawSecond)
	if err != nil {
		t.Fatal(err)
	}
	if one.fingerprint != two.fingerprint {
		t.Fatal("equivalent plans have different replay identities")
	}
	changed := testPlan()
	changed["priorityProtocol"] = "rivet-h3"
	other, err := parsePolicyPlan(testPlanBytes(t, changed))
	if err != nil {
		t.Fatal(err)
	}
	if one.fingerprint == other.fingerprint {
		t.Fatal("changed plan content reuses the replay identity")
	}
}

func TestPolicyReceiptStrict(t *testing.T) {
	fields := map[string]any{
		"version":         1,
		"storeIdentity":   testStore,
		"instanceNonce":   testInstance,
		"controllerNonce": testController,
		"transactionId":   testTxID,
		"planGeneration":  testGeneration,
	}
	encode := func(mutate func(map[string]any)) string {
		value := map[string]any{}
		for key, item := range fields {
			value[key] = item
		}
		if mutate != nil {
			mutate(value)
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	receipt, err := parsePolicyReceipt(encode(nil))
	if err != nil || receipt.TransactionID != testTxID || receipt.StoreIdentity != testStore {
		t.Fatalf("valid receipt rejected: %v", err)
	}
	if missing, err := parsePolicyReceipt(""); err != nil || missing != nil {
		t.Fatalf("absent receipt must stay absent: %v %v", missing, err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown key":   func(value map[string]any) { value["extra"] = true },
		"missing field": func(value map[string]any) { delete(value, "planGeneration") },
		"version 2":     func(value map[string]any) { value["version"] = 2 },
		"short store":   func(value map[string]any) { value["storeIdentity"] = testStore[:63] },
		"uppercase hex": func(value map[string]any) { value["instanceNonce"] = strings.ToUpper(testInstance) },
		"number nonce":  func(value map[string]any) { value["controllerNonce"] = 1 },
	} {
		if _, err := parsePolicyReceipt(encode(mutate)); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("%s: got %v, want POLICY_INVALID", name, err)
		}
	}
	for name, raw := range map[string]string{
		"null receipt":  "null",
		"array receipt": "[]",
		"trailing data": encode(nil) + "{}",
		"version float": strings.Replace(encode(nil), `"version":1`, `"version":1.0`, 1),
	} {
		if _, err := parsePolicyReceipt(raw); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("%s: got %v, want POLICY_INVALID", name, err)
		}
	}
}

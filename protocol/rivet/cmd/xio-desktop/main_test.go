package main

import (
	"encoding/json"
	"strings"
	"testing"

	"xio.local/rivet/internal/desktop"
)

const (
	testStore       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testController  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testTransaction = "dddddddddddddddddddddddddddddddd"
	testGeneration  = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

func testPlanBytes(t *testing.T, schema int) json.RawMessage {
	t.Helper()
	plan := map[string]any{
		"schema":           schema,
		"selectedId":       "fixture",
		"ids":              []string{"fixture"},
		"profiles":         []map[string]any{{"id": "fixture", "protocol": "awg", "endpoint": "203.0.113.9:51820", "configDigest": strings.Repeat("a", 64)}},
		"routing":          nil,
		"priorityProtocol": nil,
		"policy":           map[string]any{"mode": "selectedOnly", "roundMillis": 30000},
		"site":             "https://example.invalid/",
		"siteCheckEnabled": false,
		"timeoutSeconds":   15,
		"roundMillis":      30000,
		"clientOnly":       false,
		"consentRevision":  "",
		"vpnDisclosure":    nil,
	}
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testPolicyRequest(t *testing.T, instance string, schema int) desktop.PolicyRequest {
	t.Helper()
	return desktop.PolicyRequest{
		Version: 1, StoreIdentity: testStore, ControllerNonce: testController,
		InstanceNonce: instance, TransactionID: testTransaction,
		PlanGeneration: testGeneration, Plan: testPlanBytes(t, schema),
	}
}

func TestDesktopRequestDecodeIsStrict(t *testing.T) {
	plan := string(testPlanBytes(t, 2))
	body := `{"Method":"policyBegin","version":1,"storeIdentity":"` + testStore +
		`","controllerNonce":"` + testController + `","instanceNonce":"` + testGeneration +
		`","transactionId":"` + testTransaction + `","planGeneration":"` + testGeneration +
		`","expectedGeneration":null,"plan":` + plan + `}`
	decoded, err := decodeRequest([]byte(body))
	if err != nil {
		t.Fatalf("valid policy request: %v", err)
	}
	if decoded.Method != "policyBegin" || decoded.Version != 1 || decoded.StoreIdentity != testStore ||
		decoded.ControllerNonce != testController || decoded.TransactionID != testTransaction ||
		decoded.PlanGeneration != testGeneration || decoded.ExpectedGeneration != nil ||
		len(decoded.Plan) == 0 {
		t.Fatalf("decoded request lost fields: %+v", decoded)
	}
	attachment := `{"Method":"connect","ID":"fixture","Protocol":"awg","Config":"x","TimeoutMillis":1000,"RoundMillis":1000,"PolicyReceiptJSON":"{\"version\":1}"}`
	decoded, err = decodeRequest([]byte(attachment))
	if err != nil || decoded.PolicyReceiptJSON != `{"version":1}` {
		t.Fatalf("activation attachment: %+v %v", decoded, err)
	}
	for name, invalid := range map[string]string{
		"unknown field": `{"Method":"status","extra":1}`,
		"trailing data": `{"Method":"status"}{}`,
		"wrong type":    `{"Method":"status","TimeoutMillis":"soon"}`,
		"not an object": `[]`,
		"empty":         ``,
	} {
		if _, err := decodeRequest([]byte(invalid)); err == nil {
			t.Fatalf("%s accepted by the strict decoder", name)
		}
	}
}

func TestDesktopPolicyEnvelopesAreExact(t *testing.T) {
	base := `"Method":"policyBegin","version":1,"storeIdentity":"` + testStore +
		`","controllerNonce":"` + testController + `","instanceNonce":"` + testGeneration +
		`","transactionId":"` + testTransaction + `","planGeneration":"` + testGeneration +
		`","expectedGeneration":null`
	plan := string(testPlanBytes(t, 2))
	valid := `{` + base + `,"plan":` + plan + `}`
	if _, err := decodeRequest([]byte(valid)); err != nil {
		t.Fatalf("valid eight-key begin envelope: %v", err)
	}
	for name, body := range map[string]string{
		"extra key":                  `{` + base + `,"plan":` + plan + `,"planHash":"x"}`,
		"missing plan":               `{` + base + `}`,
		"missing expectedGeneration": strings.Replace(valid, `,"expectedGeneration":null`, "", 1),
	} {
		if _, err := decodeRequest([]byte(body)); err == nil {
			t.Fatalf("%s accepted by the exact envelope", name)
		}
	}
	abort := `{"Method":"policyAbort","version":1,"instanceNonce":"` + testGeneration + `","transactionId":"` + testTransaction + `"}`
	decoded, err := decodeRequest([]byte(abort))
	if err != nil || decoded.Method != "policyAbort" || decoded.TransactionID != testTransaction {
		t.Fatalf("three-key abort envelope: %+v %v", decoded, err)
	}
	if _, err := run(&desktop.Runtime{}, decoded); err == nil {
		t.Fatal("abort on an unbound helper was accepted")
	}
	for name, body := range map[string]string{
		"abort with store":           strings.Replace(abort, `"transactionId"`, `"storeIdentity":"`+testStore+`","transactionId"`, 1),
		"abort with plan":            strings.Replace(abort, `"transactionId"`, `"plan":`+plan+`,"transactionId"`, 1),
		"capabilities with identity": `{"Method":"policyCapabilities","version":1}`,
		"state with plan":            `{"Method":"policyState","plan":` + plan + `}`,
	} {
		if _, err := decodeRequest([]byte(body)); err == nil {
			t.Fatalf("%s accepted by the exact envelope", name)
		}
	}
}

func TestDesktopValidationEnvelopeIsExact(t *testing.T) {
	// policyValidate is the common eight keys plus `validation` (nine) and nothing
	// else; it is dispatched, but a missing validation object is rejected by the
	// helper, not silently treated as unversioned work.
	base := `"Method":"policyValidate","version":1,"storeIdentity":"` + testStore +
		`","controllerNonce":"` + testController + `","instanceNonce":"` + testGeneration +
		`","transactionId":"` + testTransaction + `","planGeneration":"` + testGeneration +
		`","expectedGeneration":null`
	plan := string(testPlanBytes(t, 2))
	valid := `{` + base + `,"plan":` + plan + `,"validation":{"schema":1,"documentDigest":"` +
		strings.Repeat("a", 64) + `","documentBytesBase64":"e30=","configs":[]}}`
	decoded, err := decodeRequest([]byte(valid))
	if err != nil {
		t.Fatalf("valid nine-key validate envelope: %v", err)
	}
	if decoded.Method != "policyValidate" || len(decoded.Validation) == 0 {
		t.Fatalf("validate envelope lost fields: %+v", decoded)
	}
	for name, body := range map[string]string{
		"missing validation": `{` + base + `,"plan":` + plan + `}`,
		"extra key":          `{` + base + `,"plan":` + plan + `,"validation":{},"extra":1}`,
	} {
		if _, err := decodeRequest([]byte(body)); err == nil {
			t.Fatalf("%s accepted by the nine-key envelope", name)
		}
	}
	// Dispatched, but a missing object is a policy error, never silent success.
	if _, err := run(&desktop.Runtime{}, request{Method: "policyValidate"}); err == nil {
		t.Fatal("policyValidate without a validation object was accepted")
	}
	// WIRE-V2 requires the helper to advertise validation support explicitly; the
	// state query carries the same capability value.
	runtime := &desktop.Runtime{}
	capabilities, err := run(runtime, request{Method: "policyCapabilities"})
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.(map[string]any)["validation"] != 1 {
		t.Fatalf("capabilities must advertise validation:1: %#v", capabilities)
	}
	state, err := run(runtime, request{Method: "policyState"})
	if err != nil {
		t.Fatal(err)
	}
	if state.(map[string]any)["validation"] != 1 {
		t.Fatalf("state must carry validation:1: %#v", state)
	}
}

func TestDesktopPolicyDispatchIsWired(t *testing.T) {
	// A fresh Runtime is blocked before any reconciliation; these dispatch
	// assertions are host-independent and perform no platform I/O.
	runtime := &desktop.Runtime{}
	value, err := run(runtime, request{Method: "policyCapabilities"})
	if err != nil {
		t.Fatal(err)
	}
	capabilities, ok := value.(map[string]any)
	instance, isString := capabilities["instanceNonce"].(string)
	if !ok || !isString || len(instance) != 32 || capabilities["version"] != 1 {
		t.Fatalf("capabilities: %#v", value)
	}
	if capabilities["state"] != "blocked" || capabilities["resourceState"] != "unknown" {
		t.Fatalf("fresh helper is not blocked/unknown: %#v", capabilities)
	}
	// Versioned work requires the launch store binding, the client-only build
	// identity and the shared resource claim; all are granted through the
	// production entrypoints.
	if err := runtime.BindStoreIdentity(testStore); err != nil {
		t.Fatal(err)
	}
	if err := runtime.BindClientOnly(false); err != nil {
		t.Fatal(err)
	}
	runtime.BindResourceClaim()
	begin := request{Method: "policyBegin"}
	begin.PolicyRequest = testPolicyRequest(t, instance, 2)
	if _, err := run(runtime, begin); err == nil || !strings.Contains(err.Error(), "POLICY_UNKNOWN") {
		t.Fatalf("publication before reconciliation: %v", err)
	}
	// The plan validator is reached through real dispatch, without observing the
	// host resources.
	reconcile := request{Method: "policyReconcile"}
	reconcile.PolicyRequest = testPolicyRequest(t, instance, 1)
	if _, err := run(runtime, reconcile); err == nil || !strings.Contains(err.Error(), "POLICY_INVALID") {
		t.Fatalf("schema-1 plan through dispatch: %v", err)
	}
	state, err := run(runtime, request{Method: "policyState"})
	if err != nil {
		t.Fatal(err)
	}
	if state.(map[string]any)["state"] != "blocked" {
		t.Fatalf("state after rejected publication: %#v", state)
	}
	if _, err := run(runtime, request{Method: "policyBogus"}); err == nil {
		t.Fatal("unsupported method accepted")
	}
}

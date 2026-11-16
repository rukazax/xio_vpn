package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"xio.local/rivet/internal/desktop"
)

const httpTestToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func readProjectionFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../internal/desktop/testdata/desktop-validation-projection.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture map[string]any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func fixtureRuntime(t *testing.T, fixture map[string]any) (*desktop.Runtime, string) {
	t.Helper()
	store, _ := fixture["storeIdentity"].(string)
	r := &desktop.Runtime{}
	if err := r.BindStoreIdentity(store); err != nil {
		t.Fatal(err)
	}
	if err := r.BindClientOnly(false); err != nil {
		t.Fatal(err)
	}
	r.BindResourceClaim()
	capabilities, err := r.PolicyCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	return r, capabilities["instanceNonce"].(string)
}

func manualEnvelope(t *testing.T, fixture map[string]any, instance string) map[string]any {
	t.Helper()
	manual, ok := fixture["manual"].(map[string]any)
	if !ok {
		t.Fatal("fixture has no manual variant")
	}
	original, ok := manual["validateRequest"].(map[string]any)
	if !ok {
		t.Fatal("fixture has no manual validateRequest")
	}
	envelope := make(map[string]any, len(original)+1)
	for key, value := range original {
		envelope[key] = value
	}
	envelope["instanceNonce"] = instance
	return envelope
}

func postRPC(t *testing.T, srv *httptest.Server, token string, body []byte) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, srv.URL+"/rpc", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var envelope map[string]any
	_ = json.NewDecoder(response.Body).Decode(&envelope)
	return response.StatusCode, envelope
}

func mutationBody(t *testing.T, envelope map[string]any, method string, overrides map[string]any) []byte {
	t.Helper()
	body := make(map[string]any, len(envelope)+1)
	for key, value := range envelope {
		if key == "validation" {
			continue
		}
		body[key] = value
	}
	for key, value := range overrides {
		body[key] = value
	}
	body["Method"] = method
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func validateBody(t *testing.T, envelope map[string]any) []byte {
	t.Helper()
	body := make(map[string]any, len(envelope)+1)
	for key, value := range envelope {
		body[key] = value
	}
	body["Method"] = "policyValidate"
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// renamedValidation simulates the application's owned rename/readback: the same
// document with the new receipt identity, exact bytes hashed without rewriting.
func renamedValidation(t *testing.T, fixture map[string]any, transaction, generation string) map[string]any {
	t.Helper()
	manual := fixture["manual"].(map[string]any)
	document := manual["document"].(map[string]any)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	var copied map[string]any
	if err := json.Unmarshal(raw, &copied); err != nil {
		t.Fatal(err)
	}
	receipt, ok := copied["connectionPlanReceipt"].(map[string]any)
	if !ok {
		t.Fatal("fixture document has no receipt")
	}
	receipt["transactionId"] = transaction
	receipt["planGeneration"] = generation
	documentBytes, err := json.Marshal(copied)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(documentBytes)
	validation := manual["validateRequest"].(map[string]any)["validation"].(map[string]any)
	return map[string]any{
		"schema":              1,
		"documentDigest":      hex.EncodeToString(digest[:]),
		"documentBytesBase64": base64.StdEncoding.EncodeToString(documentBytes),
		"configs":             validation["configs"],
	}
}

// TestHTTPValidateThenCommit exercises the real authenticated loopback transport
// with the immutable core fixture: validate → reconcile (READY), then a fresh
// begin → validate → commit (READY). Document/config bytes stay exact.
func TestHTTPValidateThenCommit(t *testing.T) {
	fixture := readProjectionFixture(t)
	runtime, instance := fixtureRuntime(t, fixture)
	server := httptest.NewServer(newMux(runtime, httpTestToken))
	defer server.Close()
	envelope := manualEnvelope(t, fixture, instance)
	manual := fixture["manual"].(map[string]any)

	status, response := postRPC(t, server, httpTestToken, validateBody(t, envelope))
	if status != http.StatusOK || response["ok"] != true {
		t.Fatalf("validate over HTTP: %d %#v", status, response)
	}
	value := response["value"].(map[string]any)
	if len(value) != 5 || value["documentDigest"] != manual["documentDigest"] {
		t.Fatalf("validate ACK over HTTP: %#v", value)
	}
	status, response = postRPC(t, server, httpTestToken, mutationBody(t, envelope, "policyReconcile", nil))
	if status != http.StatusOK || response["ok"] != true || response["value"].(map[string]any)["state"] != "ready" {
		t.Fatalf("reconcile over HTTP: %d %#v", status, response)
	}

	// A second generation: begin (CAS on the reconciled generation), validate,
	// commit. The transaction identity is the fixture's manual id.
	next := map[string]any{
		"transactionId":      "abababababababababababababababab",
		"planGeneration":     "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
		"expectedGeneration": manual["planGeneration"],
	}
	beginBody := mutationBody(t, envelope, "policyBegin", next)
	status, response = postRPC(t, server, httpTestToken, beginBody)
	if status != http.StatusOK || response["ok"] != true || response["value"].(map[string]any)["state"] != "pending" {
		t.Fatalf("begin over HTTP: %d %#v", status, response)
	}
	nextEnvelope := make(map[string]any, len(envelope))
	for key, item := range envelope {
		nextEnvelope[key] = item
	}
	for key, item := range next {
		nextEnvelope[key] = item
	}
	nextEnvelope["validation"] = renamedValidation(t, fixture, next["transactionId"].(string), next["planGeneration"].(string))
	status, response = postRPC(t, server, httpTestToken, validateBody(t, nextEnvelope))
	if status != http.StatusOK || response["ok"] != true {
		t.Fatalf("second validate over HTTP: %d %#v", status, response)
	}
	status, response = postRPC(t, server, httpTestToken, mutationBody(t, nextEnvelope, "policyCommit", nil))
	if status != http.StatusOK || response["ok"] != true || response["value"].(map[string]any)["state"] != "ready" {
		t.Fatalf("commit over HTTP: %d %#v", status, response)
	}
}

// TestHTTPBodyLimits proves the method-specific authenticated body cap and the
// unchanged 262144-byte logical cap for every other method, before decoding.
func TestHTTPBodyLimits(t *testing.T) {
	fixture := readProjectionFixture(t)
	runtime, _ := fixtureRuntime(t, fixture)
	server := httptest.NewServer(newMux(runtime, httpTestToken))
	defer server.Close()

	status, _ := postRPC(t, server, strings.Repeat("f", 64), []byte(`{"Method":"status"}`))
	if status != http.StatusForbidden {
		t.Fatalf("unauthenticated status %d", status)
	}
	oversizedStatus := []byte(`{"Method":"status","filler":"` + strings.Repeat("a", 262144) + `"}`)
	status, _ = postRPC(t, server, httpTestToken, oversizedStatus)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("old method oversized body status %d", status)
	}
	underValidationCap := []byte(`{"Method":"policyValidate","validation":{"documentBytesBase64":"` + strings.Repeat("A", 300000) + `"}}`)
	status, response := postRPC(t, server, httpTestToken, underValidationCap)
	if status != http.StatusOK {
		t.Fatalf("policyValidate under cap status %d", status)
	}
	if response["ok"] != false {
		t.Fatalf("invalid validation body unexpectedly accepted: %#v", response)
	}
	overValidationCap := []byte(`{"Method":"policyValidate","validation":{"documentBytesBase64":"` + strings.Repeat("A", 3<<20) + `"}}`)
	status, _ = postRPC(t, server, httpTestToken, overValidationCap)
	if status != http.StatusRequestEntityTooLarge {
		t.Fatalf("policyValidate above the 3 MiB cap status %d", status)
	}
}

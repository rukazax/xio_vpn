//go:build interopfixture

package issuancecapsule

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Test-only cross-runtime harness. The Go side generates a synthetic envelope
// and its exact payload bytes, the external Dart appendix (review-fixtures/
// g5-c0-interop) opens it with the accepted Dart codec and re-seals the same
// context/artifacts, and Verify opens the Dart envelope and compares the raw
// payload bytes byte-for-byte. No production code or Dart test is changed.

const interopScalarHex = scalarAHex

func interopContext() Context {
	return Context{
		Schema: Schema, Version: Version, Purpose: Purpose,
		Operation: "op-0001", UID: "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		Server: "srv-test-1", Deployment: "dep-test-1", Actor: "owner",
		RequestDigest:      requestDigestHex,
		ProfileSetDigest:   profileSetDigestHex,
	}
}

func interopArtifacts() map[string]string {
	return map[string]string{
		"cloak.uid":            base64CloakUID,
		"openvpn.client-key":   "SYNTHETIC\nKEY\n<>&/\"\\\nEND\n",
		"ikev2.password":       "c3ludGhldGljLXBhc3N3b3Jk",
	}
}

func interopDir(t *testing.T) string {
	t.Helper()
	directory := os.Getenv("INTEROP_DIR")
	if directory == "" {
		t.Skip("INTEROP_DIR not set")
	}
	return directory
}

func TestInteropGenerate(t *testing.T) {
	root := interopDir(t)
	goDirectory := filepath.Join(root, "go-direction")
	if err := os.MkdirAll(goDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	privateKey := mustHex(t, interopScalarHex)
	publicKey := publicFor(t, interopScalarHex)
	context := interopContext()
	artifacts := interopArtifacts()
	envelope, err := Seal(context, artifacts, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := encodePayload(context, artifacts)
	writeFile(t, filepath.Join(goDirectory, "go-envelope.json"), envelope.JSON())
	writeFile(t, filepath.Join(goDirectory, "go-plaintext.bin"), plaintext)
	contextJSON, _ := json.Marshal(map[string]any{
		"schema": 1, "purpose": Purpose, "version": 1,
		"operation": context.Operation, "uid": context.UID,
		"server": context.Server, "deployment": context.Deployment,
		"actor": context.Actor, "requestDigest": context.RequestDigest,
		"profileSetDigest": context.ProfileSetDigest,
	})
	writeFile(t, filepath.Join(goDirectory, "go-context.json"), contextJSON)
	artifactsJSON, _ := json.Marshal(artifacts)
	writeFile(t, filepath.Join(goDirectory, "artifacts.json"), artifactsJSON)
	writeFile(t, filepath.Join(goDirectory, "private.hex"), []byte(interopScalarHex))
	digest := sha256.Sum256(plaintext)
	expected, _ := json.Marshal(map[string]any{
		"plaintextSha256": hex.EncodeToString(digest[:]),
		"envelopeDigest":  envelope.Digest(),
		"contextCanonical": canonicalContext(context),
	})
	writeFile(t, filepath.Join(goDirectory, "expected.json"), expected)
	if len(privateKey) != 32 || len(envelope.Ciphertext) == 0 {
		t.Fatal("interop generation drifted")
	}
	t.Logf("generated go envelope digest %s", envelope.Digest())
}

func TestInteropVerify(t *testing.T) {
	root := interopDir(t)
	dartDirectory := filepath.Join(root, "dart-direction")
	rawEnvelope, err := os.ReadFile(filepath.Join(dartDirectory, "dart-envelope.json"))
	if err != nil {
		t.Skipf("dart direction missing: %v", err)
	}
	envelope, err := ParseEnvelope(rawEnvelope)
	if err != nil {
		t.Fatalf("dart envelope rejected: %v", err)
	}
	privateKey := mustHex(t, interopScalarHex)
	publicKey := publicFor(t, interopScalarHex)
	context := interopContext()
	openedContext, artifacts, err := Open(envelope, privateKey, publicKey, context)
	if err != nil {
		t.Fatalf("dart envelope did not open: %v", err)
	}
	if openedContext != context {
		t.Fatalf("context drift: %+v", openedContext)
	}
	for kind, value := range interopArtifacts() {
		if artifacts[kind] != value {
			t.Fatalf("artifact %s drift", kind)
		}
	}
	// Raw plaintext equality proves the Dart payload encoding is byte-identical
	// to the Go encoder (the accepted Dart codec produced this plaintext).
	rawPlaintext, err := os.ReadFile(filepath.Join(dartDirectory, "dart-plaintext.bin"))
	if err != nil {
		t.Fatal(err)
	}
	expectedPayload := encodePayload(context, interopArtifacts())
	if string(rawPlaintext) != string(expectedPayload) {
		t.Fatalf("plaintext bytes differ:\n got %s\nwant %s", rawPlaintext, expectedPayload)
	}
	sum := sha256.Sum256(rawPlaintext)
	expectedSum := sha256.Sum256(expectedPayload)
	if sum != expectedSum {
		t.Fatal("plaintext digest differs")
	}
	var result struct {
		Opened    bool              `json:"opened"`
		CapsuleID string            `json:"capsuleId"`
		Digest    string            `json:"digest"`
		Artifacts map[string]string `json:"artifacts"`
	}
	rawResult, err := os.ReadFile(filepath.Join(dartDirectory, "dart-result.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rawResult, &result); err != nil {
		t.Fatal(err)
	}
	if !result.Opened || result.Digest != envelope.Digest() || result.CapsuleID != envelope.CapsuleID {
		t.Fatalf("dart result disagrees: %+v", result)
	}
	for kind, value := range interopArtifacts() {
		if result.Artifacts[kind] != value {
			t.Fatalf("dart result artifact %s drift", kind)
		}
	}
	t.Logf("verified dart envelope digest %s", envelope.Digest())
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(fmt.Errorf("%s: %w", path, err))
	}
}

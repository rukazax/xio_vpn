package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"

	"xio.local/rivet/internal/issuancecapsule"
)

func testPublicKey(t *testing.T) []byte {
	t.Helper()
	scalar := make([]byte, 32)
	if _, err := rand.Read(scalar); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func validInput(t *testing.T, artifact string) []byte {
	t.Helper()
	payload := map[string]any{
		"context": map[string]any{
			"schema": 1, "purpose": "owner-issuance/delivery", "version": 1,
			"operation": "op-0001",
			"uid":       "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
			"server":    "srv-test-1", "deployment": "dep-test-1", "actor": "owner",
			"requestDigest":    strings.Repeat("0", 64),
			"profileSetDigest": strings.Repeat("f", 64),
		},
		"artifacts":          map[string]string{"cloak.uid": artifact},
		"recipientPublicKey": base64.StdEncoding.EncodeToString(testPublicKey(t)),
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func runSeal(t *testing.T, input []byte, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := seal(args, bytes.NewReader(input), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestSealValidInputWritesOneEnvelope(t *testing.T) {
	input := validInput(t, "wMHCw8TFxsfIycrLzM3Oz9A=")
	code, stdout, stderr := runSeal(t, input)
	if code != exitOK || stderr != "" {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("stdout must be exactly one line, got %d", len(lines))
	}
	envelope, err := issuancecapsule.ParseEnvelope([]byte(lines[0]))
	if err != nil {
		t.Fatalf("sealer output is not a strict envelope: %v", err)
	}
	if envelope.V != 1 || envelope.Alg != issuancecapsule.Alg || len(envelope.Ciphertext) != 48+len(decodedPlaintextForTest(t)) {
		t.Fatalf("envelope identity: %+v", envelope)
	}
}

func decodedPlaintextForTest(t *testing.T) string {
	t.Helper()
	return `{"actor":"owner","artifacts":{"cloak.uid":"wMHCw8TFxsfIycrLzM3Oz9A="},"deployment":"dep-test-1","operation":"op-0001","profileSetDigest":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","purpose":"owner-issuance/delivery","requestDigest":"0000000000000000000000000000000000000000000000000000000000000000","schema":1,"server":"srv-test-1","uid":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf","version":1}`
}

func badRecipientInput(t *testing.T) []byte {
	t.Helper()
	input := validInput(t, "x")
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(input, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded["recipientPublicKey"] = json.RawMessage(`"AAAA"`)
	out, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSealRejectsArgumentsAndBadInputs(t *testing.T) {
	cases := []struct {
		name  string
		input []byte
		args  []string
		code  string
	}{
		{"arguments", validInput(t, "x"), []string{"--secret=leak"}, codeUsage},
		{"empty stdin", nil, nil, codeInputShape},
		{"not json", []byte("not json"), nil, codeInputShape},
		{"unknown top field", bytes.Replace(validInput(t, "x"), []byte(`"artifacts"`), []byte(`"artifacts2"`), 1), nil, codeInputShape},
		{"missing top field", []byte(`{"context":{}}`), nil, codeInputShape},
		{"bad recipient", badRecipientInput(t), nil, codeRecipient},
		{"unknown artifact kind", bytes.Replace(validInput(t, "x"), []byte(`"cloak.uid"`), []byte(`"evil.kind"`), 1), nil, codeArtifacts},
		{"empty artifact", validInput(t, ""), nil, codeArtifacts},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runSeal(t, tc.input, tc.args...)
			if code != exitReject {
				t.Fatalf("exit %d", code)
			}
			if stdout != "" {
				t.Fatalf("rejected input wrote stdout: %q", stdout)
			}
			if stderr != tc.code+"\n" {
				t.Fatalf("stderr %q, want only %q", stderr, tc.code)
			}
		})
	}
}

func TestSealInputTooLarge(t *testing.T) {
	input := make([]byte, maxInputBytes+1)
	code, stdout, stderr := runSeal(t, input)
	if code != exitReject || stdout != "" || stderr != codeInputTooLarge+"\n" {
		t.Fatalf("oversize input: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
}

func TestSealNeverEchoesSecrets(t *testing.T) {
	secret := "SECRET-MARKER-9f3a"
	input := validInput(t, secret)
	code, stdout, stderr := runSeal(t, input)
	// The artifact value is legal printable ASCII, so the seal succeeds; neither
	// stream may contain the secret.
	if code != exitOK {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
	if strings.Contains(stdout, secret) || strings.Contains(stderr, secret) {
		t.Fatal("secret appeared on stdout/stderr")
	}
	// A rejected secret input must also not echo the value.
	bad := bytes.Replace(input, []byte(`"cloak.uid"`), []byte(`"evil.kind"`), 1)
	code, stdout, stderr = runSeal(t, bad)
	if code != exitReject || strings.Contains(stderr, secret) || strings.Contains(stdout, secret) {
		t.Fatalf("rejected secret input echoed data: %q %q", stdout, stderr)
	}
}

func TestSealStrictSingleValueAndDuplicates(t *testing.T) {
	input := validInput(t, "SYNTHETIC-SECRET-MARKER")
	cases := []struct {
		name string
		raw  []byte
		code string
	}{
		{"two json objects", append(append([]byte{}, input...), []byte(`{}`)...), codeInputShape},
		{"trailing garbage", append(append([]byte{}, input...), 'x'), codeInputShape},
		{"duplicate top", bytes.Replace(input, []byte(`"artifacts":`), []byte(`"artifacts":{},"artifacts":`), 1), codeInputShape},
		{"duplicate context", bytes.Replace(input, []byte(`"operation":"op-0001"`), []byte(`"operation":"first","operation":"op-0001"`), 1), codeInputShape},
		{"duplicate artifact", bytes.Replace(input, []byte(`"cloak.uid":"SYNTHETIC-SECRET-MARKER"`), []byte(`"cloak.uid":"first","cloak.uid":"SYNTHETIC-SECRET-MARKER"`), 1), codeInputShape},
		{"quoted schema", bytes.Replace(input, []byte(`"schema":1`), []byte(`"schema":"1"`), 1), codeContext},
		{"quoted version", bytes.Replace(input, []byte(`"version":1`), []byte(`"version":"1"`), 1), codeContext},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runSeal(t, tc.raw)
			if code != exitReject || stdout != "" || stderr != tc.code+"\n" {
				t.Fatalf("exit=%d stdout=%q stderr=%q want %q", code, stdout, stderr, tc.code)
			}
			if strings.Contains(stderr, "SYNTHETIC-SECRET-MARKER") {
				t.Fatal("secret echoed")
			}
		})
	}
}

func TestSealAcceptsSurroundingWhitespace(t *testing.T) {
	input := validInput(t, "x")
	code, stdout, stderr := runSeal(t, append(append([]byte("\n\t "), input...), []byte(" \n")...))
	if code != exitOK || stderr != "" {
		t.Fatalf("whitespace-wrapped valid input: exit=%d stderr=%q", code, stderr)
	}
	if _, err := issuancecapsule.ParseEnvelope([]byte(strings.TrimSpace(stdout))); err != nil {
		t.Fatalf("stdout envelope: %v", err)
	}
}

package issuancecapsule

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Synthetic keys from the accepted Dart capsule test (TEST-ONLY, public).
const (
	scalarAHex          = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	scalarBHex          = "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
	requestDigestHex    = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	profileSetDigestHex = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
	uidHex              = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
	base64CloakUID      = "wMHCw8TFxsfIycrLzM3Oz9A="
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func publicFor(t *testing.T, scalarHex string) []byte {
	t.Helper()
	scalar := mustHex(t, scalarHex)
	public, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return public
}

func testContext(operation string) Context {
	return Context{
		Schema: Schema, Version: Version, Purpose: Purpose,
		Operation: operation, UID: uidHex,
		Server: "srv-test-1", Deployment: "dep-test-1", Actor: "owner",
		RequestDigest: requestDigestHex, ProfileSetDigest: profileSetDigestHex,
	}
}

func testArtifacts() map[string]string {
	return map[string]string{"cloak.uid": base64CloakUID}
}

const expectedPayload = `{"actor":"owner","artifacts":{"cloak.uid":"wMHCw8TFxsfIycrLzM3Oz9A="},"deployment":"dep-test-1","operation":"op-0001","profileSetDigest":"ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100","purpose":"owner-issuance/delivery","requestDigest":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff","schema":1,"server":"srv-test-1","uid":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf","version":1}`

func TestPayloadEncodingMatchesAcceptedDartShape(t *testing.T) {
	payload := encodePayload(testContext("op-0001"), testArtifacts())
	if string(payload) != expectedPayload {
		t.Fatalf("payload differs from accepted encoding:\n got %s\nwant %s", payload, expectedPayload)
	}
	sum := sha256.Sum256(payload)
	if len(sum) != 32 {
		t.Fatal("digest width")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	publicA := publicFor(t, scalarAHex)
	privateA := mustHex(t, scalarAHex)
	context := testContext("op-0001")
	envelope, err := Seal(context, testArtifacts(), publicA)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.V != Version || envelope.Alg != Alg || len(envelope.CapsuleID) != 32 {
		t.Fatalf("envelope identity: %+v", envelope)
	}
	if len(envelope.Ciphertext) != len(expectedPayload)+AnonymousOverhead {
		t.Fatalf("ciphertext length %d", len(envelope.Ciphertext))
	}
	parsed, err := ParseEnvelope(envelope.JSON())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Digest() != envelope.Digest() || parsed.CapsuleID != envelope.CapsuleID {
		t.Fatal("parsed envelope drifted")
	}
	opened, artifacts, err := Open(parsed, privateA, publicA, context)
	if err != nil {
		t.Fatal(err)
	}
	if opened != context {
		t.Fatalf("context mismatch: %+v", opened)
	}
	if artifacts["cloak.uid"] != base64CloakUID {
		t.Fatalf("artifacts: %+v", artifacts)
	}
	if len(artifacts) != 1 {
		t.Fatalf("artifact count: %d", len(artifacts))
	}
}

func TestOpenRejectsWrongRecipient(t *testing.T) {
	publicA := publicFor(t, scalarAHex)
	privateA := mustHex(t, scalarAHex)
	publicB := publicFor(t, scalarBHex)
	context := testContext("op-0001")
	envelope, err := Seal(context, testArtifacts(), publicA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(envelope, privateA, publicB, context); reason(err) != ReasonRecipientKey {
		t.Fatalf("wrong expected recipient: %v", err)
	}
	forB, err := Seal(context, testArtifacts(), publicB)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(forB, privateA, publicA, context); reason(err) != ReasonRecipientKey {
		t.Fatalf("envelope for another recipient: %v", err)
	}
	// A validly sealed capsule for another operation opens cryptographically but
	// the bound context comparison rejects it.
	other, err := Seal(testContext("op-0002"), testArtifacts(), publicA)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Open(other, privateA, publicA, context); reason(err) != ReasonContext {
		t.Fatalf("context swap: %v", err)
	}
}

func TestOpenTamperAndTruncation(t *testing.T) {
	publicA := publicFor(t, scalarAHex)
	privateA := mustHex(t, scalarAHex)
	context := testContext("op-0001")
	envelope, err := Seal(context, testArtifacts(), publicA)
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 32, 40, len(envelope.Ciphertext) - 1} {
		tampered := append([]byte(nil), envelope.Ciphertext...)
		tampered[index] ^= 0x01
		candidate := envelope
		candidate.Ciphertext = tampered
		if _, _, err := Open(candidate, privateA, publicA, context); reason(err) != ReasonBadBox {
			t.Fatalf("tamper index %d: %v", index, err)
		}
	}
	for _, length := range []int{0, 1, 32, 47, 48} {
		candidate := envelope
		candidate.Ciphertext = envelope.Ciphertext[:length]
		if _, _, err := Open(candidate, privateA, publicA, context); reason(err) != ReasonShort {
			t.Fatalf("truncation %d: %v", length, err)
		}
	}
	for _, length := range []int{49, 50, len(envelope.Ciphertext) - 1} {
		candidate := envelope
		candidate.Ciphertext = envelope.Ciphertext[:length]
		if _, _, err := Open(candidate, privateA, publicA, context); reason(err) != ReasonBadBox {
			t.Fatalf("short valid-prefix %d: %v", length, err)
		}
	}
	// 49 bytes of garbage must be a bad box, never a panic.
	garbage := Envelope{V: Version, Alg: Alg, CapsuleID: strings.Repeat("0", 32),
		RecipientPublicKey: publicA, Ciphertext: bytes.Repeat([]byte{0x42}, 49)}
	if _, _, err := Open(garbage, privateA, publicA, context); reason(err) != ReasonBadBox {
		t.Fatalf("49-byte garbage: %v", err)
	}
}

func TestEnvelopeParsingIsStrict(t *testing.T) {
	publicA := publicFor(t, scalarAHex)
	envelope, err := Seal(testContext("op-0001"), testArtifacts(), publicA)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(envelope.JSON())
	cases := map[string]string{
		"extra field":  strings.Replace(valid, `}`, `,"extra":1}`, 1),
		"missing v":    strings.Replace(valid, `{"v":1,`, `{`, 1),
		"wrong v":      strings.Replace(valid, `"v":1`, `"v":2`, 1),
		"wrong alg":    strings.Replace(valid, Alg, "other-alg", 1),
		"short id":     strings.Replace(valid, envelope.CapsuleID, "abc", 1),
		"upper id":     strings.Replace(valid, envelope.CapsuleID, strings.ToUpper(envelope.CapsuleID), 1),
		"recipient 31": strings.Replace(valid, base64.StdEncoding.EncodeToString(publicA), base64.StdEncoding.EncodeToString(publicA[:31]), 1),
		"bad base64":   strings.Replace(valid, base64.StdEncoding.EncodeToString(envelope.Ciphertext), "!!!", 1),
		"trailing":     valid + "x",
		"not object":   `[]`,
	}
	for name, raw := range cases {
		if _, err := ParseEnvelope([]byte(raw)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// Non-canonical base64 spelling: change the last character while keeping
	// decoded length/padding valid is hard; an unpadded variant is rejected.
	if _, err := ParseEnvelope([]byte(strings.Replace(valid,
		base64.StdEncoding.EncodeToString(publicA), strings.TrimRight(base64.StdEncoding.EncodeToString(publicA), "="), 1))); err == nil {
		t.Fatal("unpadded base64 accepted")
	}
}

func TestArtifactsClosedKindsAndLimits(t *testing.T) {
	publicA := publicFor(t, scalarAHex)
	context := testContext("op-0001")
	if _, err := Seal(context, map[string]string{"evil.kind": "x"}, publicA); reason(err) != ReasonArtifactKind {
		t.Fatalf("unknown kind: %v", err)
	}
	if _, err := Seal(context, map[string]string{"cloak.uid": ""}, publicA); reason(err) != ReasonArtifactSize {
		t.Fatalf("empty value: %v", err)
	}
	if _, err := Seal(context, map[string]string{"cloak.uid": strings.Repeat("a", MaxArtifactBytes+1)}, publicA); reason(err) != ReasonArtifactSize {
		t.Fatalf("oversize value: %v", err)
	}
	// Control characters other than LF are rejected; LF (PEM) is accepted.
	if _, err := Seal(context, map[string]string{"openvpn.client-key": "a\rb"}, publicA); reason(err) != ReasonArtifactSize {
		t.Fatalf("CR accepted: %v", err)
	}
	// Empty artifact map is valid (the accepted Dart codec allows it).
	envelope, err := Seal(context, map[string]string{}, publicA)
	if err != nil {
		t.Fatal(err)
	}
	_, artifacts, err := Open(envelope, mustHex(t, scalarAHex), publicA, context)
	if err != nil || len(artifacts) != 0 {
		t.Fatalf("empty artifacts round trip: %v %v", artifacts, err)
	}
}

func TestPEMArtifactAllowsLFAndHTMLCharacters(t *testing.T) {
	publicA := publicFor(t, scalarAHex)
	privateA := mustHex(t, scalarAHex)
	context := testContext("op-0001")
	pem := "SYNTHETIC\nKEY\n<>&/\"\\\nEND\n"
	envelope, err := Seal(context, map[string]string{"openvpn.client-key": pem}, publicA)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := decryptForTest(t, envelope, privateA)
	if !bytes.Contains(plaintext, []byte(`<>&/`)) {
		t.Fatalf("HTML characters were escaped in the payload: %s", plaintext)
	}
	if !bytes.Contains(plaintext, []byte(`\n`)) {
		t.Fatalf("LF was not escaped as \\n: %s", plaintext)
	}
	opened, artifacts, err := Open(envelope, privateA, publicA, context)
	if err != nil {
		t.Fatal(err)
	}
	if opened != context || artifacts["openvpn.client-key"] != pem {
		t.Fatalf("PEM round trip drifted: %+v %q", opened, artifacts["openvpn.client-key"])
	}
}

func TestPayloadSizeBound(t *testing.T) {
	publicA := publicFor(t, scalarAHex)
	context := testContext("op-0001")
	artifacts := map[string]string{}
	for index, kind := range ArtifactKinds[:4] {
		artifacts[kind] = strings.Repeat(string(rune('a'+index)), MaxArtifactBytes)
	}
	if _, err := Seal(context, artifacts, publicA); reason(err) != ReasonPlaintextSize {
		t.Fatalf("oversize plaintext accepted or wrong reason: %v", err)
	}
	// A single 8192-byte artifact plus context stays under 32 KiB.
	small := map[string]string{"cloak.uid": strings.Repeat("a", MaxArtifactBytes)}
	if _, err := Seal(context, small, publicA); err != nil {
		t.Fatalf("bounded artifact rejected: %v", err)
	}
}

func TestContextValidation(t *testing.T) {
	publicA := publicFor(t, scalarAHex)
	base := testContext("op-0001")
	cases := map[string]Context{
		"bad operation":   func() Context { c := base; c.Operation = "bad op"; return c }(),
		"long operation":  func() Context { c := base; c.Operation = strings.Repeat("a", 65); return c }(),
		"bad uid":         func() Context { c := base; c.UID = "zz"; return c }(),
		"bad digest":      func() Context { c := base; c.RequestDigest = strings.Repeat("A", 64); return c }(),
		"empty server":    func() Context { c := base; c.Server = ""; return c }(),
		"long deployment": func() Context { c := base; c.Deployment = strings.Repeat("d", 129); return c }(),
		"non-printable":   func() Context { c := base; c.Actor = "owner\n"; return c }(),
		"wrong schema":    func() Context { c := base; c.Schema = 2; return c }(),
		"wrong version":   func() Context { c := base; c.Version = 2; return c }(),
		"wrong purpose":   func() Context { c := base; c.Purpose = "other"; return c }(),
	}
	for name, context := range cases {
		if _, err := Seal(context, testArtifacts(), publicA); reason(err) != ReasonContext {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestSealRejectsBadRecipientKey(t *testing.T) {
	for _, length := range []int{0, 31, 33} {
		if _, err := Seal(testContext("op-0001"), testArtifacts(), make([]byte, length)); reason(err) != ReasonRecipientKey {
			t.Fatalf("recipient length %d: %v", length, err)
		}
	}
}

func TestOpenRejectsMalformedPayload(t *testing.T) {
	publicA := publicFor(t, scalarAHex)
	privateA := mustHex(t, scalarAHex)
	context := testContext("op-0001")
	cases := map[string]string{
		"not json":            "hello-not-json",
		"not object":          `[]`,
		"missing uid":         strings.Replace(expectedPayload, `"uid":"`+uidHex+`",`, "", 1),
		"unexpected field":    strings.Replace(expectedPayload, `}`, `,"extra":1}`, 1),
		"wrong schema":        strings.Replace(expectedPayload, `"schema":1`, `"schema":2`, 1),
		"wrong purpose":       strings.Replace(expectedPayload, `"owner-issuance/delivery"`, `"other"`, 1),
		"wrong version":       strings.Replace(expectedPayload, `"version":1`, `"version":2`, 1),
		"other operation":     strings.Replace(expectedPayload, `"op-0001"`, `"op-0002"`, 1),
		"unknown artifact":    strings.Replace(expectedPayload, `"cloak.uid"`, `"evil.kind"`, 1),
		"empty artifact":      strings.Replace(expectedPayload, `"wMHCw8TFxsfIycrLzM3Oz9A="`, `""`, 1),
		"non-printable value": strings.Replace(expectedPayload, `"wMHCw8TFxsfIycrLzM3Oz9A="`, `"a\u0001b"`, 1),
		"duplicate key":       strings.Replace(expectedPayload, `"actor":"owner"`, `"actor":"owner","actor":"other"`, 1),
		"blank":               "   ",
	}
	for name, payload := range cases {
		ciphertext := sealForTest(t, []byte(payload), publicA)
		envelope := Envelope{V: Version, Alg: Alg, CapsuleID: strings.Repeat("0", 32),
			RecipientPublicKey: publicA, Ciphertext: ciphertext}
		_, _, err := Open(envelope, privateA, publicA, context)
		if err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func reason(err error) RejectReason {
	if rejection, ok := err.(*Rejection); ok {
		return rejection.Reason
	}
	return ""
}

func sealForTest(t *testing.T, plaintext, recipient []byte) []byte {
	t.Helper()
	var key [32]byte
	copy(key[:], recipient)
	ciphertext, err := box.SealAnonymous(nil, plaintext, &key, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func decryptForTest(t *testing.T, envelope Envelope, privateKey []byte) []byte {
	t.Helper()
	var private, public [32]byte
	copy(private[:], privateKey)
	copy(public[:], envelope.RecipientPublicKey)
	plaintext, ok := box.OpenAnonymous(nil, envelope.Ciphertext, &public, &private)
	if !ok {
		t.Fatal("test decrypt failed")
	}
	return plaintext
}

func TestEqualFieldValuesRoundTrip(t *testing.T) {
	// Reviewer counterexample: valid JSON with equal values (not duplicate keys)
	// must survive Seal -> Open.
	publicA := publicFor(t, scalarAHex)
	privateA := mustHex(t, scalarAHex)
	context := testContext("deployment-equals-operation")
	context.Operation = "same-value"
	context.Deployment = "same-value"
	context.RequestDigest = strings.Repeat("a", 64)
	context.ProfileSetDigest = strings.Repeat("a", 64)
	envelope, err := Seal(context, testArtifacts(), publicA)
	if err != nil {
		t.Fatal(err)
	}
	opened, artifacts, err := Open(envelope, privateA, publicA, context)
	if err != nil {
		t.Fatalf("valid equal values rejected: %v", err)
	}
	if opened != context || artifacts["cloak.uid"] != base64CloakUID {
		t.Fatalf("equal-value round trip drifted: %+v %+v", opened, artifacts)
	}
}

func TestPayloadDuplicateAfterNestedObjectRejected(t *testing.T) {
	publicA := publicFor(t, scalarAHex)
	privateA := mustHex(t, scalarAHex)
	context := testContext("op-0001")
	// The first "deployment" follows the closed artifacts object; the duplicate
	// must be seen as a key in the parent object, not as a value.
	payload := strings.Replace(expectedPayload,
		`},"deployment":"dep-test-1",`,
		`},"deployment":"dep-test-1","deployment":"dep-test-1",`, 1)
	if payload == expectedPayload {
		t.Fatal("test payload was not mutated")
	}
	envelope := Envelope{V: Version, Alg: Alg, CapsuleID: strings.Repeat("0", 32),
		RecipientPublicKey: publicA, Ciphertext: sealForTest(t, []byte(payload), publicA)}
	if _, _, err := Open(envelope, privateA, publicA, context); reason(err) != ReasonNotJSON {
		t.Fatalf("duplicate after nested object accepted: %v", err)
	}
}

func TestPublicEnvelopeInvariants(t *testing.T) {
	publicA := publicFor(t, scalarAHex)
	privateA := mustHex(t, scalarAHex)
	context := testContext("op-0001")
	base, err := Seal(context, testArtifacts(), publicA)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mutate func(*Envelope)
		want   RejectReason
	}{
		{"wrong version", func(e *Envelope) { e.V = 2 }, ReasonEnvelopeShape},
		{"wrong algorithm", func(e *Envelope) { e.Alg = "other" }, ReasonEnvelopeShape},
		{"bad capsule id", func(e *Envelope) { e.CapsuleID = "XYZ" }, ReasonEnvelopeShape},
		{"short recipient", func(e *Envelope) { e.RecipientPublicKey = e.RecipientPublicKey[:31] }, ReasonEnvelopeShape},
		{"oversize ciphertext", func(e *Envelope) { e.Ciphertext = make([]byte, MaxCiphertext+1) }, ReasonTooLarge},
	}
	for _, tc := range cases {
		envelope := base
		tc.mutate(&envelope)
		if _, _, err := Open(envelope, privateA, publicA, context); reason(err) != tc.want {
			t.Fatalf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestParseSealRequestIsStrict(t *testing.T) {
	valid := []byte(`{"context":{"schema":1,"purpose":"owner-issuance/delivery","version":1,"operation":"op-0001","uid":"` + uidHex + `","server":"srv-test-1","deployment":"dep-test-1","actor":"owner","requestDigest":"` + requestDigestHex + `","profileSetDigest":"` + profileSetDigestHex + `"},"artifacts":{"cloak.uid":"` + base64CloakUID + `"},"recipientPublicKey":"` + base64.StdEncoding.EncodeToString(publicFor(t, scalarAHex)) + `"}`)
	if _, err := ParseSealRequest(valid); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	cases := map[string]struct {
		raw  []byte
		want error
	}{
		"second json":        {append(append([]byte{}, valid...), []byte(`{}`)...), ErrSealRequestShape},
		"trailing garbage":   {append(append([]byte{}, valid...), 'x'), ErrSealRequestShape},
		"duplicate top":      {bytes.Replace(valid, []byte(`"artifacts":`), []byte(`"artifacts":{},"artifacts":`), 1), ErrSealRequestShape},
		"duplicate context":  {bytes.Replace(valid, []byte(`"operation":"op-0001"`), []byte(`"operation":"first","operation":"op-0001"`), 1), ErrSealRequestShape},
		"duplicate artifact": {bytes.Replace(valid, []byte(`"cloak.uid":"`+base64CloakUID+`"`), []byte(`"cloak.uid":"first","cloak.uid":"`+base64CloakUID+`"`), 1), ErrSealRequestShape},
		"quoted schema":      {bytes.Replace(valid, []byte(`"schema":1`), []byte(`"schema":"1"`), 1), ErrSealRequestContext},
		"quoted version":     {bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":"1"`), 1), ErrSealRequestContext},
		"decimal schema":     {bytes.Replace(valid, []byte(`"schema":1`), []byte(`"schema":1.0`), 1), ErrSealRequestContext},
		"exponent version":   {bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1e0`), 1), ErrSealRequestContext},
	}
	for name, tc := range cases {
		if _, err := ParseSealRequest(tc.raw); !errors.Is(err, tc.want) {
			t.Fatalf("%s: got %v, want %v", name, err, tc.want)
		}
	}
}

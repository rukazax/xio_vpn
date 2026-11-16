// Package issuancecapsule implements the bounded Go side of the XIO-CAPSULE-1
// recipient-encrypted delivery capsule (G5 C0 primitive).
//
// It is a codec, not an authority: a sealed box is anonymous, so a capsule gives
// confidentiality and context binding only. It proves nothing about the sender,
// key validity, CA state, server behaviour or the material inside; delivery trust
// stays with the pinned transport and the authenticated receipt.
//
// The wire/envelope/context/artifact limits and the payload encoding mirror the
// accepted Dart implementation (app/lib/issuance_capsule.dart at 2efbb18c):
// envelope {v, alg, capsuleId, recipientPublicKey, ciphertext}; plaintext is one
// canonical UTF-8 JSON object whose artifact values may contain LF (PEM) but are
// otherwise printable ASCII. The ciphertext is libsodium crypto_box_seal
// (ephemeral X25519 public key + XSalsa20-Poly1305 secretbox) via
// golang.org/x/crypto/nacl/box and crypto/rand; no cryptography is hand-rolled.
package issuancecapsule

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

// Protocol constants mirrored from the accepted Dart v1 codec.
const (
	Version           = 1
	Schema            = 1
	Purpose           = "owner-issuance/delivery"
	Alg               = "nacl-box-sealed-x25519-xsalsa20-poly1305-b2b24"
	AnonymousOverhead = 48
	MaxPlaintext      = 32768
	MaxCiphertext     = 32816
	MaxEnvelopeBytes  = 45056
	MaxArtifactBytes  = 8192
	MaxArtifacts      = 8
)

// ArtifactKinds is the closed v1 artifact set. An unknown kind is a rejection.
var ArtifactKinds = []string{
	"openvpn.client-key",
	"openvpn.tls-crypt-v2-client",
	"openvpn.client-cert",
	"ikev2.password",
	"tailscale.authKey",
	"cloak.uid",
}

// RejectReason is a finite, non-secret rejection code. Error strings never
// contain payload data, so they are safe for bounded diagnostics.
type RejectReason string

const (
	ReasonEnvelopeShape  RejectReason = "envelope_shape"
	ReasonTooLarge       RejectReason = "capsule_too_large"
	ReasonShort          RejectReason = "short"
	ReasonBadBox         RejectReason = "bad_box"
	ReasonEmpty          RejectReason = "empty"
	ReasonBlank          RejectReason = "blank"
	ReasonNotJSON        RejectReason = "not_json"
	ReasonNotObject      RejectReason = "not_object"
	ReasonMissingField   RejectReason = "missing_field"
	ReasonUnexpected     RejectReason = "unexpected_field"
	ReasonSchema         RejectReason = "schema"
	ReasonPurpose        RejectReason = "purpose"
	ReasonVersion        RejectReason = "version"
	ReasonContext        RejectReason = "context"
	ReasonRecipientKey   RejectReason = "recipient_key"
	ReasonArtifactKind   RejectReason = "artifact_kind"
	ReasonArtifactSize   RejectReason = "artifact_size"
	ReasonPlaintextSize  RejectReason = "plaintext_size"
	ReasonInternalRandom RejectReason = "internal_random"
)

// Rejection is a bounded error carrying only a finite reason code.
type Rejection struct{ Reason RejectReason }

func (e *Rejection) Error() string { return string(e.Reason) }

func reject(reason RejectReason) error { return &Rejection{Reason: reason} }

// Context is the bound capsule context (the AAD substitute, stored in plaintext).
type Context struct {
	Schema           int
	Version          int
	Purpose          string
	Operation        string
	UID              string
	Server           string
	Deployment       string
	Actor            string
	RequestDigest    string
	ProfileSetDigest string
}

// Envelope is the exact five-field v1 envelope.
type Envelope struct {
	V                  int
	Alg                string
	CapsuleID          string
	RecipientPublicKey []byte
	Ciphertext         []byte
}

// Digest is SHA-256 over the decoded ciphertext (lowercase hex), matching the
// Dart CapsuleEnvelope.digest.
func (e Envelope) Digest() string {
	sum := sha256.Sum256(e.Ciphertext)
	return hex.EncodeToString(sum[:])
}

// JSON renders the exact five-field envelope object in the accepted field order.
func (e Envelope) JSON() []byte {
	var output strings.Builder
	output.WriteString(`{"v":`)
	output.WriteString(strconv.Itoa(e.V))
	output.WriteString(`,"alg":`)
	output.WriteString(quoteASCII(e.Alg))
	output.WriteString(`,"capsuleId":`)
	output.WriteString(quoteASCII(e.CapsuleID))
	output.WriteString(`,"recipientPublicKey":`)
	output.WriteString(quoteASCII(base64.StdEncoding.EncodeToString(e.RecipientPublicKey)))
	output.WriteString(`,"ciphertext":`)
	output.WriteString(quoteASCII(base64.StdEncoding.EncodeToString(e.Ciphertext)))
	output.WriteString(`}`)
	return []byte(output.String())
}

// ValidateContext enforces the accepted Dart CapsuleContext constructor rules.
func ValidateContext(context Context) error {
	if context.Schema != Schema || context.Version != Version || context.Purpose != Purpose {
		return reject(ReasonContext)
	}
	if !validOperation(context.Operation) {
		return reject(ReasonContext)
	}
	if !validUID(context.UID) {
		return reject(ReasonContext)
	}
	if !isLowerHex(context.RequestDigest, 64) || !isLowerHex(context.ProfileSetDigest, 64) {
		return reject(ReasonContext)
	}
	for _, value := range []string{context.Server, context.Deployment, context.Actor} {
		if len(value) == 0 || len(value) > 128 || !printableASCII(value) {
			return reject(ReasonContext)
		}
	}
	return nil
}

// Seal validates the context/artifacts/recipient, encodes the canonical payload
// and returns a fresh envelope with a random 16-byte capsule id and a
// crypto_box_seal ciphertext.
func Seal(context Context, artifacts map[string]string, recipientPublicKey []byte) (Envelope, error) {
	if err := ValidateContext(context); err != nil {
		return Envelope{}, err
	}
	if len(recipientPublicKey) != 32 {
		return Envelope{}, reject(ReasonRecipientKey)
	}
	validated, err := validateArtifacts(artifacts)
	if err != nil {
		return Envelope{}, err
	}
	plaintext := encodePayload(context, validated)
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		return Envelope{}, reject(ReasonPlaintextSize)
	}
	var recipient [32]byte
	copy(recipient[:], recipientPublicKey)
	ciphertext, err := box.SealAnonymous(nil, plaintext, &recipient, rand.Reader)
	if err != nil {
		return Envelope{}, reject(ReasonInternalRandom)
	}
	if len(ciphertext) > MaxCiphertext {
		return Envelope{}, reject(ReasonTooLarge)
	}
	var capsuleID [16]byte
	if _, err := io.ReadFull(rand.Reader, capsuleID[:]); err != nil {
		return Envelope{}, reject(ReasonInternalRandom)
	}
	envelope := Envelope{
		V:                  Version,
		Alg:                Alg,
		CapsuleID:          hex.EncodeToString(capsuleID[:]),
		RecipientPublicKey: append([]byte(nil), recipientPublicKey...),
		Ciphertext:         ciphertext,
	}
	if len(envelope.JSON()) > MaxEnvelopeBytes {
		return Envelope{}, reject(ReasonTooLarge)
	}
	return envelope, nil
}

// Open mirrors the accepted Dart open order exactly: key binding, the 48-byte
// trap guard before any box operation, bare MAC failure, non-empty/UTF-8/blank
// checks, strict payload shape, schema/purpose/version equality, context
// equality and closed artifact kinds/sizes. Opening never validates the material
// and never implies authenticity.
func Open(envelope Envelope, recipientPrivateKey, expectedRecipientPublicKey []byte, expected Context) (Context, map[string]string, error) {
	// The public Envelope struct is not a trusted entry point: enforce the same
	// v/alg/capsuleId/key/size invariants ParseEnvelope enforces on the wire, so a
	// caller cannot bypass them by constructing the struct directly.
	if err := validateEnvelopeFields(envelope); err != nil {
		return Context{}, nil, err
	}
	if len(recipientPrivateKey) != 32 || len(expectedRecipientPublicKey) != 32 {
		return Context{}, nil, reject(ReasonRecipientKey)
	}
	var privateKey, publicKey [32]byte
	copy(privateKey[:], recipientPrivateKey)
	derived, err := curve25519.X25519(privateKey[:], curve25519.Basepoint)
	if err != nil {
		return Context{}, nil, reject(ReasonRecipientKey)
	}
	if !constantTimeEqual(derived, envelope.RecipientPublicKey) || !constantTimeEqual(derived, expectedRecipientPublicKey) {
		return Context{}, nil, reject(ReasonRecipientKey)
	}
	copy(publicKey[:], derived)
	if len(envelope.Ciphertext) <= AnonymousOverhead {
		return Context{}, nil, reject(ReasonShort)
	}
	if len(envelope.Ciphertext) > MaxCiphertext {
		return Context{}, nil, reject(ReasonTooLarge)
	}
	plaintext, ok := box.OpenAnonymous(nil, envelope.Ciphertext, &publicKey, &privateKey)
	if !ok || len(plaintext) == 0 {
		return Context{}, nil, reject(ReasonBadBox)
	}
	context, artifacts, err := decodePayload(plaintext)
	if err != nil {
		return Context{}, nil, err
	}
	if context.Schema != expected.Schema {
		return Context{}, nil, reject(ReasonSchema)
	}
	if context.Purpose != expected.Purpose {
		return Context{}, nil, reject(ReasonPurpose)
	}
	if context.Version != expected.Version {
		return Context{}, nil, reject(ReasonVersion)
	}
	if canonicalContext(context) != canonicalContext(expected) {
		return Context{}, nil, reject(ReasonContext)
	}
	return context, artifacts, nil
}

// ParseEnvelope strictly decodes the five-field envelope JSON: exact field set,
// types, canonical base64 spelling, decoded lengths and the envelope size bound.
func ParseEnvelope(raw []byte) (Envelope, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return Envelope{}, reject(ReasonTooLarge)
	}
	if err := checkNoDuplicateKeys(raw); err != nil {
		return Envelope{}, reject(ReasonEnvelopeShape)
	}
	fields, err := strictObject(raw, []string{"v", "alg", "capsuleId", "recipientPublicKey", "ciphertext"})
	if err != nil {
		if errors.Is(err, errMissingField) {
			return Envelope{}, reject(ReasonMissingField)
		}
		if errors.Is(err, errUnexpectedField) {
			return Envelope{}, reject(ReasonUnexpected)
		}
		return Envelope{}, reject(ReasonEnvelopeShape)
	}
	v, err := intValue(fields["v"])
	if err != nil || v != Version {
		return Envelope{}, reject(ReasonEnvelopeShape)
	}
	alg, err := stringValue(fields["alg"])
	if err != nil || alg != Alg {
		return Envelope{}, reject(ReasonEnvelopeShape)
	}
	capsuleID, err := stringValue(fields["capsuleId"])
	if err != nil || !isLowerHex(capsuleID, 32) {
		return Envelope{}, reject(ReasonEnvelopeShape)
	}
	recipientText, err := stringValue(fields["recipientPublicKey"])
	if err != nil {
		return Envelope{}, reject(ReasonEnvelopeShape)
	}
	recipient, err := decodeCanonicalBase64(recipientText, 32)
	if err != nil {
		return Envelope{}, reject(ReasonEnvelopeShape)
	}
	ciphertextText, err := stringValue(fields["ciphertext"])
	if err != nil {
		return Envelope{}, reject(ReasonEnvelopeShape)
	}
	ciphertext, err := decodeCanonicalBase64Any(ciphertextText, MaxCiphertext)
	if err != nil {
		return Envelope{}, reject(ReasonEnvelopeShape)
	}
	envelope := Envelope{V: v, Alg: alg, CapsuleID: capsuleID, RecipientPublicKey: recipient, Ciphertext: ciphertext}
	if len(envelope.JSON()) > MaxEnvelopeBytes {
		return Envelope{}, reject(ReasonTooLarge)
	}
	return envelope, nil
}

func canonicalContext(context Context) string {
	payload := map[string]any{
		"schema":           context.Schema,
		"purpose":          context.Purpose,
		"version":          context.Version,
		"operation":        context.Operation,
		"uid":              context.UID,
		"server":           context.Server,
		"deployment":       context.Deployment,
		"actor":            context.Actor,
		"requestDigest":    context.RequestDigest,
		"profileSetDigest": context.ProfileSetDigest,
	}
	encoded, _ := CanonicalJSON(payload)
	return encoded
}

// CanonicalJSON is the v1 canonical encoder: sorted keys, no whitespace,
// integers/bools/strings/lists/maps only, ASCII-only strings, null/floats
// rejected. It mirrors Dart canonicalJsonV1 for context comparisons.
func CanonicalJSON(value any) (string, error) {
	var output strings.Builder
	if err := writeCanonical(&output, value); err != nil {
		return "", err
	}
	return output.String(), nil
}

func writeCanonical(output *strings.Builder, value any) error {
	switch typed := value.(type) {
	case nil:
		return errors.New("canonical rejects null")
	case bool:
		if typed {
			output.WriteString("true")
		} else {
			output.WriteString("false")
		}
		return nil
	case int:
		output.WriteString(strconv.Itoa(typed))
		return nil
	case int64:
		output.WriteString(strconv.FormatInt(typed, 10))
		return nil
	case string:
		if !printableASCII(typed) {
			return errors.New("canonical strings must be printable ASCII")
		}
		output.WriteString(quoteASCII(typed))
		return nil
	case []any:
		output.WriteByte('[')
		for i, item := range typed {
			if i > 0 {
				output.WriteByte(',')
			}
			if err := writeCanonical(output, item); err != nil {
				return err
			}
		}
		output.WriteByte(']')
		return nil
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if !printableASCII(key) {
				return errors.New("canonical keys must be printable ASCII")
			}
			keys = append(keys, key)
		}
		sortStrings(keys)
		output.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				output.WriteByte(',')
			}
			output.WriteString(quoteASCII(key))
			output.WriteByte(':')
			if err := writeCanonical(output, typed[key]); err != nil {
				return err
			}
		}
		output.WriteByte('}')
		return nil
	default:
		return fmt.Errorf("canonical rejects %T", value)
	}
}

// encodePayload mirrors the accepted Dart CapsuleCodec._encodePayload: sorted
// top-level keys, sorted artifact keys, JSON string escaping with LF permitted in
// artifact values, no whitespace.
func encodePayload(context Context, artifacts map[string]string) []byte {
	artifactKeys := make([]string, 0, len(artifacts))
	for key := range artifacts {
		artifactKeys = append(artifactKeys, key)
	}
	sortStrings(artifactKeys)
	var artifactsJSON strings.Builder
	artifactsJSON.WriteByte('{')
	for i, key := range artifactKeys {
		if i > 0 {
			artifactsJSON.WriteByte(',')
		}
		artifactsJSON.WriteString(quoteASCII(key))
		artifactsJSON.WriteByte(':')
		artifactsJSON.WriteString(quoteASCII(artifacts[key]))
	}
	artifactsJSON.WriteByte('}')
	values := map[string]string{
		"artifacts":        artifactsJSON.String(),
		"actor":            quoteASCII(context.Actor),
		"deployment":       quoteASCII(context.Deployment),
		"operation":        quoteASCII(context.Operation),
		"profileSetDigest": quoteASCII(context.ProfileSetDigest),
		"purpose":          quoteASCII(context.Purpose),
		"requestDigest":    quoteASCII(context.RequestDigest),
		"schema":           strconv.Itoa(context.Schema),
		"server":           quoteASCII(context.Server),
		"uid":              quoteASCII(context.UID),
		"version":          strconv.Itoa(context.Version),
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sortStrings(keys)
	var output strings.Builder
	output.WriteByte('{')
	for i, key := range keys {
		if i > 0 {
			output.WriteByte(',')
		}
		output.WriteString(quoteASCII(key))
		output.WriteByte(':')
		output.WriteString(values[key])
	}
	output.WriteByte('}')
	return []byte(output.String())
}

func decodePayload(plaintext []byte) (Context, map[string]string, error) {
	if !utf8.Valid(plaintext) {
		return Context{}, nil, reject(ReasonNotJSON)
	}
	text := string(plaintext)
	if dartBlank(text) {
		return Context{}, nil, reject(ReasonBlank)
	}
	if err := checkNoDuplicateKeys(plaintext); err != nil {
		return Context{}, nil, reject(ReasonNotJSON)
	}
	fields, err := strictObject(plaintext, []string{
		"schema", "purpose", "version", "operation", "uid", "server", "deployment",
		"actor", "requestDigest", "profileSetDigest", "artifacts",
	})
	if err != nil {
		switch {
		case errors.Is(err, errMissingField):
			return Context{}, nil, reject(ReasonMissingField)
		case errors.Is(err, errUnexpectedField):
			return Context{}, nil, reject(ReasonUnexpected)
		default:
			return Context{}, nil, reject(ReasonNotObject)
		}
	}
	context := Context{}
	if context.Schema, err = intValue(fields["schema"]); err != nil {
		return Context{}, nil, reject(ReasonEnvelopeShape)
	}
	if context.Version, err = intValue(fields["version"]); err != nil {
		return Context{}, nil, reject(ReasonEnvelopeShape)
	}
	for key, target := range map[string]*string{
		"purpose": &context.Purpose, "operation": &context.Operation, "uid": &context.UID,
		"server": &context.Server, "deployment": &context.Deployment, "actor": &context.Actor,
		"requestDigest": &context.RequestDigest, "profileSetDigest": &context.ProfileSetDigest,
	} {
		value, err := stringValue(fields[key])
		if err != nil {
			return Context{}, nil, reject(ReasonEnvelopeShape)
		}
		*target = value
	}
	artifacts, err := decodeArtifacts(fields["artifacts"])
	if err != nil {
		return Context{}, nil, err
	}
	if err := ValidateContext(context); err != nil {
		return Context{}, nil, reject(ReasonEnvelopeShape)
	}
	return context, artifacts, nil
}

func decodeArtifacts(raw json.RawMessage) (map[string]string, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, reject(ReasonEnvelopeShape)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, reject(ReasonEnvelopeShape)
	}
	if len(fields) > MaxArtifacts {
		return nil, reject(ReasonArtifactSize)
	}
	artifacts := make(map[string]string, len(fields))
	for key, valueRaw := range fields {
		if !isArtifactKind(key) {
			return nil, reject(ReasonArtifactKind)
		}
		value, err := stringValue(valueRaw)
		if err != nil {
			return nil, reject(ReasonEnvelopeShape)
		}
		if len(value) == 0 || len(value) > MaxArtifactBytes || !printableArtifact(value) {
			return nil, reject(ReasonArtifactSize)
		}
		artifacts[key] = value
	}
	return artifacts, nil
}

func validateArtifacts(artifacts map[string]string) (map[string]string, error) {
	if len(artifacts) > MaxArtifacts {
		return nil, reject(ReasonArtifactSize)
	}
	copy := make(map[string]string, len(artifacts))
	for key, value := range artifacts {
		if !isArtifactKind(key) {
			return nil, reject(ReasonArtifactKind)
		}
		if len(value) == 0 || len(value) > MaxArtifactBytes || !printableArtifact(value) {
			return nil, reject(ReasonArtifactSize)
		}
		copy[key] = value
	}
	return copy, nil
}

func isArtifactKind(value string) bool {
	for _, kind := range ArtifactKinds {
		if kind == value {
			return true
		}
	}
	return false
}

func validOperation(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		switch {
		case character >= 'A' && character <= 'Z':
		case character >= 'a' && character <= 'z':
		case character >= '0' && character <= '9':
		case character == '.' || character == '_' || character == ':' || character == '-':
		default:
			return false
		}
	}
	return true
}

func validUID(value string) bool {
	return (len(value) == 32 || len(value) == 64) && isLowerHex(value, len(value))
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for i := 0; i < len(value); i++ {
		character := value[i]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func printableASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func printableArtifact(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] != '\n' && (value[i] < 0x20 || value[i] > 0x7e) {
			return false
		}
	}
	return true
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var difference byte
	for i := range a {
		difference |= a[i] ^ b[i]
	}
	return difference == 0
}

// dartBlank mirrors Dart String.trim()'s whitespace matrix for the blank
// plaintext guard.
func dartBlank(value string) bool {
	for _, character := range value {
		switch character {
		case 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020, 0x0085, 0x00a0,
			0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		default:
			if character < 0x2000 || character > 0x200a {
				return false
			}
		}
	}
	return true
}

// quoteASCII mirrors Dart jsonEncode for the ASCII subset (control characters,
// quote and backslash; LF stays "\n"; no HTML escaping, so <>&/ remain literal).
func quoteASCII(value string) string {
	var output strings.Builder
	output.WriteByte('"')
	for i := 0; i < len(value); i++ {
		character := value[i]
		switch character {
		case '"':
			output.WriteString(`\"`)
		case '\\':
			output.WriteString(`\\`)
		case 0x08:
			output.WriteString(`\b`)
		case 0x09:
			output.WriteString(`\t`)
		case 0x0a:
			output.WriteString(`\n`)
		case 0x0c:
			output.WriteString(`\f`)
		case 0x0d:
			output.WriteString(`\r`)
		default:
			if character < 0x20 {
				output.WriteString(`\u00`)
				output.WriteByte(hexDigits[character>>4])
				output.WriteByte(hexDigits[character&0xf])
			} else {
				output.WriteByte(character)
			}
		}
	}
	output.WriteByte('"')
	return output.String()
}

const hexDigits = "0123456789abcdef"

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}

func decodeCanonicalBase64(value string, length int) ([]byte, error) {
	decoded, err := decodeCanonicalBase64Any(value, length)
	if err != nil {
		return nil, err
	}
	if len(decoded) != length {
		return nil, errors.New("unexpected base64 length")
	}
	return decoded, nil
}

func decodeCanonicalBase64Any(value string, maxLength int) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("non-canonical base64 spelling")
	}
	if len(decoded) > maxLength {
		return nil, errors.New("base64 payload too large")
	}
	return decoded, nil
}

var (
	errMissingField    = errors.New("missing field")
	errUnexpectedField = errors.New("unexpected field")
)

func strictObject(raw []byte, fields []string) (map[string]json.RawMessage, error) {
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil || decoded == nil {
		return nil, errors.New("not object")
	}
	allowed := make(map[string]bool, len(fields))
	for _, field := range fields {
		allowed[field] = true
	}
	for key := range decoded {
		if !allowed[key] {
			return nil, errUnexpectedField
		}
	}
	for _, field := range fields {
		if _, present := decoded[field]; !present {
			return nil, errMissingField
		}
	}
	return decoded, nil
}

func stringValue(raw json.RawMessage) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	return value, nil
}

func intValue(raw json.RawMessage) (int, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return 0, errors.New("empty number")
	}
	for _, character := range trimmed {
		if (character < '0' || character > '9') && character != '-' {
			return 0, errors.New("not integer")
		}
	}
	parsed, err := strconv.Atoi(string(trimmed))
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

// checkNoDuplicateKeys parses exactly one JSON value with a bounded recursive
// descent and rejects duplicate object keys at every depth, including keys that
// follow a nested container. A global "expect key/value" toggle is not used:
// after a child object/array closes, control returns to the parent loop, which
// still expects its next key.
func checkNoDuplicateKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("json too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			if keys[key] {
				return errors.New("duplicate key")
			}
			keys[key] = true
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("unbalanced object")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("unbalanced array")
		}
		return nil
	default:
		return errors.New("unexpected delimiter")
	}
}

// validateEnvelopeFields is the invariant shared by ParseEnvelope and the public
// Open entry point.
func validateEnvelopeFields(envelope Envelope) error {
	if envelope.V != Version || envelope.Alg != Alg ||
		!isLowerHex(envelope.CapsuleID, 32) || len(envelope.RecipientPublicKey) != 32 {
		return reject(ReasonEnvelopeShape)
	}
	if len(envelope.Ciphertext) > MaxCiphertext || len(envelope.JSON()) > MaxEnvelopeBytes {
		return reject(ReasonTooLarge)
	}
	return nil
}

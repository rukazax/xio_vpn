package desktop

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// WIRE-V2 policy identity for the desktop helper. The plan is immutable and is
// the only admission authority once versioned ownership begins; the Dart
// product document stays the durable source of truth and the helper never keeps
// its own durable plan journal.
const (
	policyVersion     = 1
	policyPlanSchema  = 2
	policyRoundMillis = 30000
	policyMaxProfiles = 16
)

// Error values are the exact wire codes printed by the existing RPC envelope.
// Errors never imply that physical ownership was released or rolled back.
var (
	ErrPolicyInvalid     = errors.New("POLICY_INVALID")
	ErrPolicyUnsupported = errors.New("POLICY_UNSUPPORTED")
	ErrPolicyBusy        = errors.New("POLICY_BUSY")
	ErrPolicyStale       = errors.New("POLICY_STALE")
	ErrPolicyUnknown     = errors.New("POLICY_UNKNOWN")
	ErrPolicyUnverified  = errors.New("POLICY_UNVERIFIED")
)

var (
	policyNoncePattern  = regexp.MustCompile(`^[a-f0-9]{32}$`)
	policyDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	policyIDPattern     = regexp.MustCompile(`^[a-z0-9]{1,80}$`)
)

// policyError keeps the exact wire code as the prefix and adds the static
// context even when the message has no formatting verbs. Returning a bare
// sentinel would make independent diagnosis impossible.
func policyError(code error, format string, args ...any) error {
	if format == "" {
		return code
	}
	return fmt.Errorf("%w: %s", code, fmt.Sprintf(format, args...))
}

func policyInvalid(format string, args ...any) error {
	return policyError(ErrPolicyInvalid, format, args...)
}
func policyUnsupported(format string, args ...any) error {
	return policyError(ErrPolicyUnsupported, format, args...)
}
func policyBusy(format string, args ...any) error { return policyError(ErrPolicyBusy, format, args...) }
func policyStale(format string, args ...any) error {
	return policyError(ErrPolicyStale, format, args...)
}
func policyUnknown(format string, args ...any) error {
	return policyError(ErrPolicyUnknown, format, args...)
}
func policyUnverified(format string, args ...any) error {
	return policyError(ErrPolicyUnverified, format, args...)
}

// policyConfigDigest hashes the exact saved/base config bytes as UTF-8, with no
// trimming or reserialization. WIRE-V2 §1.1 fixes the four golden values.
func policyConfigDigest(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// PolicyRequest is the exact lowerCamelCase wire request shared by
// policyBegin/commit/reconcile/abort. The RPC entrypoint embeds this struct so
// the existing capitalized transport members keep working unchanged.
type PolicyRequest struct {
	Version            int
	StoreIdentity      string
	ControllerNonce    string
	InstanceNonce      string
	TransactionID      string
	PlanGeneration     string
	ExpectedGeneration *string
	Plan               json.RawMessage
}

// PolicyAbortRequest is the exact three-key revocation request agreed with the
// cross-platform wire: version, instanceNonce, transactionId. It carries no plan,
// store or controller identity, so revocation can never re-derive admission.
type PolicyAbortRequest struct {
	Version       int
	InstanceNonce string
	TransactionID string
}

// policyReceipt is the six-field activation attachment (WIRE-V2 §2). Desktop
// carries it as PolicyReceiptJSON, a UTF-8 JSON string in the existing request.
type policyReceipt struct {
	Version         int
	StoreIdentity   string
	InstanceNonce   string
	ControllerNonce string
	TransactionID   string
	PlanGeneration  string
}

type policyProfile struct {
	ID       string
	Protocol string
	Endpoint string
	Digest   [32]byte
}

type policyPlan struct {
	Schema           int
	SelectedID       *string
	IDs              []string
	Profiles         []policyProfile
	PriorityProtocol *string
	Mode             string
	PolicyRound      int64
	Site             string
	SiteCheck        bool
	TimeoutSeconds   int
	RoundMillis      int64
	ClientOnly       bool
	ConsentRevision  string
	VPNDisclosure    *string
	raw              []byte
	fingerprint      [32]byte
}

type policyTx struct {
	store       string
	controller  string
	instance    string
	transaction string
	generation  string
	expected    string
	plan        *policyPlan
	fingerprint [32]byte
}

func (t *policyTx) computeFingerprint() [32]byte {
	h := sha256.New()
	var length [8]byte
	write := func(value string) {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		h.Write(length[:])
		h.Write([]byte(value))
	}
	write(t.store)
	write(t.controller)
	write(t.generation)
	write(t.expected)
	write(hex.EncodeToString(t.plan.fingerprint[:]))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func isJSONNull(raw []byte) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// decodeStrictObject accepts exactly one JSON object with no duplicate and no
// unknown keys, and returns each member's raw bytes. The plan is authenticated
// local traffic from our own bridge, but strictness here is cheap and prevents a
// future caller from smuggling routing/priority fields past admission.
func decodeStrictObject(raw []byte, required, optional []string, what string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	open, err := dec.Token()
	if err != nil {
		return nil, policyInvalid("malformed %s", what)
	}
	if delim, ok := open.(json.Delim); !ok || delim != '{' {
		return nil, policyInvalid("malformed %s", what)
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = true
	}
	for _, key := range optional {
		allowed[key] = true
	}
	fields := make(map[string]json.RawMessage, len(required)+len(optional))
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, policyInvalid("malformed %s", what)
		}
		key, ok := token.(string)
		if !ok {
			return nil, policyInvalid("malformed %s key", what)
		}
		if !allowed[key] {
			return nil, policyInvalid("unknown %s key %q", what, key)
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, policyInvalid("duplicate %s key %q", what, key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, policyInvalid("malformed %s value", what)
		}
		fields[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, policyInvalid("malformed %s", what)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, policyInvalid("trailing %s data", what)
	}
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return nil, policyInvalid("missing %s key %q", what, key)
		}
	}
	return fields, nil
}

// CheckExactObjectKeys enforces an exact top-level key set (no unknown, no
// duplicate, no missing keys) for the authenticated policy envelopes. The RPC
// entrypoint uses it so policyBegin/commit/reconcile are exactly eight keys and
// policyAbort exactly three, plus the transport method name.
func CheckExactObjectKeys(raw []byte, keys []string, what string) error {
	_, err := decodeStrictObject(raw, keys, nil, what)
	return err
}

// policyStringValue requires a real JSON string; Go's json.Unmarshal silently
// accepts null for a string, which would turn a present null into "".
func policyStringValue(raw json.RawMessage, what string) (string, error) {
	if isJSONNull(raw) {
		return "", policyInvalid("invalid %s", what)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", policyInvalid("invalid %s", what)
	}
	return value, nil
}

func policyNullableString(raw json.RawMessage, what string) (*string, error) {
	if isJSONNull(raw) {
		return nil, nil
	}
	value, err := policyStringValue(raw, what)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func policyBoolValue(raw json.RawMessage, what string) (bool, error) {
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, policyInvalid("invalid %s", what)
	}
	return value, nil
}

func policyIntValue(raw json.RawMessage, what string) (int64, error) {
	var value int64
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, policyInvalid("invalid %s", what)
	}
	return value, nil
}

func policyStringArray(raw json.RawMessage, what string) ([]string, error) {
	if isJSONNull(raw) {
		return nil, policyInvalid("invalid %s", what)
	}
	var values []string
	if err := json.Unmarshal(raw, &values); err != nil || values == nil {
		return nil, policyInvalid("invalid %s", what)
	}
	return values, nil
}

func validPolicyEndpoint(endpoint string) bool {
	if endpoint == "" || len(endpoint) > 512 {
		return false
	}
	for _, r := range endpoint {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func parsePolicySite(raw json.RawMessage) (string, error) {
	site, err := policyStringValue(raw, "site")
	if err != nil {
		return "", err
	}
	parsed, err := url.Parse(site)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return "", policyInvalid("invalid verification site")
	}
	return site, nil
}

// parsePolicyPlan implements WIRE-V2 §1 exactly: schema 2, no unknown keys, and
// a routing value that must be JSON null on desktop. A non-null routing object is
// rejected as POLICY_INVALID and never ignored.
func parsePolicyPlan(raw []byte) (*policyPlan, error) {
	fields, err := decodeStrictObject(raw, []string{
		"schema", "selectedId", "ids", "profiles", "routing", "priorityProtocol",
		"policy", "site", "siteCheckEnabled", "timeoutSeconds", "roundMillis",
		"clientOnly", "consentRevision", "vpnDisclosure",
	}, nil, "plan")
	if err != nil {
		return nil, err
	}
	plan := &policyPlan{}
	schema, err := policyIntValue(fields["schema"], "schema")
	if err != nil || schema != policyPlanSchema {
		return nil, policyInvalid("unsupported plan schema")
	}
	plan.Schema = int(schema)
	if plan.SelectedID, err = policyNullableString(fields["selectedId"], "selected identity"); err != nil {
		return nil, err
	}
	if plan.SelectedID != nil && !policyIDPattern.MatchString(*plan.SelectedID) {
		return nil, policyInvalid("invalid selected identity")
	}
	if plan.IDs, err = policyStringArray(fields["ids"], "candidate ids"); err != nil {
		return nil, err
	}
	if len(plan.IDs) > policyMaxProfiles {
		return nil, policyInvalid("too many plan candidates")
	}
	if plan.Profiles, err = parsePolicyProfiles(fields["profiles"]); err != nil {
		return nil, err
	}
	if !isJSONNull(fields["routing"]) {
		return nil, policyInvalid("desktop plan routing must be null")
	}
	if plan.PriorityProtocol, err = policyNullableString(fields["priorityProtocol"], "priority protocol"); err != nil {
		return nil, err
	}
	policyFields, err := decodeStrictObject(fields["policy"], []string{"mode", "roundMillis"}, nil, "policy")
	if err != nil {
		return nil, err
	}
	if plan.Mode, err = policyStringValue(policyFields["mode"], "policy mode"); err != nil {
		return nil, err
	}
	if plan.Mode != "automatic" && plan.Mode != "selectedOnly" {
		return nil, policyInvalid("unsupported policy mode")
	}
	if plan.PolicyRound, err = policyIntValue(policyFields["roundMillis"], "policy round"); err != nil {
		return nil, err
	}
	if plan.PolicyRound != policyRoundMillis {
		return nil, policyInvalid("unsupported policy round")
	}
	if plan.Site, err = parsePolicySite(fields["site"]); err != nil {
		return nil, err
	}
	if plan.SiteCheck, err = policyBoolValue(fields["siteCheckEnabled"], "verification flag"); err != nil {
		return nil, err
	}
	timeout, err := policyIntValue(fields["timeoutSeconds"], "candidate timeout")
	if err != nil {
		return nil, err
	}
	if timeout < 5 || timeout > 60 {
		return nil, policyInvalid("candidate timeout out of range")
	}
	plan.TimeoutSeconds = int(timeout)
	if plan.RoundMillis, err = policyIntValue(fields["roundMillis"], "round budget"); err != nil {
		return nil, err
	}
	if plan.RoundMillis != policyRoundMillis {
		return nil, policyInvalid("unsupported round budget")
	}
	if plan.ClientOnly, err = policyBoolValue(fields["clientOnly"], "client-only flag"); err != nil {
		return nil, err
	}
	if plan.ConsentRevision, err = policyStringValue(fields["consentRevision"], "consent revision"); err != nil {
		return nil, err
	}
	if plan.VPNDisclosure, err = policyNullableString(fields["vpnDisclosure"], "VPN disclosure"); err != nil {
		return nil, err
	}
	if plan.IDs == nil {
		plan.IDs = []string{}
	}
	if err := validatePolicyPlan(plan); err != nil {
		return nil, err
	}
	plan.raw = append([]byte(nil), raw...)
	plan.fingerprint = plan.computeFingerprint()
	return plan, nil
}

func parsePolicyProfiles(raw json.RawMessage) ([]policyProfile, error) {
	if isJSONNull(raw) {
		return nil, policyInvalid("invalid profile metadata")
	}
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil || entries == nil {
		return nil, policyInvalid("invalid profile metadata")
	}
	if len(entries) > policyMaxProfiles {
		return nil, policyInvalid("too many plan candidates")
	}
	profiles := make([]policyProfile, len(entries))
	for i, entry := range entries {
		fields, err := decodeStrictObject(entry,
			[]string{"id", "protocol", "endpoint", "configDigest"}, nil, "profile")
		if err != nil {
			return nil, err
		}
		profile := &profiles[i]
		if profile.ID, err = policyStringValue(fields["id"], "profile id"); err != nil {
			return nil, err
		}
		if !policyIDPattern.MatchString(profile.ID) {
			return nil, policyInvalid("invalid profile id")
		}
		if profile.Protocol, err = policyStringValue(fields["protocol"], "profile protocol"); err != nil {
			return nil, err
		}
		if !knownDesktopProtocol(profile.Protocol) {
			return nil, policyInvalid("unsupported profile protocol")
		}
		if profile.Endpoint, err = policyStringValue(fields["endpoint"], "profile endpoint"); err != nil {
			return nil, err
		}
		if !validPolicyEndpoint(profile.Endpoint) {
			return nil, policyInvalid("invalid profile endpoint")
		}
		digest, err := policyStringValue(fields["configDigest"], "config digest")
		if err != nil {
			return nil, err
		}
		if !policyDigestPattern.MatchString(digest) {
			return nil, policyInvalid("invalid config digest")
		}
		decoded, err := hex.DecodeString(digest)
		if err != nil || len(decoded) != sha256.Size {
			return nil, policyInvalid("invalid config digest")
		}
		copy(profile.Digest[:], decoded)
	}
	return profiles, nil
}

func knownDesktopProtocol(protocol string) bool {
	for _, supported := range Protocols {
		if supported == protocol {
			return true
		}
	}
	return false
}

func validatePolicyPlan(p *policyPlan) error {
	if len(p.IDs) != len(p.Profiles) {
		return policyInvalid("profile metadata does not match candidates")
	}
	seen := make(map[string]bool, len(p.IDs))
	for i, id := range p.IDs {
		if p.Profiles[i].ID != id {
			return policyInvalid("profile metadata order mismatch")
		}
		if seen[id] {
			return policyInvalid("duplicate candidate")
		}
		seen[id] = true
	}
	if p.Mode == "selectedOnly" {
		// A manual plan is never truncated: it has at most that one candidate and
		// a non-empty manual plan is exactly the selected identity.
		if len(p.IDs) > 1 {
			return policyInvalid("manual plan has multiple candidates")
		}
		if len(p.IDs) == 1 && (p.SelectedID == nil || *p.SelectedID != p.IDs[0]) {
			return policyInvalid("manual plan candidate is not the selection")
		}
		return nil
	}
	// AUTOMATIC keeps the selected identity first. An unusable selection may
	// still be recorded with an empty candidate list.
	if p.SelectedID != nil && len(p.IDs) > 0 && p.IDs[0] != *p.SelectedID {
		return policyInvalid("automatic plan does not keep the selection first")
	}
	return nil
}

// computeFingerprint is the replay identity of the immutable plan. Key order and
// whitespace in the incoming JSON cannot influence it.
func (p *policyPlan) computeFingerprint() [32]byte {
	type canonicalProfile struct {
		ID           string `json:"id"`
		Protocol     string `json:"protocol"`
		Endpoint     string `json:"endpoint"`
		ConfigDigest string `json:"configDigest"`
	}
	type canonicalPolicy struct {
		Mode        string `json:"mode"`
		RoundMillis int64  `json:"roundMillis"`
	}
	type canonicalPlan struct {
		Schema           int                `json:"schema"`
		SelectedID       *string            `json:"selectedId"`
		IDs              []string           `json:"ids"`
		Profiles         []canonicalProfile `json:"profiles"`
		Routing          string             `json:"routing"`
		PriorityProtocol *string            `json:"priorityProtocol"`
		Policy           canonicalPolicy    `json:"policy"`
		Site             string             `json:"site"`
		SiteCheck        bool               `json:"siteCheckEnabled"`
		TimeoutSeconds   int                `json:"timeoutSeconds"`
		RoundMillis      int64              `json:"roundMillis"`
		ClientOnly       bool               `json:"clientOnly"`
		ConsentRevision  string             `json:"consentRevision"`
		VPNDisclosure    *string            `json:"vpnDisclosure"`
	}
	ids := p.IDs
	if ids == nil {
		ids = []string{}
	}
	profiles := make([]canonicalProfile, len(p.Profiles))
	for i, profile := range p.Profiles {
		profiles[i] = canonicalProfile{profile.ID, profile.Protocol, profile.Endpoint, hex.EncodeToString(profile.Digest[:])}
	}
	encoded, err := json.Marshal(canonicalPlan{
		Schema:           p.Schema,
		SelectedID:       p.SelectedID,
		IDs:              ids,
		Profiles:         profiles,
		Routing:          "null",
		PriorityProtocol: p.PriorityProtocol,
		Policy:           canonicalPolicy{Mode: p.Mode, RoundMillis: p.PolicyRound},
		Site:             p.Site,
		SiteCheck:        p.SiteCheck,
		TimeoutSeconds:   p.TimeoutSeconds,
		RoundMillis:      p.RoundMillis,
		ClientOnly:       p.ClientOnly,
		ConsentRevision:  p.ConsentRevision,
		VPNDisclosure:    p.VPNDisclosure,
	})
	if err != nil {
		panic("desktop: policy plan canonicalization failed: " + err.Error())
	}
	return sha256.Sum256(encoded)
}

// admissionProfile re-derives the stored candidate identity for an activation.
// Manual admission requires the one committed candidate; automatic admission
// requires membership in the frozen candidate order.
func (p *policyPlan) admissionProfile(id, protocol string) (policyProfile, error) {
	if !policyIDPattern.MatchString(id) || id != strings.TrimSpace(id) {
		return policyProfile{}, policyInvalid("invalid profile identifier")
	}
	index := -1
	for i, candidate := range p.IDs {
		if candidate == id {
			index = i
			break
		}
	}
	if p.Mode == "selectedOnly" {
		if p.SelectedID == nil || *p.SelectedID != id || len(p.IDs) != 1 {
			return policyProfile{}, policyStale("candidate is not the committed manual selection")
		}
		index = 0
	} else if index < 0 {
		return policyProfile{}, policyStale("candidate is not in the committed plan")
	}
	if index < 0 || index >= len(p.Profiles) {
		return policyProfile{}, policyStale("candidate metadata missing")
	}
	profile := p.Profiles[index]
	if profile.ID != id {
		return policyProfile{}, policyStale("candidate metadata mismatch")
	}
	if profile.Protocol != protocol {
		return policyProfile{}, policyStale("candidate protocol does not match the committed plan")
	}
	return profile, nil
}

func parsePolicyTransaction(request PolicyRequest) (*policyTx, error) {
	if request.Version != policyVersion {
		return nil, policyInvalid("unsupported policy version")
	}
	if !storeIdentityPattern.MatchString(request.StoreIdentity) {
		return nil, policyInvalid("invalid store identity")
	}
	if !policyNoncePattern.MatchString(request.ControllerNonce) {
		return nil, policyInvalid("invalid controller nonce")
	}
	if !policyNoncePattern.MatchString(request.InstanceNonce) {
		return nil, policyInvalid("invalid instance nonce")
	}
	if !policyNoncePattern.MatchString(request.TransactionID) {
		return nil, policyInvalid("invalid transaction id")
	}
	if !policyNoncePattern.MatchString(request.PlanGeneration) {
		return nil, policyInvalid("invalid plan generation")
	}
	expected := ""
	if request.ExpectedGeneration != nil {
		if !policyNoncePattern.MatchString(*request.ExpectedGeneration) {
			return nil, policyInvalid("invalid expected generation")
		}
		expected = *request.ExpectedGeneration
	}
	if len(request.Plan) == 0 {
		return nil, policyInvalid("missing plan")
	}
	plan, err := parsePolicyPlan(request.Plan)
	if err != nil {
		return nil, err
	}
	tx := &policyTx{
		store:       request.StoreIdentity,
		controller:  request.ControllerNonce,
		instance:    request.InstanceNonce,
		transaction: request.TransactionID,
		generation:  request.PlanGeneration,
		expected:    expected,
		plan:        plan,
	}
	tx.fingerprint = tx.computeFingerprint()
	return tx, nil
}

func parsePolicyReceipt(raw string) (*policyReceipt, error) {
	if raw == "" {
		return nil, nil
	}
	fields, err := decodeStrictObject([]byte(raw), []string{
		"version", "storeIdentity", "instanceNonce", "controllerNonce",
		"transactionId", "planGeneration",
	}, nil, "policy receipt")
	if err != nil {
		return nil, err
	}
	receipt := &policyReceipt{}
	version, err := policyIntValue(fields["version"], "receipt version")
	if err != nil || version != policyVersion {
		return nil, policyInvalid("unsupported receipt version")
	}
	receipt.Version = int(version)
	stringFields := []struct {
		key    string
		target *string
		what   string
	}{
		{"storeIdentity", &receipt.StoreIdentity, "receipt store identity"},
		{"instanceNonce", &receipt.InstanceNonce, "receipt instance nonce"},
		{"controllerNonce", &receipt.ControllerNonce, "receipt controller nonce"},
		{"transactionId", &receipt.TransactionID, "receipt transaction"},
		{"planGeneration", &receipt.PlanGeneration, "receipt plan generation"},
	}
	for _, field := range stringFields {
		if *field.target, err = policyStringValue(fields[field.key], field.what); err != nil {
			return nil, err
		}
	}
	if !storeIdentityPattern.MatchString(receipt.StoreIdentity) {
		return nil, policyInvalid("invalid receipt store identity")
	}
	for _, value := range []string{receipt.InstanceNonce, receipt.ControllerNonce, receipt.TransactionID, receipt.PlanGeneration} {
		if !policyNoncePattern.MatchString(value) {
			return nil, policyInvalid("invalid receipt identity")
		}
	}
	return receipt, nil
}

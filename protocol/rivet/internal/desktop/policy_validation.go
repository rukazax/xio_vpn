package desktop

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"unicode/utf8"
)

// Bounded transient validation of an offered plan against the durable document
// snapshot the controller supplies. This is consistency checking, NOT an
// independent disk read: the controller vouches for vault/filesystem provenance.
// The document bytes are hashed exactly as supplied; nothing is normalised.
const (
	policyValidationSchema = 1

	policyValidationBodyLimit     = 3 << 20
	policyValidationDocumentLimit = 512 << 10
	policyValidationConfigsLimit  = 1 << 20
	policyValidationCombinedLimit = 1536 << 10
	policyValidationSingleLimit   = 200000
	policyValidationMaxConfigs    = policyMaxProfiles
)

// PolicyValidation is the exact `validation` object of the nine-key
// policyValidate envelope.
type PolicyValidation struct {
	Schema              int
	DocumentDigest      string
	DocumentBytesBase64 string
	Configs             []PolicyValidationConfig
}

type PolicyValidationConfig struct {
	ID          string
	BytesBase64 string
}

type validationConfig struct {
	id     string
	digest [32]byte
}

type policyValidationInput struct {
	documentDigest [32]byte
	document       []byte
	configs        []validationConfig
}

type policyValidationRecord struct {
	instance        string
	store           string
	controller      string
	transaction     string
	expected        string
	generation      string
	planFingerprint [32]byte
	documentDigest  [32]byte
	configDigests   map[string][32]byte
	epoch           uint64
	deadline        int64 // UnixNano; compared with Runtime.clock
}

func validBase64Text(encoded string, maxDecoded int) bool {
	if encoded == "" {
		return false
	}
	// Reject an oversized encoding before decoding, so a malicious length cannot
	// cause a large allocation.
	if len(encoded) > (maxDecoded+2)/3*4+4 {
		return false
	}
	for i := 0; i < len(encoded); i++ {
		c := encoded[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/', c == '=':
		default:
			return false
		}
	}
	return true
}

func decodeValidationBase64(encoded string, maxDecoded int) ([]byte, error) {
	if !validBase64Text(encoded, maxDecoded) {
		return nil, policyInvalid("invalid validation base64")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, policyInvalid("invalid validation base64")
	}
	if len(decoded) > maxDecoded {
		return nil, policyInvalid("validation payload too large")
	}
	return decoded, nil
}

// parsePolicyValidation validates the envelope, enforces the bounded payload
// limits and proves the offered plan against the supplied document snapshot.
// clientOnly comes from the launch binding, never from the document.
func parsePolicyValidation(raw json.RawMessage, plan *policyPlan, tx *policyTx, clientOnly bool) (*policyValidationInput, error) {
	fields, err := decodeStrictObject(raw,
		[]string{"schema", "documentDigest", "documentBytesBase64", "configs"}, nil, "validation")
	if err != nil {
		return nil, err
	}
	schema, err := policyIntValue(fields["schema"], "validation schema")
	if err != nil || schema != policyValidationSchema {
		return nil, policyInvalid("unsupported validation schema")
	}
	digestText, err := policyStringValue(fields["documentDigest"], "document digest")
	if err != nil {
		return nil, err
	}
	if !policyDigestPattern.MatchString(digestText) {
		return nil, policyInvalid("invalid document digest")
	}
	documentBase64, err := policyStringValue(fields["documentBytesBase64"], "document bytes")
	if err != nil {
		return nil, err
	}
	document, err := decodeValidationBase64(documentBase64, policyValidationDocumentLimit)
	if err != nil {
		return nil, err
	}
	var entries []json.RawMessage
	if isJSONNull(fields["configs"]) {
		return nil, policyInvalid("invalid validation configs")
	}
	if err := json.Unmarshal(fields["configs"], &entries); err != nil || entries == nil {
		return nil, policyInvalid("invalid validation configs")
	}
	if len(entries) != len(plan.IDs) || len(entries) > policyValidationMaxConfigs {
		return nil, policyInvalid("validation configs do not match the plan")
	}
	input := &policyValidationInput{
		document: document,
		configs:  make([]validationConfig, len(entries)),
	}
	copy(input.documentDigest[:], decodePolicyDigest(digestText))
	if sha256.Sum256(document) != input.documentDigest {
		return nil, policyInvalid("document digest does not match the supplied bytes")
	}
	totalConfigs := 0
	for i, entry := range entries {
		configFields, err := decodeStrictObject(entry,
			[]string{"id", "bytesBase64"}, nil, "validation config")
		if err != nil {
			return nil, err
		}
		id, err := policyStringValue(configFields["id"], "validation config id")
		if err != nil {
			return nil, err
		}
		if id != plan.IDs[i] {
			return nil, policyInvalid("validation configs do not match the plan")
		}
		encoded, err := policyStringValue(configFields["bytesBase64"], "validation config bytes")
		if err != nil {
			return nil, err
		}
		configBytes, err := decodeValidationBase64(encoded, policyValidationSingleLimit)
		if err != nil {
			return nil, err
		}
		totalConfigs += len(configBytes)
		if totalConfigs > policyValidationConfigsLimit ||
			len(document)+totalConfigs > policyValidationCombinedLimit {
			return nil, policyInvalid("validation payload too large")
		}
		if len(configBytes) == 0 || !utf8.Valid(configBytes) || dartBlank(string(configBytes)) {
			return nil, policyInvalid("invalid saved configuration")
		}
		digest := sha256.Sum256(configBytes)
		if digest != plan.Profiles[i].Digest {
			return nil, policyStale("saved configuration digest mismatch")
		}
		// Pure protocol-shape validation; no admin/stop/setup/route/TUN effect.
		if _, err := ParseProfile(plan.Profiles[i].Protocol, string(configBytes)); err != nil {
			return nil, policyInvalid("saved configuration is not usable")
		}
		input.configs[i] = validationConfig{id: id, digest: digest}
	}
	if !utf8.Valid(document) {
		return nil, policyInvalid("document is not valid UTF-8")
	}
	if err := checkNoDuplicateJSONKeys(document); err != nil {
		return nil, err
	}
	projection, err := parseDocumentProjection(document)
	if err != nil {
		return nil, err
	}
	if err := validateDocumentProjection(plan, tx, projection, clientOnly); err != nil {
		return nil, err
	}
	return input, nil
}

func decodePolicyDigest(text string) []byte {
	decoded, _ := hex.DecodeString(text)
	return decoded
}

// dartBlank matches Dart String.trim()'s whitespace set, probed on 3.13.5:
// blank = U+0009..U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000..U+200A,
// U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF. It deliberately differs from
// Go's strings.TrimSpace, which misses U+FEFF (a BOM-only configuration would
// otherwise look usable). The stored bytes are never normalised: this predicate
// only classifies them.
func dartBlank(value string) bool {
	if value == "" {
		return true
	}
	for _, r := range value {
		if !dartWhitespace(r) {
			return false
		}
	}
	return true
}

func dartWhitespace(r rune) bool {
	switch r {
	case 0x0009, 0x000A, 0x000B, 0x000C, 0x000D, 0x0020, 0x0085, 0x00A0,
		0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// checkNoDuplicateJSONKeys rejects duplicate object keys anywhere in the
// document. encoding/json silently keeps the last value, which would let a
// snapshot disagree with a naive reader.
func checkNoDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	type frame struct {
		object    bool
		keys      map[string]bool
		expectKey bool
	}
	var stack []*frame
	pop := func() {
		stack = stack[:len(stack)-1]
		if n := len(stack); n > 0 && stack[n-1].object {
			stack[n-1].expectKey = true
		}
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return policyInvalid("malformed document")
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, &frame{object: true, keys: make(map[string]bool), expectKey: true})
			case '[':
				stack = append(stack, &frame{})
			case '}', ']':
				if len(stack) == 0 {
					return policyInvalid("malformed document")
				}
				pop()
			}
		case string:
			if n := len(stack); n > 0 && stack[n-1].object && stack[n-1].expectKey {
				current := stack[n-1]
				if current.keys[value] {
					return policyInvalid("duplicate document key %q", value)
				}
				current.keys[value] = true
				current.expectKey = false
			} else if n > 0 && stack[n-1].object {
				stack[n-1].expectKey = true
			}
		default:
			if n := len(stack); n > 0 && stack[n-1].object {
				stack[n-1].expectKey = true
			}
		}
	}
	if len(stack) != 0 {
		return policyInvalid("malformed document")
	}
	return nil
}

type documentProfile struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Endpoint string `json:"endpoint"`
}

type documentUser struct {
	ID         string            `json:"id"`
	ProfileIDs map[string]string `json:"profileIds"`
	Revoked    *bool             `json:"revoked"`
}

type documentPolicy struct {
	Mode        string `json:"mode"`
	RoundMillis int64  `json:"roundMillis"`
}

type documentReceipt struct {
	Schema         int             `json:"schema"`
	TransactionID  string          `json:"transactionId"`
	PlanGeneration string          `json:"planGeneration"`
	Plan           json.RawMessage `json:"plan"`
}

// documentProjection strictly types the authority fields the accepted plan
// builder reads. Unrelated valid top-level settings are deliberately ignored;
// the authority objects themselves (document schema, connectionPolicy,
// connectionPlanReceipt) are strict, required and exact-key.
type documentProjection struct {
	Schema            int               `json:"schema"`
	Profiles          []documentProfile `json:"profiles"`
	Selected          *string           `json:"selected"`
	Users             []documentUser    `json:"users"`
	LegalRecord       json.RawMessage   `json:"legalRecord"`
	ConnectionPolicy  *documentPolicy   `json:"connectionPolicy"`
	PriorityProtocol  *string           `json:"priorityProtocol"`
	SiteCheckEnabled  *bool             `json:"siteCheckEnabled"`
	CheckSite         *string           `json:"checkSite"`
	ProtocolTimeout   *int              `json:"protocolTimeoutSeconds"`
	VPNDisclosure     *string           `json:"vpnDisclosure"`
	ConnectionReceipt *documentReceipt  `json:"connectionPlanReceipt"`
}

func parseDocumentProjection(raw []byte) (*documentProjection, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return nil, policyInvalid("invalid document")
	}
	schemaRaw, ok := top["schema"]
	if !ok {
		return nil, policyInvalid("document schema is missing")
	}
	schema, err := policyIntValue(schemaRaw, "document schema")
	if err != nil || schema != 2 {
		return nil, policyInvalid("unsupported document schema")
	}
	projection := &documentProjection{Schema: int(schema)}
	profilesRaw, ok := top["profiles"]
	if !ok || isJSONNull(profilesRaw) {
		return nil, policyInvalid("document has no profile graph")
	}
	if err := json.Unmarshal(profilesRaw, &projection.Profiles); err != nil || projection.Profiles == nil {
		return nil, policyInvalid("invalid document profile graph")
	}
	if selectedRaw, ok := top["selected"]; ok {
		if projection.Selected, err = policyNullableString(selectedRaw, "document selected identity"); err != nil {
			return nil, err
		}
	}
	if usersRaw, ok := top["users"]; ok && !isJSONNull(usersRaw) {
		if err := json.Unmarshal(usersRaw, &projection.Users); err != nil {
			return nil, policyInvalid("invalid document user graph")
		}
	}
	legalRaw, ok := top["legalRecord"]
	if !ok {
		return nil, policyInvalid("document has no legal record")
	}
	projection.LegalRecord = legalRaw
	if value, ok := top["priorityProtocol"]; ok {
		if projection.PriorityProtocol, err = policyNullableString(value, "document priority protocol"); err != nil {
			return nil, err
		}
	}
	if value, ok := top["siteCheckEnabled"]; ok {
		parsed, err := policyBoolValue(value, "document verification flag")
		if err != nil {
			return nil, err
		}
		projection.SiteCheckEnabled = &parsed
	}
	if value, ok := top["checkSite"]; ok {
		parsed, err := policyStringValue(value, "document verification site")
		if err != nil {
			return nil, err
		}
		projection.CheckSite = &parsed
	}
	if value, ok := top["protocolTimeoutSeconds"]; ok {
		parsed, err := policyIntValue(value, "document candidate timeout")
		if err != nil {
			return nil, err
		}
		timeout := int(parsed)
		projection.ProtocolTimeout = &timeout
	}
	if value, ok := top["vpnDisclosure"]; ok {
		if projection.VPNDisclosure, err = policyNullableString(value, "document VPN disclosure"); err != nil {
			return nil, err
		}
	}
	policyRaw, ok := top["connectionPolicy"]
	if !ok || isJSONNull(policyRaw) {
		return nil, policyInvalid("document has no connection policy")
	}
	policyFields, err := decodeStrictObject(policyRaw, []string{"mode", "roundMillis"}, nil, "connection policy")
	if err != nil {
		return nil, err
	}
	mode, err := policyStringValue(policyFields["mode"], "connection policy mode")
	if err != nil {
		return nil, err
	}
	round, err := policyIntValue(policyFields["roundMillis"], "connection policy round")
	if err != nil {
		return nil, err
	}
	projection.ConnectionPolicy = &documentPolicy{Mode: mode, RoundMillis: round}
	receiptRaw, ok := top["connectionPlanReceipt"]
	if !ok || isJSONNull(receiptRaw) {
		return nil, policyInvalid("document has no connection plan receipt")
	}
	receiptFields, err := decodeStrictObject(receiptRaw,
		[]string{"schema", "transactionId", "planGeneration", "plan"}, nil, "connection plan receipt")
	if err != nil {
		return nil, err
	}
	receiptSchema, err := policyIntValue(receiptFields["schema"], "connection plan receipt schema")
	if err != nil || receiptSchema != 1 {
		return nil, policyInvalid("unsupported connection plan receipt schema")
	}
	transaction, err := policyStringValue(receiptFields["transactionId"], "receipt transaction")
	if err != nil {
		return nil, err
	}
	generation, err := policyStringValue(receiptFields["planGeneration"], "receipt generation")
	if err != nil {
		return nil, err
	}
	projection.ConnectionReceipt = &documentReceipt{
		Schema: int(receiptSchema), TransactionID: transaction,
		PlanGeneration: generation, Plan: receiptFields["plan"],
	}
	return projection, nil
}

func optionalStringEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func documentProfileByID(projection *documentProjection) (map[string]documentProfile, error) {
	profiles := make(map[string]documentProfile, len(projection.Profiles))
	for _, profile := range projection.Profiles {
		if !policyIDPattern.MatchString(profile.ID) {
			return nil, policyInvalid("invalid document profile id")
		}
		if _, duplicate := profiles[profile.ID]; duplicate {
			return nil, policyInvalid("duplicate document profile id")
		}
		profiles[profile.ID] = profile
	}
	return profiles, nil
}

func selectedDocumentOwner(projection *documentProjection) (*documentUser, error) {
	if projection.Selected == nil {
		return nil, nil
	}
	for i := range projection.Users {
		for _, id := range projection.Users[i].ProfileIDs {
			if id == *projection.Selected {
				// The accepted oracle uses firstOrNull.
				return &projection.Users[i], nil
			}
		}
	}
	return nil, nil
}

// validateDocumentProjection compares the plan with the actual document field
// names and semantics verified against the accepted source. It never rewrites the
// document bytes and never derives clientOnly from the document.
func validateDocumentProjection(plan *policyPlan, tx *policyTx, projection *documentProjection, clientOnly bool) error {
	profiles, err := documentProfileByID(projection)
	if err != nil {
		return err
	}
	for _, offered := range plan.Profiles {
		documentProfile, ok := profiles[offered.ID]
		if !ok {
			return policyStale("candidate is not in the document")
		}
		if documentProfile.Protocol != offered.Protocol || documentProfile.Endpoint != offered.Endpoint {
			return policyStale("candidate metadata drifted from the document")
		}
	}
	if !optionalStringEqual(plan.SelectedID, projection.Selected) {
		return policyStale("selected identity does not match the document")
	}
	if projection.ConnectionPolicy == nil {
		return policyInvalid("document has no connection policy")
	}
	if projection.ConnectionPolicy.Mode != plan.Mode ||
		projection.ConnectionPolicy.RoundMillis != policyRoundMillis {
		return policyStale("connection policy does not match the plan")
	}
	if !optionalStringEqual(plan.PriorityProtocol, projection.PriorityProtocol) {
		return policyStale("priority protocol does not match the document")
	}
	site := "https://youtube.com"
	if projection.CheckSite != nil {
		site = *projection.CheckSite
	}
	if site != plan.Site {
		return policyStale("verification site does not match the document")
	}
	siteCheck := false
	if projection.SiteCheckEnabled != nil {
		siteCheck = *projection.SiteCheckEnabled
	}
	if siteCheck != plan.SiteCheck {
		return policyStale("verification flag does not match the document")
	}
	timeout := 15
	if projection.ProtocolTimeout != nil {
		timeout = *projection.ProtocolTimeout
	}
	if timeout != plan.TimeoutSeconds {
		return policyStale("candidate timeout does not match the document")
	}
	if !optionalStringEqual(plan.VPNDisclosure, projection.VPNDisclosure) {
		return policyStale("VPN disclosure does not match the document")
	}
	record, err := parseLegalRecord(projection.LegalRecord)
	if err != nil {
		return err
	}
	if !record.current() {
		return policyStale("legal record is not current")
	}
	if plan.ConsentRevision != record.Revision {
		return policyStale("consent revision does not match the legal record")
	}
	if projection.ConnectionReceipt == nil {
		return policyInvalid("missing connection plan receipt")
	}
	receipt := projection.ConnectionReceipt
	if receipt.Schema != 1 {
		return policyInvalid("unsupported connection plan receipt schema")
	}
	if receipt.TransactionID != tx.transaction || receipt.PlanGeneration != tx.generation {
		return policyStale("connection plan receipt identity mismatch")
	}
	embedded, err := parsePolicyPlan(receipt.Plan)
	if err != nil {
		return err
	}
	if embedded.fingerprint != plan.fingerprint {
		return policyStale("connection plan receipt content mismatch")
	}
	owner, err := selectedDocumentOwner(projection)
	if err != nil {
		return err
	}
	return checkOfferedCandidateOrder(plan, profileOrder(projection), profiles, owner, clientOnly, helperSupportedProtocols())
}

// helperSupportedProtocols is the helper's own capability list; it gates the
// offered pool independently of the document. The ordering algorithm itself is
// protocol-list parameterised so the accepted mixed-protocol oracle can be
// replicated exactly when a richer supported set is supplied.
func helperSupportedProtocols() []string {
	return append([]string(nil), Protocols...)
}

func profileOrder(projection *documentProjection) []string {
	order := make([]string, len(projection.Profiles))
	for i, profile := range projection.Profiles {
		order[i] = profile.ID
	}
	return order
}

// restrictedNetworkProtocols is the five-entry ordering oracle frozen from the
// pre-removal Dart source (app/lib/rivet_profile.dart when it still listed
// cloak), kept only so TestOfferedOrderMixedProtocolOracle can replay that
// mixed-protocol expectation exactly. It is NOT the production capability set
// and it does not mirror the current Dart file: shipped validation uses
// helperSupportedProtocols() from Protocols (runtime.go), which has no cloak.
// Ordering ranks are relative, so the four shipped protocols keep the same
// relative order here (xray, rivet-s1, awg, rivet-h3).
var restrictedNetworkProtocols = []string{"xray", "rivet-s1", "cloak", "awg", "rivet-h3"}

// protocolPreference mirrors rivet_profile.dart protocolPreference with
// restricted:true. The selected/explicit priority protocol ranks first, then the
// documented order; an unexpected protocol ranks last.
func protocolPreference(protocol, preferred string) int {
	if protocol == preferred {
		return 0
	}
	for i, candidate := range restrictedNetworkProtocols {
		if candidate == protocol {
			return i + 1
		}
	}
	return 100
}

// checkOfferedCandidateOrder mirrors the accepted connectionCandidates oracle:
// the selected profile first when usable, then same-endpoint variants sorted by
// protocolPreference (document order as the tie-break), then other-endpoint
// fallbacks the same way; a revoked owner makes no candidate eligible. The plan
// may drop unreadable non-selected candidates, so the offered ids must be an
// ordered subsequence of this derived order.
func checkOfferedCandidateOrder(plan *policyPlan, documentOrder []string, profiles map[string]documentProfile, owner *documentUser, clientOnly bool, supported []string) error {
	if owner != nil && owner.Revoked != nil && *owner.Revoked {
		if len(plan.IDs) == 0 {
			return nil
		}
		return policyStale("selected owner is revoked")
	}
	if plan.SelectedID == nil {
		if len(plan.IDs) == 0 {
			return nil
		}
		return policyStale("offered candidates have no selected identity")
	}
	selected, ok := profiles[*plan.SelectedID]
	if !ok {
		if len(plan.IDs) == 0 {
			return nil
		}
		return policyStale("selected profile is not in the document")
	}
	preferred := "xray"
	if plan.PriorityProtocol != nil {
		preferred = *plan.PriorityProtocol
	}
	ownerAllows := func(id string) bool {
		if clientOnly || owner == nil {
			return true
		}
		for _, owned := range owner.ProfileIDs {
			if owned == id {
				return true
			}
		}
		return false
	}
	usable := func(profile documentProfile) bool {
		for _, protocol := range supported {
			if profile.Protocol == protocol {
				return true
			}
		}
		return false
	}
	type candidate struct {
		id    string
		index int
	}
	indexOf := make(map[string]int, len(documentOrder))
	for i, id := range documentOrder {
		indexOf[id] = i
	}
	var variants, fallbacks []candidate
	for _, id := range documentOrder {
		profile := profiles[id]
		if id == *plan.SelectedID {
			continue
		}
		if !usable(profile) || !ownerAllows(id) {
			continue
		}
		c := candidate{id: id, index: indexOf[id]}
		if profile.Endpoint == selected.Endpoint {
			variants = append(variants, c)
		} else {
			fallbacks = append(fallbacks, c)
		}
	}
	sortCandidates := func(list []candidate) {
		sort.SliceStable(list, func(i, j int) bool {
			left := protocolPreference(profiles[list[i].id].Protocol, preferred)
			right := protocolPreference(profiles[list[j].id].Protocol, preferred)
			if left != right {
				return left < right
			}
			return list[i].index < list[j].index
		})
	}
	sortCandidates(variants)
	sortCandidates(fallbacks)
	eligible := make([]string, 0, len(documentOrder))
	if usable(selected) {
		eligible = append(eligible, selected.ID)
	}
	if plan.Mode == "automatic" {
		for _, c := range variants {
			eligible = append(eligible, c.id)
		}
		for _, c := range fallbacks {
			eligible = append(eligible, c.id)
		}
	}
	position := 0
	for _, id := range eligible {
		if position < len(plan.IDs) && plan.IDs[position] == id {
			position++
		}
	}
	if position != len(plan.IDs) {
		return policyStale("offered candidates are not an ordered subsequence of the document-eligible plan")
	}
	return nil
}

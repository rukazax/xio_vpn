package desktop

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// The desktop helper has exactly one serialized policy writer. Policy state is
// mutated only under the existing Runtime mutex; the only physical work (read-only
// resource evidence and joining the existing teardown) happens outside it while
// `writing` still owns the lane. There is deliberately no durable helper plan
// journal: the Dart product document stays authoritative, and a helper restart
// always invalidates the instance nonce and starts blocked.
type policyMachine struct {
	instance        string
	boundStore      string
	launchBound     bool
	resourceClaimed bool
	phase           string // "blocked" (also zero), "pending", "ready"
	pending         *policyTx
	committed       *policyTx
	lastBlocked     *policyTx
	writing         bool
	committing      bool
	commitEpoch     uint64
	revoked         bool
	lane            chan struct{}
	resources       ResourceEvidence
	errorCode       string
	seen            map[string][32]byte
	observe         func() ResourceEvidence
	settleDelay     time.Duration
	clientOnly      bool
	clientOnlyBound bool
	validating      bool
	validationEpoch uint64
	validation      *policyValidationRecord
	validationTTL   time.Duration
}

const defaultPolicyValidationTTL = 120 * time.Second

const defaultPolicySettleWait = 5 * time.Second

// policyStateError is a finite, nonsecret diagnostic set. The state query never
// returns free-form text.
const (
	policyErrorNone            = ""
	policyErrorRevoked         = "revoked"
	policyErrorEvidenceOwned   = "resource_owned"
	policyErrorEvidenceUnknown = "resource_unknown"
)

type instanceNonceState struct {
	nonce string
	err   error
}

func policyACK(tx *policyTx, instance, state string) map[string]any {
	// Exactly the six fields WIRE-V1 §"Success ACK" allows; the Dart channel
	// rejects any other shape.
	return map[string]any{
		"version":         policyVersion,
		"instanceNonce":   instance,
		"controllerNonce": tx.controller,
		"transactionId":   tx.transaction,
		"planGeneration":  tx.generation,
		"state":           state,
	}
}

func policyReceiptView(tx *policyTx) map[string]any {
	return map[string]any{
		"version":         policyVersion,
		"storeIdentity":   tx.store,
		"instanceNonce":   tx.instance,
		"controllerNonce": tx.controller,
		"transactionId":   tx.transaction,
		"planGeneration":  tx.generation,
	}
}

func (m *policyMachine) phaseName() string {
	if m.writing {
		return "pending"
	}
	if m.phase == "" {
		return "blocked"
	}
	return m.phase
}

func (m *policyMachine) ready() bool {
	return m.phase == "ready" && m.committed != nil
}

func (m *policyMachine) resourceName() string {
	if m.resources == "" {
		return string(ResourcesUnknown)
	}
	return string(m.resources)
}

func (m *policyMachine) committedGeneration() string {
	if m.committed == nil {
		return ""
	}
	return m.committed.generation
}

func (m *policyMachine) settleTimeout() time.Duration {
	if m.settleDelay <= 0 {
		return defaultPolicySettleWait
	}
	return m.settleDelay
}

func (m *policyMachine) observerLocked() func() ResourceEvidence {
	if m.observe != nil {
		return m.observe
	}
	return observePlatformResources
}

func (m *policyMachine) closeLaneLocked() {
	if m.lane != nil {
		close(m.lane)
		m.lane = nil
	}
}

// identityLocked binds the helper to the launch store identity and one
// process-lifetime instance nonce. A versioned helper never adopts a store from an
// RPC and never accepts a different one.
func (m *policyMachine) identityLocked(tx *policyTx, instance string) error {
	if m.instance == "" {
		m.instance = instance
	}
	if m.instance != instance || tx.instance != instance {
		return policyStale("instance nonce")
	}
	if m.boundStore != tx.store {
		return policyStale("store identity")
	}
	return nil
}

// requireClaimsLocked enforces the cooperating prerequisites before any versioned
// publication: the launch store binding, the shared fixed-resource claim and the
// launch client-only build identity. None of them replaces nonce/generation
// fencing.
func (m *policyMachine) requireClaimsLocked() error {
	if !m.launchBound {
		return policyUnsupported("helper launch store binding required")
	}
	if !m.resourceClaimed {
		return policyUnsupported("shared resource claim required")
	}
	if !m.clientOnlyBound {
		return policyUnsupported("helper launch client-only binding required")
	}
	return nil
}

func (m *policyMachine) validationTimeout() time.Duration {
	if m.validationTTL > 0 {
		return m.validationTTL
	}
	return defaultPolicyValidationTTL
}

// validationRecordLocked reports whether a live validation exists for exactly
// this transaction/plan/CAS identity. It never mutates the record, so a caller
// can consume it only after this check succeeds.
func (m *policyMachine) validationRecordLocked(tx *policyTx, now time.Time) bool {
	record := m.validation
	if record == nil {
		return false
	}
	if record.instance != tx.instance || record.store != tx.store ||
		record.controller != tx.controller || record.transaction != tx.transaction ||
		record.expected != tx.expected || record.generation != tx.generation ||
		record.planFingerprint != tx.fingerprint {
		return false
	}
	if now.UnixNano() >= record.deadline {
		return false
	}
	for _, profile := range tx.plan.Profiles {
		if record.configDigests[profile.ID] != profile.Digest {
			return false
		}
	}
	return true
}

func policyValidationACK(tx *policyTx, instance string, documentDigest [32]byte) map[string]any {
	return map[string]any{
		"version":         policyVersion,
		"instanceNonce":   instance,
		"controllerNonce": tx.controller,
		"transactionId":   tx.transaction,
		"documentDigest":  hex.EncodeToString(documentDigest[:]),
	}
}

func (m *policyMachine) reserveLocked(tx *policyTx) {
	m.phase = "pending"
	m.pending = tx
	m.writing = true
	m.committing = false
	m.revoked = false
	m.errorCode = policyErrorNone
	m.lane = make(chan struct{})
}

func (r *Runtime) policyBlockedLocked(tx *policyTx, errorCode string) map[string]any {
	m := &r.policy
	m.phase = "blocked"
	m.pending = nil
	m.writing = false
	m.committing = false
	m.revoked = false
	m.errorCode = errorCode
	m.lastBlocked = tx
	m.validation = nil
	if m.seen == nil {
		m.seen = make(map[string][32]byte)
	}
	m.seen[tx.transaction] = tx.fingerprint
	m.closeLaneLocked()
	return policyACK(tx, m.instance, "blocked")
}

func (r *Runtime) policyCommitFinishLocked(tx *policyTx, evidence ResourceEvidence, epoch uint64) (map[string]any, error) {
	m := &r.policy
	if !m.committing || m.commitEpoch != epoch {
		// A superseded settlement must not mutate or ACK the current owner.
		return nil, policyBusy("commit settlement superseded")
	}
	if m.pending == nil || m.pending.transaction != tx.transaction || m.pending.fingerprint != tx.fingerprint {
		return nil, policyBusy("commit reservation changed before settlement")
	}
	m.resources = evidence
	m.committing = false
	if m.revoked {
		return r.policyBlockedLocked(tx, policyErrorRevoked), nil
	}
	if evidence != ResourcesClean {
		// Owned remnants require explicit recovery; a failed/limited query is
		// unknown. Neither is proof of a clean host and neither deletes anything.
		code := policyErrorEvidenceOwned
		if evidence == ResourcesUnknown {
			code = policyErrorEvidenceUnknown
		}
		return r.policyBlockedLocked(tx, code), nil
	}
	m.committed = tx
	m.pending = nil
	m.phase = "ready"
	m.writing = false
	m.committing = false
	m.revoked = false
	m.errorCode = policyErrorNone
	m.validation = nil
	if m.seen == nil {
		m.seen = make(map[string][32]byte)
	}
	m.seen[tx.transaction] = tx.fingerprint
	m.closeLaneLocked()
	return policyACK(tx, m.instance, "ready"), nil
}

func (r *Runtime) policyInstanceNonce() (string, error) {
	r.policyNonceOnce.Do(func() {
		generator := r.newPolicyNonce
		if generator == nil {
			generator = func() (string, error) {
				var raw [16]byte
				if _, err := rand.Read(raw[:]); err != nil {
					return "", err
				}
				return hex.EncodeToString(raw[:]), nil
			}
		}
		nonce, err := generator()
		if err == nil && !policyNoncePattern.MatchString(nonce) {
			err = errors.New("generated instance nonce is malformed")
		}
		r.policyNonceState.Store(&instanceNonceState{nonce: nonce, err: err})
	})
	state := r.policyNonceState.Load()
	if state == nil || state.err != nil {
		return "", policyUnknown("instance nonce unavailable")
	}
	return state.nonce, nil
}

// BindStoreIdentity applies the launch-time `--store-identity` binding. It never
// replaces an existing binding and never creates one after a commit.
func (r *Runtime) BindStoreIdentity(identity string) error {
	if !storeIdentityPattern.MatchString(identity) {
		return policyInvalid("store identity")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	m := &r.policy
	if m.boundStore == "" {
		m.boundStore = identity
		m.launchBound = true
		return nil
	}
	if m.boundStore != identity {
		return policyStale("store identity")
	}
	return nil
}

// BindClientOnly applies the mandatory launch `--client-only` build identity,
// which is never derived from the durable document.
func (r *Runtime) BindClientOnly(value bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	m := &r.policy
	if !m.launchBound {
		return policyUnsupported("launch store binding required before client-only")
	}
	if m.clientOnlyBound {
		if m.clientOnly != value {
			return policyInvalid("client-only binding already set")
		}
		return nil
	}
	m.clientOnly = value
	m.clientOnlyBound = true
	return nil
}

// BindResourceClaim records that this process holds the shared fixed-resource
// namespace claim. It is not store-scoped: distinct Full/Client stores share the
// fixed xio019 namespace and must still exclude each other.
func (r *Runtime) BindResourceClaim() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policy.resourceClaimed = true
}

func (r *Runtime) policyCapabilitiesLocked(instance string) map[string]any {
	m := &r.policy
	if m.instance == "" {
		m.instance = instance
	}
	return map[string]any{
		"version":         policyVersion,
		"instanceNonce":   instance,
		"state":           m.phaseName(),
		"resourceState":   m.resourceName(),
		"planSchema":      policyPlanSchema,
		"validation":      1,
		"launchBound":     m.launchBound,
		"resourceClaimed": m.resourceClaimed,
	}
}

// PolicyCapabilities is a cheap identity/readiness query. It never reserves and
// never reports a busy helper as ready: an unreachable lock degrades to pending.
func (r *Runtime) PolicyCapabilities() (map[string]any, error) {
	instance, err := r.policyInstanceNonce()
	if err != nil {
		return nil, err
	}
	if !r.mu.TryLock() {
		return map[string]any{
			"version":       policyVersion,
			"instanceNonce": instance,
			"state":         "pending",
			"resourceState": string(ResourcesUnknown),
			"planSchema":    policyPlanSchema,
			"validation":    1,
			"busy":          true,
		}, nil
	}
	defer r.mu.Unlock()
	m := &r.policy
	if m.instance == "" {
		m.instance = instance
	}
	return r.policyCapabilitiesLocked(instance), nil
}

// PolicyState is a query, not admission.
func (r *Runtime) PolicyState() (map[string]any, error) {
	instance, err := r.policyInstanceNonce()
	if err != nil {
		return nil, err
	}
	if !r.mu.TryLock() {
		return nil, policyBusy("runtime admission busy")
	}
	defer r.mu.Unlock()
	m := &r.policy
	if m.instance == "" {
		m.instance = instance
	}
	view := r.policyCapabilitiesLocked(instance)
	view["storeIdentity"] = m.boundStore
	view["clientOnly"] = nil
	if m.clientOnlyBound {
		view["clientOnly"] = m.clientOnly
	}
	// Finite, nonsecret diagnostics. No free-form text and never activation
	// authority by themselves.
	view["error"] = m.errorCode
	view["pendingTransaction"] = nil
	if m.pending != nil {
		view["pendingTransaction"] = m.pending.transaction
	}
	// `receipt` is activation authority ONLY while the helper is ready. While
	// blocked/pending the committed generation is exposed as `casGeneration`:
	// an expectedGeneration CAS input, never an admissible attachment.
	if m.committed != nil {
		view["casGeneration"] = m.committed.generation
	}
	if m.ready() {
		view["receipt"] = policyReceiptView(m.committed)
	}
	return view, nil
}

// PolicyBegin reserves the next generation. A helper that has not been
// reconciled refuses to publish, so a fresh Runtime can never bless a plan it
// never validated.
func (r *Runtime) PolicyBegin(request PolicyRequest) (map[string]any, error) {
	tx, err := parsePolicyTransaction(request)
	if err != nil {
		return nil, err
	}
	instance, err := r.policyInstanceNonce()
	if err != nil {
		return nil, err
	}
	if !r.mu.TryLock() {
		return nil, policyBusy("runtime admission busy")
	}
	defer r.mu.Unlock()
	m := &r.policy
	if err := m.requireClaimsLocked(); err != nil {
		return nil, err
	}
	if err := m.identityLocked(tx, instance); err != nil {
		return nil, err
	}
	if m.writing || m.pending != nil {
		return nil, policyBusy("policy writer owned")
	}
	if r.current != nil || r.cleanupPending.Load() {
		return nil, policyBusy("runtime is not idle")
	}
	if !m.ready() {
		return nil, policyUnknown("helper requires reconciliation before publication")
	}
	if tx.expected != m.committedGeneration() {
		return nil, policyStale("expected generation")
	}
	if prior, ok := m.seen[tx.transaction]; ok {
		if prior != tx.fingerprint {
			return nil, policyInvalid("transaction replay with different content")
		}
		return nil, policyStale("transaction already settled")
	}
	// A new publication invalidates any previous transient validation.
	m.validation = nil
	m.reserveLocked(tx)
	return policyACK(tx, instance, "pending"), nil
}

// PolicyCommit commits the reserved generation after authoritative Runtime
// memory admission. Owned/unknown resource evidence yields a blocked receipt, not
// a ready one, and never performs cleanup.
func (r *Runtime) PolicyCommit(request PolicyRequest) (map[string]any, error) {
	tx, err := parsePolicyTransaction(request)
	if err != nil {
		return nil, err
	}
	instance, err := r.policyInstanceNonce()
	if err != nil {
		return nil, err
	}
	if !r.mu.TryLock() {
		return nil, policyBusy("runtime admission busy")
	}
	observe, ack, epoch, err := r.policyCommitPrepareLocked(tx, instance)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if observe == nil {
		return ack, nil
	}
	evidence := observe()
	r.mu.Lock()
	ack, err = r.policyCommitFinishLocked(tx, evidence, epoch)
	r.mu.Unlock()
	return ack, err
}

func (r *Runtime) policyCommitPrepareLocked(tx *policyTx, instance string) (func() ResourceEvidence, map[string]any, uint64, error) {
	m := &r.policy
	if err := m.requireClaimsLocked(); err != nil {
		return nil, nil, 0, err
	}
	if err := m.identityLocked(tx, instance); err != nil {
		return nil, nil, 0, err
	}
	if m.committing {
		// Exactly one physical observer may exist for a reservation. A retry
		// during the in-flight settlement is busy, never a duplicate observer.
		return nil, nil, 0, policyBusy("commit settlement already in flight")
	}
	if m.committed != nil && m.committed.transaction == tx.transaction {
		if m.committed.fingerprint != tx.fingerprint {
			return nil, nil, 0, policyInvalid("transaction replay with different content")
		}
		if m.ready() {
			return nil, policyACK(tx, instance, "ready"), 0, nil
		}
	}
	if !m.writing || m.pending == nil {
		return nil, nil, 0, policyStale("no matching reservation")
	}
	if m.pending.transaction != tx.transaction {
		return nil, nil, 0, policyStale("no matching reservation")
	}
	if m.pending.fingerprint != tx.fingerprint {
		return nil, nil, 0, policyInvalid("transaction content changed")
	}
	if m.revoked {
		return nil, nil, 0, policyStale("transaction revoked")
	}
	if !m.validationRecordLocked(tx, r.clock()) {
		return nil, nil, 0, policyUnverified("transient validation is missing or expired")
	}
	m.commitEpoch++
	epoch := m.commitEpoch
	m.committing = true
	return m.observerLocked(), nil, epoch, nil
}

// PolicyReconcile publishes an explicitly validated durable app snapshot. It
// reuses the reservation/commit path and cannot steal an owned writer.
func (r *Runtime) PolicyReconcile(request PolicyRequest) (map[string]any, error) {
	tx, err := parsePolicyTransaction(request)
	if err != nil {
		return nil, err
	}
	instance, err := r.policyInstanceNonce()
	if err != nil {
		return nil, err
	}
	if !r.mu.TryLock() {
		return nil, policyBusy("runtime admission busy")
	}
	observe, ack, epoch, err := r.policyReconcilePrepareLocked(tx, instance)
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if observe == nil {
		return ack, nil
	}
	evidence := observe()
	r.mu.Lock()
	ack, err = r.policyCommitFinishLocked(tx, evidence, epoch)
	r.mu.Unlock()
	return ack, err
}

func (r *Runtime) policyReconcilePrepareLocked(tx *policyTx, instance string) (func() ResourceEvidence, map[string]any, uint64, error) {
	m := &r.policy
	if err := m.requireClaimsLocked(); err != nil {
		return nil, nil, 0, err
	}
	if err := m.identityLocked(tx, instance); err != nil {
		return nil, nil, 0, err
	}
	if m.committing {
		return nil, nil, 0, policyBusy("commit settlement already in flight")
	}
	if m.writing || m.pending != nil {
		return nil, nil, 0, policyBusy("policy writer owned")
	}
	if m.committed != nil && m.committed.transaction == tx.transaction {
		if m.committed.fingerprint != tx.fingerprint {
			return nil, nil, 0, policyInvalid("transaction replay with different content")
		}
		if m.ready() {
			return nil, policyACK(tx, instance, "ready"), 0, nil
		}
	}
	if m.ready() {
		return nil, nil, 0, policyStale("helper already reconciled")
	}
	if prior, ok := m.seen[tx.transaction]; ok {
		if prior != tx.fingerprint {
			return nil, nil, 0, policyInvalid("transaction replay with different content")
		}
		return nil, nil, 0, policyStale("transaction already settled")
	}
	if tx.expected != m.committedGeneration() {
		return nil, nil, 0, policyStale("expected generation")
	}
	if !m.validationRecordLocked(tx, r.clock()) {
		return nil, nil, 0, policyUnverified("transient validation is missing or expired")
	}
	m.reserveLocked(tx)
	m.commitEpoch++
	epoch := m.commitEpoch
	m.committing = true
	return m.observerLocked(), nil, epoch, nil
}

// PolicyValidate proves an offered plan against the supplied durable snapshot and
// records a bounded, transaction-bound transient validation. It is mandatory
// before commit/reconcile for every versioned publication. The heavy document and
// config checks run outside the Runtime mutex while an exclusive validation epoch
// protects the transaction from concurrent revocation or a new publication.
func (r *Runtime) PolicyValidate(request PolicyRequest, validation json.RawMessage) (map[string]any, error) {
	tx, err := parsePolicyTransaction(request)
	if err != nil {
		return nil, err
	}
	if len(validation) == 0 {
		return nil, policyInvalid("missing validation")
	}
	instance, err := r.policyInstanceNonce()
	if err != nil {
		return nil, err
	}
	if !r.mu.TryLock() {
		return nil, policyBusy("runtime admission busy")
	}
	m := &r.policy
	if err := m.requireClaimsLocked(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if err := m.identityLocked(tx, instance); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	if tx.plan.ClientOnly != m.clientOnly {
		r.mu.Unlock()
		return nil, policyInvalid("offered plan client-only flag does not match this helper build")
	}
	if m.validating {
		r.mu.Unlock()
		return nil, policyBusy("validation in progress")
	}
	if m.writing || m.pending != nil {
		if m.pending == nil || m.pending.transaction != tx.transaction || m.pending.fingerprint != tx.fingerprint {
			r.mu.Unlock()
			return nil, policyBusy("policy writer owned")
		}
	} else if m.phase != "" && m.phase != "blocked" && m.phase != "ready" {
		r.mu.Unlock()
		return nil, policyStale("unexpected helper phase")
	}
	if tx.expected != m.committedGeneration() {
		r.mu.Unlock()
		return nil, policyStale("expected generation")
	}
	m.validating = true
	epoch := m.validationEpoch
	clientOnly := m.clientOnly
	r.mu.Unlock()
	input, parseErr := parsePolicyValidation(validation, tx.plan, tx, clientOnly)
	r.mu.Lock()
	if !m.validating || m.validationEpoch != epoch {
		m.validating = false
		r.mu.Unlock()
		return nil, policyStale("validation superseded by a revocation or a new publication")
	}
	m.validating = false
	if parseErr != nil {
		r.mu.Unlock()
		return nil, parseErr
	}
	// The reservation/ownership must still be the same; nothing may have moved on
	// while the validation ran outside the mutex.
	if m.pending != nil {
		if m.pending.transaction != tx.transaction || m.pending.fingerprint != tx.fingerprint {
			r.mu.Unlock()
			return nil, policyStale("transaction changed during validation")
		}
	} else if m.committedGeneration() != tx.expected {
		r.mu.Unlock()
		return nil, policyStale("generation changed during validation")
	}
	configDigests := make(map[string][32]byte, len(input.configs))
	for _, config := range input.configs {
		configDigests[config.id] = config.digest
	}
	m.validation = &policyValidationRecord{
		instance:        instance,
		store:           tx.store,
		controller:      tx.controller,
		transaction:     tx.transaction,
		expected:        tx.expected,
		generation:      tx.generation,
		planFingerprint: tx.fingerprint,
		documentDigest:  input.documentDigest,
		configDigests:   configDigests,
		epoch:           epoch,
		deadline:        r.clock().Add(m.validationTimeout()).UnixNano(),
	}
	ack := policyValidationACK(tx, instance, input.documentDigest)
	r.mu.Unlock()
	return ack, nil
}

// PolicyAbort revokes the logical transaction with the agreed three-key request
// (version, instanceNonce, transactionId). Physical ownership is not released
// until any in-flight observation settles and the blocked reconciliation receipt
// is written; a timed-out caller therefore cannot admit a successor.
func (r *Runtime) PolicyAbort(request PolicyAbortRequest) (map[string]any, error) {
	if request.Version != policyVersion ||
		!policyNoncePattern.MatchString(request.InstanceNonce) ||
		!policyNoncePattern.MatchString(request.TransactionID) {
		return nil, policyInvalid("malformed abort request")
	}
	instance, err := r.policyInstanceNonce()
	if err != nil {
		return nil, err
	}
	if !r.mu.TryLock() {
		return nil, policyBusy("runtime admission busy")
	}
	m := &r.policy
	if err := m.requireClaimsLocked(); err != nil {
		r.mu.Unlock()
		return nil, err
	}
	// Revocation invalidates any in-flight or stored transient validation before
	// it can be consumed; a late validation can therefore never re-bless it.
	m.validationEpoch++
	m.validation = nil
	m.validating = false
	if m.instance == "" {
		m.instance = instance
	}
	if request.InstanceNonce != instance || m.instance != instance {
		r.mu.Unlock()
		return nil, policyStale("instance nonce")
	}
	if m.committed != nil && m.committed.transaction == request.TransactionID {
		r.mu.Unlock()
		return nil, policyStale("transaction already committed")
	}
	if m.pending == nil || m.pending.transaction != request.TransactionID {
		// The transaction may already have settled as blocked (for example a
		// timed-out abort whose in-flight commit finished). Re-ACK that settled
		// blocked receipt instead of inventing a stale/ready outcome; never ready.
		if m.lastBlocked != nil && m.lastBlocked.transaction == request.TransactionID {
			ack := policyACK(m.lastBlocked, m.instance, "blocked")
			r.mu.Unlock()
			return ack, nil
		}
		r.mu.Unlock()
		return nil, policyStale("unknown transaction")
	}
	pending := m.pending
	if !m.committing {
		// Nothing physical is outstanding: settle the blocked receipt now.
		ack := r.policyBlockedLocked(pending, policyErrorRevoked)
		r.mu.Unlock()
		return ack, nil
	}
	m.revoked = true
	lane := m.lane
	wait := m.settleTimeout()
	r.mu.Unlock()
	if lane != nil {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-lane:
		case <-timer.C:
			return nil, policyBusy("policy writer still settling")
		}
	}
	if !r.lockUntil(time.Now().Add(wait)) {
		return nil, policyBusy("policy writer still settling")
	}
	defer r.mu.Unlock()
	if m.pending != nil && m.pending.transaction == request.TransactionID {
		return r.policyBlockedLocked(m.pending, policyErrorRevoked), nil
	}
	return policyACK(pending, m.instance, "blocked"), nil
}

// admitPolicyLocked is the activation fence: it runs under the Runtime mutex
// before ANY stop/setup/route/effect. A missing receipt after versioned ownership
// began is POLICY_UNSUPPORTED, never a silent automatic fallback.
func (r *Runtime) admitPolicyLocked(id, protocol, raw string, receipt *policyReceipt) error {
	m := &r.policy
	owned := m.boundStore != "" || m.committed != nil || m.pending != nil || m.writing
	if receipt == nil {
		if owned {
			return policyUnsupported("policy receipt required")
		}
		return nil
	}
	if !m.launchBound || !m.resourceClaimed {
		return policyUnsupported("versioned activation requires launch binding and shared resource claim")
	}
	instance, err := r.policyInstanceNonce()
	if err != nil {
		return err
	}
	if m.instance == "" {
		m.instance = instance
	}
	if receipt.InstanceNonce != instance || m.instance != instance {
		return policyStale("instance nonce")
	}
	if m.boundStore == "" || receipt.StoreIdentity != m.boundStore {
		return policyStale("store identity")
	}
	if m.writing || m.pending != nil {
		return policyBusy("policy transaction pending")
	}
	if !m.ready() || m.committed == nil {
		return policyStale("helper is not ready")
	}
	committed := m.committed
	if receipt.TransactionID != committed.transaction ||
		receipt.PlanGeneration != committed.generation ||
		receipt.ControllerNonce != committed.controller {
		return policyStale("committed policy receipt mismatch")
	}
	profile, err := committed.plan.admissionProfile(id, protocol)
	if err != nil {
		return err
	}
	if policyConfigDigest(raw) != hex.EncodeToString(profile.Digest[:]) {
		return policyStale("saved configuration digest mismatch")
	}
	return nil
}

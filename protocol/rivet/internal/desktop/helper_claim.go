package desktop

import (
	"regexp"
)

var storeIdentityPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// HelperClaim is cooperating process-lifetime ownership scoped to one validated
// product StoreIdentity. It is not evidence that OS resources are absent: a
// successful claim only excludes another cooperating helper for the same store.
// Hold it until every Runtime operation has settled.
type HelperClaim interface {
	Close() error
}

func ClaimHelper(storeIdentity string) (HelperClaim, error) {
	if !storeIdentityPattern.MatchString(storeIdentity) {
		return nil, policyInvalid("store identity")
	}
	return claimProductHelper(storeIdentity)
}

// ClaimResourceNamespace is the shared cooperating claim over the fixed OS
// resource namespace (xio019, its routes/rules and receipts). It is separate from
// the per-store helper claim: two helpers for DIFFERENT product stores must still
// exclude each other, because the device name and routing selectors are fixed.
// Hold it for the whole helper lifetime, across observation, admission, activation
// and teardown. It is cooperating exclusion only: read-only resource evidence is
// still required to classify stale or noncooperating leftovers.
func ClaimResourceNamespace() (HelperClaim, error) {
	return claimProductResource()
}

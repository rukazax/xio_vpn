package issuancecapsule

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ParseSealRequest is the strict, reusable stdin request parser for the sealer
// CLI. It enforces exactly one JSON value with no trailing bytes, duplicate keys
// at every object level, an exact closed field set, and real JSON integers for
// schema/version (quoted, decimal and exponent forms are rejected).
var (
	ErrSealRequestShape     = errors.New("seal request shape")
	ErrSealRequestContext   = errors.New("seal request context")
	ErrSealRequestArtifacts = errors.New("seal request artifacts")
	ErrSealRequestRecipient = errors.New("seal request recipient")
)

// SealRequest is the decoded CLI input. Secrets in Artifacts are only returned
// to the caller; they are never logged or echoed by this package.
type SealRequest struct {
	Context            Context
	Artifacts          map[string]string
	RecipientPublicKey []byte
}

var sealRequestFields = []string{"context", "artifacts", "recipientPublicKey"}

var sealContextFields = []string{
	"schema", "purpose", "version", "operation", "uid", "server", "deployment",
	"actor", "requestDigest", "profileSetDigest",
}

func ParseSealRequest(raw []byte) (SealRequest, error) {
	if err := checkNoDuplicateKeys(raw); err != nil {
		return SealRequest{}, fmt.Errorf("%w: %v", ErrSealRequestShape, err)
	}
	fields, err := strictObject(raw, sealRequestFields)
	if err != nil {
		return SealRequest{}, fmt.Errorf("%w: %v", ErrSealRequestShape, err)
	}
	context, err := parseSealContext(fields["context"])
	if err != nil {
		return SealRequest{}, err
	}
	artifacts, err := parseSealArtifacts(fields["artifacts"])
	if err != nil {
		return SealRequest{}, err
	}
	var recipientText string
	if err := json.Unmarshal(fields["recipientPublicKey"], &recipientText); err != nil {
		return SealRequest{}, fmt.Errorf("%w: %v", ErrSealRequestRecipient, err)
	}
	recipient, err := decodeCanonicalBase64(recipientText, 32)
	if err != nil {
		return SealRequest{}, fmt.Errorf("%w: %v", ErrSealRequestRecipient, err)
	}
	return SealRequest{Context: context, Artifacts: artifacts, RecipientPublicKey: recipient}, nil
}

func parseSealContext(raw json.RawMessage) (Context, error) {
	fields, err := strictObject(raw, sealContextFields)
	if err != nil {
		return Context{}, fmt.Errorf("%w: %v", ErrSealRequestContext, err)
	}
	context := Context{}
	if context.Schema, err = intValue(fields["schema"]); err != nil {
		return Context{}, fmt.Errorf("%w: %v", ErrSealRequestContext, err)
	}
	if context.Version, err = intValue(fields["version"]); err != nil {
		return Context{}, fmt.Errorf("%w: %v", ErrSealRequestContext, err)
	}
	for key, target := range map[string]*string{
		"purpose": &context.Purpose, "operation": &context.Operation, "uid": &context.UID,
		"server": &context.Server, "deployment": &context.Deployment, "actor": &context.Actor,
		"requestDigest": &context.RequestDigest, "profileSetDigest": &context.ProfileSetDigest,
	} {
		value, err := stringValue(fields[key])
		if err != nil {
			return Context{}, fmt.Errorf("%w: %v", ErrSealRequestContext, err)
		}
		*target = value
	}
	if err := ValidateContext(context); err != nil {
		return Context{}, fmt.Errorf("%w: %v", ErrSealRequestContext, err)
	}
	return context, nil
}

func parseSealArtifacts(raw json.RawMessage) (map[string]string, error) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, fmt.Errorf("%w: not an object", ErrSealRequestArtifacts)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSealRequestArtifacts, err)
	}
	if len(fields) > MaxArtifacts {
		return nil, fmt.Errorf("%w: too many artifacts", ErrSealRequestArtifacts)
	}
	artifacts := make(map[string]string, len(fields))
	for key, valueRaw := range fields {
		if !isArtifactKind(key) {
			return nil, fmt.Errorf("%w: unknown kind", ErrSealRequestArtifacts)
		}
		value, err := stringValue(valueRaw)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrSealRequestArtifacts, err)
		}
		if len(value) == 0 || len(value) > MaxArtifactBytes || !printableArtifact(value) {
			return nil, fmt.Errorf("%w: invalid value", ErrSealRequestArtifacts)
		}
		artifacts[key] = value
	}
	return artifacts, nil
}

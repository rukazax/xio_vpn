package desktop

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// Immutable copy of the core DSL fixture (source branch
// agent/connection-mode-implementation-20261106, product 1be0954). The bytes are
// the golden; the source hash and size are asserted so a local edit cannot drift.
const (
	coreFixturePath   = "testdata/desktop-validation-projection.json"
	coreFixtureSHA256 = "a9ff83c7f42994367a1c0f81ac83f894558263b51a6c0f9f443b77fddfb0ab1f"
	coreFixtureSize   = 21245
)

type coreFixtureVariant struct {
	TransactionID  string          `json:"transactionId"`
	PlanGeneration string          `json:"planGeneration"`
	DocumentDigest string          `json:"documentDigest"`
	DocumentBytes  string          `json:"documentBytesBase64"`
	Document       json.RawMessage `json:"document"`
	Plan           json.RawMessage `json:"plan"`
	Configs        []struct {
		ID      string `json:"id"`
		Bytes   string `json:"bytesBase64"`
		SHA256  string `json:"sha256"`
	} `json:"configs"`
	ValidateRequest json.RawMessage `json:"validateRequest"`
}

type coreFixture struct {
	Schema         int    `json:"schema"`
	StoreIdentity  string `json:"storeIdentity"`
	InstanceNonce  string `json:"instanceNonce"`
	ControllerNonce string `json:"controllerNonce"`
	Manual         coreFixtureVariant `json:"manual"`
	Automatic      coreFixtureVariant `json:"automatic"`
}

func loadCoreFixture(t *testing.T) coreFixture {
	t.Helper()
	raw, err := os.ReadFile(coreFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != coreFixtureSize {
		t.Fatalf("fixture size %d, want %d", len(raw), coreFixtureSize)
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != coreFixtureSHA256 {
		t.Fatalf("fixture sha256 %s, want %s", got, coreFixtureSHA256)
	}
	var fixture coreFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != 1 || len(fixture.Manual.ValidateRequest) == 0 || len(fixture.Automatic.ValidateRequest) == 0 {
		t.Fatalf("unexpected fixture envelope: %+v", fixture)
	}
	return fixture
}

// TestCoreFixtureParserAcceptance is the independent Go parser verdict for the
// core DSL fixture: it decodes the exact document/config bytes, verifies every
// digest, parses the plan and the nine-key envelope, and only then runs the real
// policyValidate path. No admin, device, route or network effect is involved.
func TestCoreFixtureParserAcceptance(t *testing.T) {
	fixture := loadCoreFixture(t)
	for name, variant := range map[string]coreFixtureVariant{
		"manual":    fixture.Manual,
		"automatic": fixture.Automatic,
	} {
		t.Run(name, func(t *testing.T) {
			documentBytes, err := base64.StdEncoding.DecodeString(variant.DocumentBytes)
			if err != nil {
				t.Fatalf("document base64: %v", err)
			}
			digest := sha256.Sum256(documentBytes)
			if got := hex.EncodeToString(digest[:]); got != variant.DocumentDigest {
				t.Fatalf("document sha256 %s, want %s", got, variant.DocumentDigest)
			}
			plan, err := parsePolicyPlan(variant.Plan)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if len(variant.Configs) != len(plan.IDs) {
				t.Fatalf("config ids %d, plan ids %d", len(variant.Configs), len(plan.IDs))
			}
			for i, config := range variant.Configs {
				if config.ID != plan.IDs[i] {
					t.Fatalf("config id %q, want %q", config.ID, plan.IDs[i])
				}
				bytes, err := base64.StdEncoding.DecodeString(config.Bytes)
				if err != nil {
					t.Fatalf("config %q base64: %v", config.ID, err)
				}
				sum := sha256.Sum256(bytes)
				if got := hex.EncodeToString(sum[:]); got != hex.EncodeToString(plan.Profiles[i].Digest[:]) {
					t.Fatalf("config %q sha256 %s, want %s", config.ID, got, hex.EncodeToString(plan.Profiles[i].Digest[:]))
				}
				if _, err := ParseProfile(plan.Profiles[i].Protocol, string(bytes)); err != nil {
					t.Fatalf("pure parser rejected fixture config %q: %v", config.ID, err)
				}
			}
			// The full public path: bind the fixture identity, then validate.
			r := &Runtime{newPolicyNonce: func() (string, error) { return fixture.InstanceNonce, nil }}
			r.policy.observe = func() ResourceEvidence { return ResourcesClean }
			if err := r.BindStoreIdentity(fixture.StoreIdentity); err != nil {
				t.Fatal(err)
			}
			if err := r.BindClientOnly(plan.ClientOnly); err != nil {
				t.Fatal(err)
			}
			r.BindResourceClaim()
			var envelope struct {
				Version            int             `json:"version"`
				StoreIdentity      string          `json:"storeIdentity"`
				ControllerNonce    string          `json:"controllerNonce"`
				InstanceNonce      string          `json:"instanceNonce"`
				TransactionID      string          `json:"transactionId"`
				ExpectedGeneration *string         `json:"expectedGeneration"`
				PlanGeneration     string          `json:"planGeneration"`
				Plan               json.RawMessage `json:"plan"`
				Validation         json.RawMessage `json:"validation"`
			}
			if err := json.Unmarshal(variant.ValidateRequest, &envelope); err != nil {
				t.Fatal(err)
			}
			request := PolicyRequest{
				Version: envelope.Version, StoreIdentity: envelope.StoreIdentity,
				ControllerNonce: envelope.ControllerNonce, InstanceNonce: envelope.InstanceNonce,
				TransactionID: envelope.TransactionID, PlanGeneration: envelope.PlanGeneration,
				ExpectedGeneration: envelope.ExpectedGeneration, Plan: envelope.Plan,
			}
			ack, err := r.PolicyValidate(request, envelope.Validation)
			if err != nil {
				t.Fatalf("policyValidate rejected the fixture: %v", err)
			}
			if ack["documentDigest"] != variant.DocumentDigest || len(ack) != 5 {
				t.Fatalf("validate ACK %v, want the five-field response", ack)
			}
			// The transient record must be consumable by reconcile for this identity.
			if _, err := r.PolicyReconcile(request); err != nil {
				t.Fatalf("reconcile after fixture validation: %v", err)
			}
		})
	}
}

// TestCoreFixtureTamperRejection proves the fixture-backed path is not a blind
// accept: changing the supplied config bytes, document digest or plan content is
// rejected before any READY state.
func TestCoreFixtureTamperRejection(t *testing.T) {
	fixture := loadCoreFixture(t)
	variant := fixture.Manual
	plan, err := parsePolicyPlan(variant.Plan)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(coreFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	envelope := root["manual"].(map[string]any)["validateRequest"].(map[string]any)
	validation := envelope["validation"].(map[string]any)
	documentBase64 := validation["documentBytesBase64"].(string)

	newRuntime := func() (*Runtime, PolicyRequest) {
		r := &Runtime{newPolicyNonce: func() (string, error) { return fixture.InstanceNonce, nil }}
		r.policy.observe = func() ResourceEvidence { return ResourcesClean }
		if err := r.BindStoreIdentity(fixture.StoreIdentity); err != nil {
			t.Fatal(err)
		}
		if err := r.BindClientOnly(plan.ClientOnly); err != nil {
			t.Fatal(err)
		}
		r.BindResourceClaim()
		request := PolicyRequest{
			Version: 1, StoreIdentity: fixture.StoreIdentity, ControllerNonce: fixture.ControllerNonce,
			InstanceNonce: fixture.InstanceNonce, TransactionID: variant.TransactionID,
			PlanGeneration: variant.PlanGeneration, Plan: variant.Plan,
		}
		return r, request
	}
	t.Run("document digest mismatch", func(t *testing.T) {
		r, request := newRuntime()
		tampered := map[string]any{}
		for key, value := range validation {
			tampered[key] = value
		}
		tampered["documentDigest"] = "0" + variant.DocumentDigest[1:]
		payload, _ := json.Marshal(tampered)
		if _, err := r.PolicyValidate(request, payload); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("digest mismatch: %v", err)
		}
	})
	t.Run("config bytes mismatch", func(t *testing.T) {
		r, request := newRuntime()
		tampered := map[string]any{}
		for key, value := range validation {
			tampered[key] = value
		}
		configs := []any{}
		for _, entry := range tampered["configs"].([]any) {
			config := entry.(map[string]any)
			bytes, _ := base64.StdEncoding.DecodeString(config["bytesBase64"].(string))
			config["bytesBase64"] = base64.StdEncoding.EncodeToString(append(bytes, '\n'))
			configs = append(configs, config)
		}
		tampered["configs"] = configs
		payload, _ := json.Marshal(tampered)
		if _, err := r.PolicyValidate(request, payload); !errors.Is(err, ErrPolicyStale) {
			t.Fatalf("config mismatch: %v", err)
		}
	})
	t.Run("document bytes mismatch", func(t *testing.T) {
		r, request := newRuntime()
		tampered := map[string]any{}
		for key, value := range validation {
			tampered[key] = value
		}
		bytes, _ := base64.StdEncoding.DecodeString(documentBase64)
		bytes = append(bytes, ' ')
		tampered["documentBytesBase64"] = base64.StdEncoding.EncodeToString(bytes)
		payload, _ := json.Marshal(tampered)
		if _, err := r.PolicyValidate(request, payload); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("document bytes mismatch: %v", err)
		}
	})
}

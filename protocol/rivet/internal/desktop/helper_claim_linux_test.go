package desktop

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyHelperClaimsOnlyOwnedTemporaryFixture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "helper.lock")
	owner := uint32(os.Geteuid())
	first, err := claimHelperFile(path, owner)
	if err != nil {
		t.Fatal(err)
	}
	second, err := claimHelperFile(path, owner)
	if second != nil {
		_ = second.Close()
		t.Fatal("second cooperating helper claimed the store")
	}
	if !errors.Is(err, ErrPolicyBusy) {
		t.Fatalf("duplicate claim error %v, want POLICY_BUSY", err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	replacement, err := claimHelperFile(path, owner)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	// The claim inode must stay stable: never unlink a lock another helper holds.
	if _, err = os.Stat(path); err != nil {
		t.Fatal("claim inode must remain stable", err)
	}
}

func TestPolicyHelperRejectsUnsafeOwnedFixture(t *testing.T) {
	owner := uint32(os.Geteuid())
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if claim, err := claimHelperFile(link, owner); err == nil {
		_ = claim.Close()
		t.Fatal("symlink accepted as claim")
	} else if !errors.Is(err, ErrPolicyUnknown) {
		t.Fatalf("symlink error %v, want POLICY_UNKNOWN", err)
	}
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	if claim, err := claimHelperFile(target, owner); err == nil {
		_ = claim.Close()
		t.Fatal("public claim file accepted")
	}
	if claim, err := claimHelperFile(target, owner+1); err == nil {
		_ = claim.Close()
		t.Fatal("foreign-owned claim file accepted")
	}
	for _, identity := range []string{"", "../escape", strings.Repeat("A", 64), strings.Repeat("a", 63), strings.Repeat("a", 65)} {
		if claim, err := ClaimHelper(identity); err == nil {
			_ = claim.Close()
			t.Fatalf("invalid identity %q reached the product claim", identity)
		}
	}
}

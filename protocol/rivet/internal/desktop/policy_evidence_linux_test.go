package desktop

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyResourcesAreNeverInferred(t *testing.T) {
	for _, tc := range []struct {
		name         string
		observations []resourceObservation
		want         ResourceEvidence
	}{
		{"no observations", nil, ResourcesUnknown},
		{"known clean", []resourceObservation{{complete: true}, {complete: true}}, ResourcesClean},
		{"owned receipt", []resourceObservation{{complete: true, owned: true}, {complete: true}}, ResourcesOwned},
		{"failed enumeration", []resourceObservation{{complete: true}, {}}, ResourcesUnknown},
		{"owned but incomplete", []resourceObservation{{complete: true, owned: true}, {}}, ResourcesUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyResources(tc.observations...); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestPolicyJournalObservation(t *testing.T) {
	owner := uint32(os.Geteuid())
	dir := t.TempDir()
	path := filepath.Join(dir, "journal")
	if observation := observeLinuxJournal(path, owner); !observation.complete || observation.owned {
		t.Fatalf("absent journal: %+v", observation)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if observation := observeLinuxJournal(path, owner); !observation.complete || observation.owned {
		t.Fatalf("empty journal: %+v", observation)
	}
	if err := os.WriteFile(path, []byte("XIO019-routing-owned\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if observation := observeLinuxJournal(path, owner); !observation.complete || !observation.owned {
		t.Fatalf("owned marker: %+v", observation)
	}
	if err := os.WriteFile(path, []byte("some-other-owner\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if observation := observeLinuxJournal(path, owner); observation.complete {
		t.Fatalf("unknown marker treated as known: %+v", observation)
	}
	// Unsafe permissions or ownership are Unknown, never clean.
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if observation := observeLinuxJournal(path, owner); observation.complete {
		t.Fatalf("public journal accepted: %+v", observation)
	}
	if observation := observeLinuxJournal(path, owner+1); observation.complete {
		t.Fatalf("foreign-owned journal accepted: %+v", observation)
	}
	if observation := observeLinuxJournal(dir, owner); observation.complete {
		t.Fatalf("directory accepted as journal: %+v", observation)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if observation := observeLinuxJournal(link, owner); observation.complete {
		t.Fatalf("symlink journal accepted: %+v", observation)
	}
}

func fakeIP(overrides map[string]string, failure string) commandRunner {
	return func(name string, args ...string) ([]byte, error) {
		if name != "/usr/sbin/ip" {
			return nil, os.ErrNotExist
		}
		key := strings.Join(args, " ")
		if key == failure {
			return nil, os.ErrPermission
		}
		if value, ok := overrides[key]; ok {
			return []byte(value), nil
		}
		return []byte("[]"), nil
	}
}

func watchInterface(name string) func() ([]net.Interface, error) {
	return func() ([]net.Interface, error) { return []net.Interface{{Name: name}}, nil }
}

func TestPolicyLinuxEvidenceClassification(t *testing.T) {
	cleanJournal := func() resourceObservation { return resourceObservation{complete: true} }
	ownedJournal := func() resourceObservation { return resourceObservation{complete: true, owned: true} }
	unknownJournal := func() resourceObservation { return resourceObservation{} }
	noInterfaces := func() ([]net.Interface, error) { return nil, nil }
	withDevice := func() ([]net.Interface, error) { return []net.Interface{{Name: deviceName}}, nil }
	failingInterfaces := func() ([]net.Interface, error) { return nil, os.ErrPermission }
	empty := fakeIP(nil, "")
	cases := []struct {
		name       string
		interfaces func() ([]net.Interface, error)
		journal    func() resourceObservation
		run        commandRunner
		want       ResourceEvidence
	}{
		{"clean host", noInterfaces, cleanJournal, empty, ResourcesClean},
		{"device remains", withDevice, cleanJournal, empty, ResourcesOwned},
		{"journal marker", noInterfaces, ownedJournal, empty, ResourcesOwned},
		{"reserved rule", noInterfaces, cleanJournal, fakeIP(map[string]string{
			"-4 -j rule show": `[{"priority":18018,"fwmark":"0x80000/0xff0000"}]`,
		}, ""), ResourcesOwned},
		{"dedicated table", noInterfaces, cleanJournal, fakeIP(map[string]string{
			"-6 -j route show table all": `[{"table":"28691"}]`,
		}, ""), ResourcesOwned},
		{"device route", noInterfaces, cleanJournal, fakeIP(map[string]string{
			"-4 -j route show table all": `[{"dev":"xio019","table":"main"}]`,
		}, ""), ResourcesOwned},
		{"query failure", noInterfaces, cleanJournal, fakeIP(nil, "-6 -j rule show"), ResourcesUnknown},
		{"invalid json", noInterfaces, cleanJournal, fakeIP(map[string]string{
			"-4 -j rule show": `not-json`,
		}, ""), ResourcesUnknown},
		{"null rows", noInterfaces, cleanJournal, fakeIP(map[string]string{
			"-4 -j route show table all": "null",
		}, ""), ResourcesUnknown},
		{"interface enumeration failure", failingInterfaces, cleanJournal, empty, ResourcesUnknown},
		{"unknown journal", noInterfaces, unknownJournal, empty, ResourcesUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := observeLinuxResources(tc.interfaces, tc.journal, tc.run); got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

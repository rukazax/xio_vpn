package tailclient

import (
	"context"
	"errors"
	"github.com/tailscale/wireguard-go/tun"
	"golang.org/x/sys/unix"
	"os"
	"tailscale.com/ipn"
	"testing"
	"time"
)

type memoryStore struct {
	values map[string]string
	fail   bool
}

func (m *memoryStore) Load(k string) string { return m.values[k] }
func (m *memoryStore) Save(k, v string) bool {
	if m.fail {
		return false
	}
	m.values[k] = v
	return true
}
func TestEncryptedStoreContract(t *testing.T) {
	m := &memoryStore{values: map[string]string{}}
	s := &encryptedStore{store: m}
	if _, e := s.ReadState("missing"); !errors.Is(e, ipn.ErrStateNotExist) {
		t.Fatal(e)
	}
	if e := s.WriteState("node", []byte("sensitive fixture")); e != nil {
		t.Fatal(e)
	}
	if m.values["node"] == "sensitive fixture" {
		t.Fatal("expected base64 bridge encoding")
	}
	b, e := s.ReadState("node")
	if e != nil || string(b) != "sensitive fixture" {
		t.Fatal(e)
	}
	m.values["node"] = "!"
	if _, e = s.ReadState("node"); e == nil {
		t.Fatal("corrupt store accepted")
	}
	m.fail = true
	if e = s.WriteState("node", b); e == nil {
		t.Fatal("failed persistence ignored")
	}
}
func TestDeferredTunCloseBeforeAttach(t *testing.T) {
	d := NewDevice()
	done := make(chan error, 1)
	go func() { _, e := d.Read(make([]byte, 1600), make([]tun.ReadPacket, 1)); done <- e }()
	d.Close()
	select {
	case e := <-done:
		if !errors.Is(e, os.ErrClosed) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("read leaked before attachment")
	}
}
func TestTunPacketsAndClose(t *testing.T) {
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fds[1])
	d := NewDevice()
	if e = d.Attach(fds[0]); e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	payload := []byte{0x45, 0, 0, 4}
	_, e = unix.Write(fds[1], payload)
	if e != nil {
		t.Fatal(e)
	}
	slab := make([]byte, 1600)
	packets := make([]tun.ReadPacket, 1)
	n, e := d.Read(slab, packets)
	if e != nil || n != 1 || packets[0].Offset != 64 || packets[0].Size != 4 {
		t.Fatalf("read: %v", e)
	}
	if _, e = d.Write([][]byte{append([]byte{0, 0}, payload...)}, 2); e != nil {
		t.Fatal(e)
	}
	b := make([]byte, 32)
	n, e = unix.Read(fds[1], b)
	if e != nil || n != 4 || b[0] != 0x45 {
		t.Fatal("write mismatch")
	}
	wait, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() { d.Read(slab, packets); close(done) }()
	d.Close()
	select {
	case <-done:
	case <-wait.Done():
		t.Fatal("attached read did not close")
	}
}

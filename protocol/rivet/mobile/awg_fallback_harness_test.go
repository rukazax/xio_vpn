//go:build awgstandalone

// Explicit-file-list harness only: compiled together with awg_fallback.go and
// awg_handshake_unix.go so the Android registry can be exercised on Windows
// with upstream memory-only TUN/Bind. No OS sockets, drivers or devices.
package mobile

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

func harnessDevice(t *testing.T) (*device.Device, string) {
	t.Helper()
	binds := bindtest.NewChannelBinds()
	logger := &device.Logger{Verbosef: func(string, ...any) {}, Errorf: func(string, ...any) {}}
	a := device.NewDevice(tuntest.NewChannelTUN().TUN(), binds[0], logger)
	b := device.NewDevice(tuntest.NewChannelTUN().TUN(), binds[1], logger)
	t.Cleanup(func() {
		a.Close()
		b.Close()
	})
	ka, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicA := hex.EncodeToString(ka.PublicKey().Bytes())
	publicB := hex.EncodeToString(kb.PublicKey().Bytes())
	if err := a.IpcSet("private_key=" + hex.EncodeToString(ka.Bytes()) + "\nrekey_timeout=1\npublic_key=" + publicB + "\nallowed_ip=0.0.0.0/0\nendpoint=127.0.0.1:1\n"); err != nil {
		t.Fatal(err)
	}
	if err := b.IpcSet("private_key=" + hex.EncodeToString(kb.Bytes()) + "\npublic_key=" + publicA + "\nallowed_ip=0.0.0.0/0\nendpoint=127.0.0.1:2\n"); err != nil {
		t.Fatal(err)
	}
	if err := a.Up(); err != nil {
		t.Fatal(err)
	}
	if err := b.Up(); err != nil {
		t.Fatal(err)
	}
	return a, publicB
}

func harnessRegister(handle int64, d *device.Device) {
	awgHandles.Lock()
	awgHandles.entries[handle] = &awgHandleEntry{device: d, closeDevice: func() { awgCloseDevice(d) },
		closed: make(chan struct{}), attempted: make(map[device.NoisePublicKey]bool)}
	awgHandles.Unlock()
}
func harnessUnregister(handle int64) { awgTurnOff(handle) }

func TestAwgActualHandshakeMemoryOnly(t *testing.T) {
	a, public := harnessDevice(t)
	harnessRegister(1, a)
	defer harnessUnregister(1)

	original, _ := a.IpcGet()
	if e := AwgHandshakeCandidates(999, public, "127.0.0.1:3", 100); e == nil {
		t.Fatal("closed handle accepted")
	}
	if e := AwgHandshakeCandidates(1, public, "127.0.0.1:3\nprivate_key=bad", 100); e == nil {
		t.Fatal("IPC injection accepted")
	}
	unchanged, _ := a.IpcGet()
	if original != unchanged {
		t.Fatal("validation mutated config")
	}
	// Endpoint 9 is unreachable in the fixture; endpoint 3 is the exact numeric
	// source of authenticated responses. Only that source may succeed.
	if e := AwgHandshakeCandidates(1, public, "127.0.0.1:9,127.0.0.1:3", 8000); e != nil {
		t.Fatal("actual authenticated fallback", e)
	}
	raw, _ := a.IpcGet()
	if !strings.Contains(raw, "endpoint=127.0.0.1:3\n") {
		t.Fatal("winning endpoint not installed")
	}
	if !strings.Contains(raw, "allowed_ip=0.0.0.0/0") {
		t.Fatal("peer configuration was replaced")
	}
	if e := AwgHandshakeCandidates(1, strings.ToUpper(public), "127.0.0.1:3", 2000); e == nil {
		t.Fatal("second activation on one handle accepted")
	}
}

func TestAwgActualCancelMemoryOnly(t *testing.T) {
	a, public := harnessDevice(t)
	harnessRegister(2, a)
	defer harnessUnregister(2)

	done := make(chan error, 1)
	go func() { done <- AwgHandshakeCandidates(2, public, "127.0.0.1:1", 30000) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		awgHandles.Lock()
		e := awgHandles.entries[2]
		active := e != nil && e.operation != nil
		awgHandles.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("operation not started")
		}
		time.Sleep(time.Millisecond)
	}
	AwgCancelHandshake(2)
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("cancel accepted as success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cancel did not return")
	}
	awgHandles.Lock()
	_, stillRegistered := awgHandles.entries[2]
	awgHandles.Unlock()
	if stillRegistered {
		t.Fatal("failed attempt kept its handle")
	}
	AwgCancelHandshake(999)
}

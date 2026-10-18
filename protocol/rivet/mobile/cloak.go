package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/cbeuw/Cloak"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type cloakBridge struct {
	listener net.Listener
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.Mutex
	conns    map[net.Conn]bool
}

var cloakState struct {
	sync.Mutex
	b *cloakBridge
}

type cloakDialer struct {
	ctx context.Context
	p   Protector
}

func (d cloakDialer) Dial(network, address string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second, Control: func(_, _ string, c syscall.RawConn) error {
		ok := false
		e := c.Control(func(fd uintptr) { ok = d.p != nil && d.p.Protect(int64(fd)) })
		if e != nil {
			return e
		}
		if !ok {
			return errors.New("cloak: socket protection failed")
		}
		return nil
	}}
	return dialer.DialContext(d.ctx, network, address)
}
func CloakStart(raw string, p Protector, timeoutMillis int64) (int64, error) {
	CloakStop()
	if len(raw) > 65536 || p == nil || timeoutMillis < 1 || timeoutMillis > 60000 {
		return 0, errors.New("cloak: invalid profile")
	}
	var envelope struct {
		Protocol string          `json:"protocol"`
		Cloak    json.RawMessage `json:"cloak"`
	}
	if json.Unmarshal([]byte(raw), &envelope) != nil || envelope.Protocol != "cloak" {
		return 0, errors.New("cloak: invalid profile")
	}
	cfg, e := cloak.Decode(envelope.Cloak)
	if e != nil || len(cfg.UID) != 16 || len(cfg.PublicKey) != 32 || cfg.ServerName == "" {
		return 0, errors.New("cloak: invalid profile")
	}
	port, e := strconv.Atoi(cfg.RemotePort)
	if e != nil || port < 1 || port > 65535 {
		return 0, errors.New("cloak: invalid port")
	}
	if net.ParseIP(cfg.RemoteHost) == nil {
		done := make(chan string, 1)
		go func() { done <- p.Resolve(cfg.RemoteHost) }()
		select {
		case host := <-done:
			cfg.RemoteHost = host
		case <-time.After(time.Duration(timeoutMillis) * time.Millisecond):
			return 0, errors.New("cloak: DNS timeout")
		}
		if net.ParseIP(cfg.RemoteHost) == nil {
			return 0, errors.New("cloak: DNS failed")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	ln, e := net.Listen("tcp4", "127.0.0.1:0")
	if e != nil {
		cancel()
		return 0, e
	}
	b := &cloakBridge{listener: ln, cancel: cancel, conns: map[net.Conn]bool{}}
	cloakState.Lock()
	cloakState.b = b
	cloakState.Unlock()
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			local, e := ln.Accept()
			if e != nil {
				return
			}
			b.mu.Lock()
			if len(b.conns) >= 2 {
				b.mu.Unlock()
				local.Close()
				continue
			}
			b.conns[local] = true
			b.mu.Unlock()
			b.wg.Add(1)
			go func() {
				defer b.wg.Done()
				defer local.Close()
				defer func() { b.mu.Lock(); delete(b.conns, local); b.mu.Unlock() }()
				attempt, stop := context.WithTimeout(ctx, time.Duration(timeoutMillis)*time.Millisecond)
				remote, e := cloak.Open(attempt, cfg, cloakDialer{attempt, p})
				stop()
				if e != nil {
					return
				}
				defer remote.Close()
				done := context.AfterFunc(ctx, func() { remote.Close(); local.Close() })
				defer done()
				copied := make(chan struct{}, 1)
				go func() { _, _ = io.Copy(remote, local); copied <- struct{}{} }()
				_, _ = io.Copy(local, remote)
				remote.Close()
				local.Close()
				<-copied
			}()
		}
	}()
	return int64(ln.Addr().(*net.TCPAddr).Port), nil
}
func CloakStop() {
	cloakState.Lock()
	b := cloakState.b
	cloakState.b = nil
	cloakState.Unlock()
	if b == nil {
		return
	}
	b.cancel()
	b.listener.Close()
	b.mu.Lock()
	for c := range b.conns {
		c.Close()
	}
	b.mu.Unlock()
	b.wg.Wait()
}

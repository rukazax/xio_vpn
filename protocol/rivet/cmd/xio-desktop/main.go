package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
	"xio.local/rivet/internal/desktop"
)

type request struct {
	Method, ID, Protocol, Config string
	TimeoutMillis                int64
	SharingEnabled               bool
	SharingInterface             string
}

func run(r *desktop.Runtime, q request) (any, error) {
	switch q.Method {
	case "capabilities":
		return desktop.Protocols, nil
	case "sharingStatus":
		return r.SharingStatus()
	case "sharingSet":
		return r.SetSharing(q.SharingEnabled, q.SharingInterface)
	case "status":
		return r.Status(), nil
	case "disconnect":
		r.Disconnect()
		return map[string]bool{"ok": true}, nil
	case "connect":
		if !regexp.MustCompile(`^[a-z0-9]{1,80}$`).MatchString(q.ID) {
			return nil, errors.New("invalid profile identifier")
		}
		return r.Connect(q.ID, q.Protocol, q.Config, q.TimeoutMillis)
	default:
		return nil, errors.New("unsupported request")
	}
}
func envelope(v any, e error) map[string]any {
	if e != nil {
		return map[string]any{"ok": false, "error": e.Error()}
	}
	return map[string]any{"ok": true, "value": v}
}
func main() {
	stdio := flag.Bool("stdio", false, "private pipe, for isolated tests")
	listen := flag.String("http", "", "loopback address")
	tokenFile := flag.String("token-file", "", "one-time authentication file")
	flag.Parse()
	r := &desktop.Runtime{}
	defer r.Disconnect()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() { <-signals; r.Disconnect(); os.Exit(0) }()
	if *stdio {
		s := bufio.NewScanner(os.Stdin)
		s.Buffer(make([]byte, 4096), 262144)
		for s.Scan() {
			var q request
			e := json.Unmarshal(s.Bytes(), &q)
			var v any
			if e == nil {
				v, e = run(r, q)
			}
			_ = json.NewEncoder(os.Stdout).Encode(envelope(v, e))
		}
		return
	}
	host, port, e := net.SplitHostPort(*listen)
	if e != nil || host != "127.0.0.1" || port == "" {
		fmt.Fprintln(os.Stderr, "loopback address required")
		os.Exit(1)
	}
	stat, e := os.Lstat(*tokenFile)
	if e != nil || !stat.Mode().IsRegular() || stat.Size() != 64 {
		fmt.Fprintln(os.Stderr, "private authentication file required")
		os.Exit(1)
	}
	raw, e := os.ReadFile(*tokenFile)
	if e != nil {
		os.Exit(1)
	}
	key, e := hex.DecodeString(string(raw))
	if e != nil || len(key) != 32 {
		os.Exit(1)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, q *http.Request) {
		if q.Method != "GET" || q.Header.Get("Origin") != "" {
			http.Error(w, "denied", 403)
			return
		}
		nonce := q.URL.Query().Get("nonce")
		if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(nonce) {
			http.Error(w, "denied", 400)
			return
		}
		h := hmac.New(sha256.New, key)
		h.Write([]byte("XIO-019:" + nonce))
		_ = json.NewEncoder(w).Encode(map[string]string{"proof": hex.EncodeToString(h.Sum(nil))})
	})
	mux.HandleFunc("/rpc", func(w http.ResponseWriter, q *http.Request) {
		if q.Method != "POST" || q.Header.Get("Origin") != "" || !hmac.Equal([]byte(q.Header.Get("Authorization")), []byte("Bearer "+strings.TrimSpace(string(raw)))) {
			http.Error(w, "denied", 403)
			return
		}
		body, e := io.ReadAll(io.LimitReader(q.Body, 262145))
		if e != nil || len(body) > 262144 {
			http.Error(w, "too large", 413)
			return
		}
		var req request
		d := json.NewDecoder(strings.NewReader(string(body)))
		d.DisallowUnknownFields()
		e = d.Decode(&req)
		if e == nil && d.Decode(new(any)) != io.EOF {
			e = errors.New("invalid request")
		}
		var v any
		if e == nil {
			v, e = run(r, req)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(envelope(v, e))
	})
	server := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 70 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	if e = server.ListenAndServe(); e != nil {
		fmt.Fprintln(os.Stderr, "local engine service failed")
		os.Exit(1)
	}
}

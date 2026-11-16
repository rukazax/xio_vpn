package main

import (
	"bufio"
	"bytes"
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

// request is the existing capitalized transport envelope. Policy fields are the
// exact WIRE-V2 lowerCamelCase members promoted from desktop.PolicyRequest; the
// activation attachment stays the additional PolicyReceiptJSON string, so no new
// transport or second attachment shape is introduced.
type request struct {
	Method, ID, Protocol, Config string
	TimeoutMillis, RoundMillis   int64
	PolicyJSON                   string
	PolicyReceiptJSON            string
	SharingEnabled               bool
	SharingInterface             string
	Validation                   json.RawMessage
	desktop.PolicyRequest
}

func decodeRequest(body []byte) (request, error) {
	var decoded request
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return decoded, errors.New("invalid request")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return decoded, errors.New("invalid request")
	}
	if err := validatePolicyKeys(body, decoded.Method); err != nil {
		return decoded, err
	}
	return decoded, nil
}

// validatePolicyKeys enforces the agreed exact envelopes: begin/commit/reconcile
// are exactly eight keys, abort exactly three, policyValidate is the common eight
// plus `validation` (nine), and the read-only policy queries carry no identity
// fields. No extra field can be smuggled into a strict request.
func validatePolicyKeys(body []byte, method string) error {
	switch method {
	case "policyBegin", "policyCommit", "policyReconcile":
		return desktop.CheckExactObjectKeys(body, []string{
			"Method", "version", "storeIdentity", "controllerNonce", "instanceNonce",
			"transactionId", "expectedGeneration", "planGeneration", "plan",
		}, "request")
	case "policyValidate":
		return desktop.CheckExactObjectKeys(body, []string{
			"Method", "version", "storeIdentity", "controllerNonce", "instanceNonce",
			"transactionId", "expectedGeneration", "planGeneration", "plan", "validation",
		}, "request")
	case "policyAbort":
		return desktop.CheckExactObjectKeys(body, []string{
			"Method", "version", "instanceNonce", "transactionId",
		}, "request")
	case "policyCapabilities", "policyState":
		return desktop.CheckExactObjectKeys(body, []string{"Method"}, "request")
	}
	return nil
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
		timeout := q.TimeoutMillis
		if timeout == 0 {
			timeout = 30000
		}
		if err := r.DisconnectTimeout(timeout); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, nil
	case "policyCapabilities":
		return r.PolicyCapabilities()
	case "policyState":
		return r.PolicyState()
	case "policyBegin":
		return r.PolicyBegin(q.PolicyRequest)
	case "policyCommit":
		return r.PolicyCommit(q.PolicyRequest)
	case "policyReconcile":
		return r.PolicyReconcile(q.PolicyRequest)
	case "policyValidate":
		return r.PolicyValidate(q.PolicyRequest, q.Validation)
	case "policyAbort":
		return r.PolicyAbort(desktop.PolicyAbortRequest{
			Version:       q.Version,
			InstanceNonce: q.InstanceNonce,
			TransactionID: q.TransactionID,
		})
	case "connect":
		if !regexp.MustCompile(`^[a-z0-9]{1,80}$`).MatchString(q.ID) {
			return nil, errors.New("invalid profile identifier")
		}
		return r.ConnectWithPolicyReceipt(q.ID, q.Protocol, q.Config, q.TimeoutMillis, q.RoundMillis, q.PolicyJSON, q.PolicyReceiptJSON)
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
	storeIdentity := flag.String("store-identity", "", "product store identity binding (64 lowercase hex)")
	clientOnlyFlag := flag.String("client-only", "", "product build identity: true or false (mandatory with --store-identity)")
	flag.Parse()
	r := &desktop.Runtime{}
	// The launch client-only/build identity is never derived from the durable
	// document; the launcher must bind it explicitly alongside the store.
	if *storeIdentity == "" && *clientOnlyFlag != "" {
		fmt.Fprintln(os.Stderr, "client-only requires --store-identity")
		os.Exit(1)
	}
	if *storeIdentity != "" && *clientOnlyFlag != "true" && *clientOnlyFlag != "false" {
		fmt.Fprintln(os.Stderr, "explicit --client-only=true|false is required with --store-identity")
		os.Exit(1)
	}
	// The shared fixed-resource claim covers xio019 and its routes/receipts. Every
	// helper takes it for its whole lifetime, so two helpers for DIFFERENT product
	// stores cannot both observe clean and then both activate. A second helper
	// fails to start and must not be retried blindly.
	resourceClaim, err := desktop.ClaimResourceNamespace()
	if err != nil {
		fmt.Fprintln(os.Stderr, "shared resource claim failed:", err)
		os.Exit(1)
	}
	defer resourceClaim.Close()
	r.BindResourceClaim()
	if *storeIdentity != "" {
		// The launch binding and the RPC store identity must agree. Hold the
		// per-store cooperating helper claim for the whole process lifetime.
		if err := r.BindStoreIdentity(*storeIdentity); err != nil {
			fmt.Fprintln(os.Stderr, "invalid store identity binding:", err)
			os.Exit(1)
		}
		if err := r.BindClientOnly(*clientOnlyFlag == "true"); err != nil {
			fmt.Fprintln(os.Stderr, "invalid client-only binding:", err)
			os.Exit(1)
		}
		claim, err := desktop.ClaimHelper(*storeIdentity)
		if err != nil {
			fmt.Fprintln(os.Stderr, "helper ownership claim failed:", err)
			os.Exit(1)
		}
		defer claim.Close()
	}
	defer r.Disconnect()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() { <-signals; r.Disconnect(); os.Exit(0) }()
	if *stdio {
		s := bufio.NewScanner(os.Stdin)
		s.Buffer(make([]byte, 4096), 262144)
		for s.Scan() {
			q, e := decodeRequest(s.Bytes())
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
	server := &http.Server{Addr: *listen, Handler: newMux(r, strings.TrimSpace(string(raw))), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 70 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	if e = server.ListenAndServe(); e != nil {
		fmt.Fprintln(os.Stderr, "local engine service failed")
		os.Exit(1)
	}
}

// newMux builds the authenticated loopback surface. It is factored out so tests
// can exercise the real HTTP body limits without launching a helper.
func newMux(r *desktop.Runtime, tokenHex string) *http.ServeMux {
	key, _ := hex.DecodeString(tokenHex)
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
		if q.Method != "POST" || q.Header.Get("Origin") != "" || !hmac.Equal([]byte(q.Header.Get("Authorization")), []byte("Bearer "+tokenHex)) {
			http.Error(w, "denied", 403)
			return
		}
		// The authenticated body is read up to the larger validation budget and
		// then checked against the method-specific cap. Older methods keep the
		// 262144-byte logical limit; only policyValidate may use 3 MiB. The cap is
		// applied before decoding so an oversized old-format body is never parsed.
		body, e := io.ReadAll(io.LimitReader(q.Body, 3<<20+1))
		if e != nil || len(body) > 3<<20 {
			http.Error(w, "too large", 413)
			return
		}
		if len(body) > 262144 {
			var probe struct{ Method string }
			if json.Unmarshal(body, &probe) != nil || probe.Method != "policyValidate" {
				http.Error(w, "too large", 413)
				return
			}
		}
		req, e := decodeRequest(body)
		var v any
		if e == nil {
			v, e = run(r, req)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(envelope(v, e))
	})
	return mux
}

package xrayclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ProbeHTTPS authenticates remote data through this Xray session before exposing
// a TUN. It is independent of UID/CIDR policy and never dials the target directly.
// rootsPEM is the application's bundled public trust roots, not profile input.
func (s *Session) ProbeHTTPS(raw, rootsPEM string, budget time.Duration) error {
	if s.closed.Load() || budget <= 0 || budget > time.Minute {
		return net.ErrClosed
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if len(rootsPEM) > 32768 || !roots.AppendCertsFromPEM([]byte(rootsPEM)) {
		return errors.New("invalid probe roots")
	}
	ctx, cancel := context.WithTimeout(s.ctx, budget)
	defer cancel()
	return probeHTTPS(ctx, raw, s.dialAddress, roots)
}

func probeURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || len(raw) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("invalid HTTPS probe URL")
	}
	return u, nil
}
func probeHTTPS(ctx context.Context, raw string, dial func(context.Context, string) (net.Conn, error), roots *x509.CertPool) error {
	u, e := probeURL(raw)
	if e != nil {
		return e
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}, DialContext: func(c context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, errors.New("invalid probe network")
		}
		return dial(c, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 4 {
			return errors.New("probe redirect limit")
		}
		_, err := probeURL(req.URL.String())
		return err
	}}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if e != nil {
		return e
	}
	req.Header.Set("User-Agent", "XIO connection check")
	response, e := client.Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return errors.New("HTTPS probe status rejected")
	}
	_, e = io.CopyN(io.Discard, response.Body, 1024)
	if e == io.EOF {
		return nil
	}
	return e
}

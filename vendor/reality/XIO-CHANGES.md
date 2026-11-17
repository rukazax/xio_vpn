# XIO changes to github.com/xtls/reality

Base: `github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f`
(MPL-2.0; original files and notices retained unchanged).

## Why this directory exists

The pinned REALITY release parses the decoy target's TLS flight with a fixed
8 KiB buffer (`size = 8192` in `tls.go`). A target whose TLS `Certificate`
record is larger than that buffer — `www.microsoft.com` returns an 8273-byte
record, i.e. 81 bytes over — is rejected with `REALITY: processed invalid
connection …: handshake did not complete successfully`, for **every** client,
because the substituted certificate can never be built. The failure looks like
a client authentication problem but is a target-size limit.

## Change

`tls.go`: `size = 8192` → `size = 17 * 1024` (matches the buffer of the
current upstream REALITY implementation). No cryptographic code, wire format,
authentication or validation logic is modified; the buffer only bounds how much
of the decoy's first flight is accepted.

## Build integration

`vendor/xray/go.mod` and `protocol/rivet/go.mod` replace
`github.com/xtls/reality` with this directory, so both the server gateway
(`xio-stack`) and the Android runtime are built from the patched source.

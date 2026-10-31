# internal/xiofirewall

Project-local, fail-closed Windows Filtering Platform (WFP) policy for the XIO
desktop engine. Import path:

```go
import "xio.local/rivet/internal/xiofirewall"
```

This package is a **minimal adaptation** of
`golang.zx2c4.com/wireguard/windows/tunnel/firewall` at **v1.0.1**. The
upstream MIT headers are preserved verbatim in every file; only the delta
listed below differs from the pinned source. Original files are unchanged in
the module cache, so no backup of an existing tree was needed and no existing
file was overwritten.

## Defect being fixed

`golang.zx2c4.com/wireguard/windows@v1.0.1/tunnel/firewall/helpers.go`
(lines 74–100, `getCurrentProcessSecurityDescriptor`) looks for a service SID
in the current process token: an enabled group with NT authority, at least six
sub-authorities and sub-authority 0 equal to `80` (`S-1-5-80-*`,
`RtlCreateServiceSid`). WireGuard always runs that code inside its service.
The XIO engine is an elevated interactive desktop executable, whose token has
no such group, so the helper returned `ERROR_NO_SUCH_GROUP`. Because
`EnableFirewall` wraps the whole installation in one transaction and aborts on
error, the firewall never came up.

The provider/sub-layer registration was never the problem:
`blocker.go` already creates its own GUID provider and a `^uint16(0)`-weight
sub-layer inside a `FWPM_SESSION_FLAG_DYNAMIC` session.

## Delta from upstream v1.0.1

1. **Package identity** — `package firewall` becomes `package xiofirewall`;
   every file carries a `//go:build windows` constraint (and
   `windows && (amd64 || arm64)` / `windows && (386 || arm)` on the layout
   files) so non-Windows `go list ./...` stays clean.
2. **Identity permit** (`helpers.go`, `rules.go`) — the owning-process permit
   now uses the current token **user SID** instead of a service SID:
   - `currentProcessUserSID()` reads `GetTokenUser().User.Sid`.
   - `getCurrentProcessUserSecurityDescriptor()` builds a self-relative
     security descriptor whose only ACE grants `FWP_ACTRL_MATCH_FILTER` to that
     user SID (`TRUSTEE_IS_USER`).
   - `permitOwningProcess()` (renamed from `permitWireGuardService`) pairs the
     `ALE_USER_ID` condition with the existing `ALE_APP_ID` condition through
     `identityConditions()`. Together they match **this executable, run by
     this user**, not the whole user session.
   - Any failure to resolve the identity aborts the enclosing transaction, so
     the policy stays fail-closed; there is no permissive fallback.
3. **Session serialization** (`blocker.go`) — `EnableFirewall`/`DisableFirewall`
   are guarded by a mutex so two concurrent enables cannot leak a handle or
   report a false "already enabled" state. The session remains
   `FWPM_SESSION_FLAG_DYNAMIC`: closing the handle or exiting the process
   removes every provider, sub-layer and filter.
4. **Display names** — WFP objects are named `XIO` instead of `WireGuard` so
   diagnostics can tell the two engines apart. GUIDs are still generated per
   session.
5. **Documentation** — this README and `doc.go`.

Everything else is byte-for-byte upstream: filter weights (engine 15, DNS
15/14, loopback 13, TUN/DHCP/NDP 12, block 0), the physical IPv4/IPv6 blanket
block, the `CLEAR_ACTION_RIGHT` permits, DHCPv4/v6 and NDP permit conditions,
the optional DNS-server allow list, the transaction wrapper and the
`runtime.KeepAlive` lifetimes of pointers passed to WFP.

## Policy installed by `EnableFirewall(luid, false, nil)`

| Weight | Filter |
| --- | --- |
| 15 | permit this executable **and** this user SID (4 layers) |
| 13 | permit loopback (4 layers) |
| 12 | permit TUN by interface LUID (4 layers) |
| 12 | permit DHCPv4 request/response |
| 12 | permit DHCPv6 request/response, link-local only |
| 12 | permit NDP 133/134/135/136/137 |
| 0 | block all other IPv4/IPv6 inbound and outbound |

DNS: with `restrictToDNSServers` non-empty, DNS (TCP/UDP 53, both families) is
blocked at weight 14 and allowed only towards the listed resolvers at weight
15. With an empty list DNS falls under the weight-0 block, so no query can
leave outside the tunnel.

`doNotRestrict=true` installs only the engine permit and no block; XIO always
passes `false`.

## Integration

`internal/desktop/network_windows.go` still imports
`golang.zx2c4.com/wireguard/windows/tunnel/firewall`. The parent owns that
file; the switch is exactly two lines:

```go
// line 8
"xio.local/rivet/internal/xiofirewall"
// lines 73-74
enableFirewall:  xiofirewall.EnableFirewall,
disableFirewall: xiofirewall.DisableFirewall,
```

`EnableFirewall(uint64, bool, []netip.Addr) error` and `DisableFirewall()` keep
the upstream signatures, and `luid` is still a raw `uint64` (winipcfg LUID
cast), so no call-site changes are required.

## Verification

Executed on `go1.27.2 windows/amd64` against this tree:

```
gofmt -l internal/xiofirewall        # empty
go vet ./internal/xiofirewall        # ok
go test ./internal/xiofirewall -v    # 6/6 PASS, no WFP objects touched
GOOS=windows GOARCH=amd64 go build ./internal/xiofirewall   # ok
GOOS=windows GOARCH=arm64 go build ./internal/xiofirewall   # ok
GOOS=windows GOARCH=386  go build ./internal/xiofirewall    # ok
GOOS=windows GOARCH=arm  go build ./internal/xiofirewall    # unsupported pair in Go 1.27.2
```

Tests never call `EnableFirewall`: there are no live WFP, adapter, route or
host-policy mutations. They verify that a plain desktop process resolves its
user SID without `ERROR_NO_SUCH_GROUP`, that the self-relative DACL contains
exactly one access-allowed ACE with mask `FWP_ACTRL_MATCH_FILTER` for the token
user, that the APP_ID blob resolves, and that the two ALE conditions are
wired correctly. A disposable elevated host is still required to accept the
installed policy end to end.

## Provenance

Source: `golang.zx2c4.com/wireguard/windows v1.0.1`, directory
`tunnel/firewall`, module zip SHA-256
`62d67e1e13e78f24087ac79808f8a6a1d802940a02b40e1e03a20a7b2df2f07b`,
`go.sum` h1 `eOxiDVbywPC+ZQqvdCK7x+ZwWXKbYv50TtH8ysFIbw8=`.

SHA-256 of the pinned upstream files copied here
(`types_windows_test.go` was not copied):

```
blocker.go            f1d90254538abf233998ab9e5d824d055deea6ab894bd28f100f6cf0e7524267
helpers.go            43a3fb8b60ac6a8c91406170bd76e7e714932b547f5e8c90b0e5c480f66ee3a5
mksyscall.go          cbaa18412cb9a661041a62ee3c8a598fb83d87c411bdb60b1a43b06b4e1176a4
rules.go              c2bf0016dc09e56c8d2ad52b6ee9d5758681581c4cb431e65bab27e696b2e22b
syscall_windows.go    8b7f3cfa4907f93ea38bdf888a94ff788c467f5204d8efa79b09d0aa8fc4d65b
types_windows.go      67b58c70ebbb213b5e17922294b739318404de73904a2a6ba72d362ffd635354
types_windows_32.go   e808b269b597ac95b9a120f8eb6fa3b121861ae98f60ed61a0e0c57066dc6198
types_windows_64.go   191666d97a49cf505c2343e64847ea7749e92ac4e62f399b224c0e76437563d4
zsyscall_windows.go   884475f84b71d22b4d150bba062a9b12e6238c371ccbaafeac5b8c490b8f24b5
```

`zsyscall_windows.go` remains generated code; its `//go:generate` line is kept
in `mksyscall.go`. Regenerating requires
`golang.org/x/sys/windows/mkwinsyscall` from the module graph.

License: MIT, `Copyright (C) 2019-2026 WireGuard LLC. All Rights Reserved.`
The XIO adaptation keeps the same license; update `THIRD-PARTY-0.22.md` (or the
next notice revision) when this package ships.

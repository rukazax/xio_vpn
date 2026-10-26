# XIO Client 0.22.5: native Windows check and IPv6 on a real test stand

Date: 2026-10-26. Release 0.22.5+5014 continues 0.22.4 and closes two defects that were found on
real hardware rather than in unit tests.

## What this run verified

Stand: Debian 13 (`192.168.88.17`), a physical POCO X6 5G (Android 16) and Windows 11 x64.
The server was installed from the app's own bundle (recipe 24); the client was built from source and
signed with the publisher certificate.

| Check | Result |
|---|---|
| Android, AmneziaWG, IPv4 endpoint | connected, HTTP 200, traffic |
| Android, AmneziaWG, IPv6 endpoint | connected, HTTP 200, `ping6` to the tunnel gateway 0% loss |
| Android, RIVET/H3 and S1 | connected, HTTP 200, 31.0/18.9 KB, server reports the user online |
| Android, Xray/REALITY | **does not connect** — see below |
| Windows x64, AmneziaWG | native Wintun tunnel: `xio019` adapter, 10.78.0.7/32, ping 3/3, handshake, 496 KB in / 2.9 MB out |

## Defect 1: re-importing a profile after deletion

Deleting a profile left a dangling reference in the user record, so importing the same `xio://`
container again was rejected as “user already added” even though no profile existed on the device.

Fixed in `app/lib/core.dart`: removing a profile now drops the reference from every user and rolls
back from a snapshot if the write fails. `forgetServer()` and `revoke()` iterate a copy, because the
removal now mutates the collection they walk.

A regression test, `app/test/profile_removal_test.dart`, fails on the previous code and passes on
the fixed one.

## Defect 2: the IPv6 firewall rule on Windows

To block IPv6 traffic while the tunnel is up, the helper called
`netsh advfirewall firewall add rule ... remoteip=::/0`. Current Windows 11 rejects a zero-length
prefix (“one or more address prefixes are invalid”), so connecting failed with “Windows VPN firewall
setup failed” — the Windows client could not connect at all.

Verified manually: `remoteip=::/0` and `remoteip=0.0.0.0/0` are rejected, while
`remoteip=::/1,8000::/1` is accepted and covers the same range. Fixed in
`protocol/rivet/internal/desktop/network_windows.go`.

## Known limitation: Xray/REALITY

The server (Xray `26.7.28`) logs `REALITY: processed invalid connection … handshake did not complete
successfully`; the client core is the `amnezia-xray-core v1.260728.0` fork. REALITY keys, `shortId`
and `serverName` were verified to match, and lowering `minClientVer` to `1.0.0` does not help. The
REALITY implementation itself is incompatible, not a single version check. Until the cores are
aligned, Xray must not be counted as working on this client/gateway pair. AWG and RIVET work.

## IPv6: exactly what was proven

The test network has no public IPv6 (the router advertises no prefix), so a local ULA
`fd88:17::/64` is advertised by radvd without a default route — the phone gets an address and the
internet path is unchanged. Confirmed: the client connects to `[fd88:17::1]`, receives
`fd78:1::N/128` inside the tunnel and `ping6` to the tunnel gateway succeeds.

IPv6 egress is still blocked by the server itself (`ip6tables FORWARD -i x1oawg0 -j DROP`, no
NAT66). That is deliberate behaviour rather than a defect, but it is not public dual-stack.

## Screenshots

![Windows client home](images/2026-10-26-win-windows-home.png)

![Imported profile](images/2026-10-26-win-windows-profile.png)

Android screenshots are not included: the app sets `FLAG_SECURE`, so the system returns a black
image. That confirms the advertised protection but rules out screenshots.

## Next

- Align the Xray core (client vs gateway) or drop Xray from the declared matrix until verified.
- Run the full GUI connect flow on Windows (this run exercised the engine over the same IPC the UI
  uses).
- Investigate coexistence with a second VPN: with a foreign VPN holding `/1` routes the XIO tunnel
  comes up but the handshake never completes.

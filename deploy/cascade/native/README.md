# Native SSH-TUN cascade (bridge RU → exit foreign)

This directory installs the cascade that was verified on 17.11.2026:
phone → `81.177.142.37` (RU bridge) → `103.102.135.124` (foreign exit).
It is **not** the Docker/kernel-WireGuard payload in the parent directory.

## Files

| File | Role |
|---|---|
| `xio-cascade-exit-up.sh` / `-down.sh` | exit: `tun0` 10.250.0.2/30 + fd78:2::2/64, forwarding, NAT44/NAT66 |
| `xio-cascade-bridge-up.sh` / `-down.sh` | bridge: `tun0` 10.250.0.1/30 + fd78:2::1/64, `ip rule iif xioawg0`, SNAT, MSS clamp |
| `xio-cascade-exit.service` | exit oneshot, `RemainAfterExit=yes` |
| `xio-cascade-bridge.service` | bridge SSH client `ssh -N -w 0:0`, restarts on failure |

## Install order

1. Exit: copy the two scripts to `/usr/local/sbin/`, the unit to
   `/etc/systemd/system/`, then `systemctl enable --now xio-cascade-exit`.
2. Bridge: same for its scripts/unit; write
   `/etc/xio-cascade/bridge.env` with `XIO_CASCADE_EXIT_HOST=<exit-ip>`;
   `systemctl enable --now xio-cascade-bridge`.
3. SSH trust: `PermitTunnel yes` on exit; bridge key
   `/root/.ssh/xio_cascade` authorized in exit `authorized_keys`.

The scripts are idempotent: `systemctl restart` recreates rules without
duplicating them.

## Why `iif`, not `fwmark`

A firewall mark on a forwarded client packet is inherited by the encapsulated
WireGuard/UDP packet and can route the encapsulation back into the tunnel. The
working rule is `ip rule add iif xioawg0 lookup 51888 priority 1000`.

## Verified limits

- SSH TUN is TCP-over-TCP. With BBR on the bridge and 16 MiB buffers it reached
  69.3 Mbit/s for 20 MiB; without BBR it collapsed to 1.5 Mbit/s on the same
  path (≈8 % loss).
- WireGuard between the two hosts completed a handshake but its transport
  packets were lost on this route; SSH TUN is the fallback that worked.
- The app UI still installs only the bridge; there is no one-button pair
  installer yet.

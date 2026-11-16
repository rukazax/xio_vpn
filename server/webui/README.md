# XIO WebUI — bounded contract repair

TLS owner panel, one Python standard-library backend and one inline HTML/JS page.
This is a **partial WebUI repair**, not completion of all provisioning features.

## Implemented and pending

- Managed inspection/status, immutable-ID user revocation and fixed allowlisted
  service commands use the actual owner managed-admin JSON protocol.
- **User creation is pending a durable client issuance/delivery workflow.** The
  old name-only form is removed; `/api/user/add` returns `ISSUANCE_PENDING` before
  any command. No user or key is created. Public-key-only input is not a complete
  XIO client profile; there is no fabricated key or server-private-key shortcut.
- Legacy RIVET gateway Start/Stop controls only `xio-rivet-gateway`. Stopping it
  interrupts RIVET clients. Service command success is not tunnel/native health.
- Native cascade is **informational only**: inspect with pinned identity; enabled,
  phase, guard provenance, infrastructure and fresh family evidence are separate.
  Missing/stale evidence is not healthy. GET never verifies/probes/configures,
  reconciles or removes native state. Two-host setup and explicit direct-mode
  removal remain separate owner-coordinator work.
- Source/mock tests do not certify installed systemd/runtime behavior or release
  artifacts. Unsupported/untested deployment variants must not be advertised as
  working merely because optional write paths exist.

## API / wire contract

Bearer token or `xio_sid` cookie authenticates the **owner**; there is no browser
actor/delegate selector. Every POST also requires `X-XIO-CSRF` from authenticated
`GET /api/state`. No CORS relaxation. Default listener is `127.0.0.1:10443` over TLS.

| Method / path | Request / result |
|---|---|
| GET `/`, `/index.html` | Static panel |
| GET `/api/health` | Public panel process health, not managed tunnel health |
| GET `/api/state` | `schema:1`, managed availability, safe server/users/traffic/service/native projection |
| POST `/api/user/revoke` | Exact `{expectedServerId,id}`; id is lower-case 32-hex UID, never display name |
| POST `/api/user/add` | Explicit unsupported issuance workflow; no effects |
| POST `/api/service/start\|stop\|restart` | Exact `{expectedServerId}` plus `X-XIO-Unit` from fixed unit allowlist |
| POST `/api/cascade/enable\|disable` | Legacy alias, exact `{expectedServerId}`, fixed RIVET gateway start/stop only |

All browser mutations capture identity from the **rendered control**, not the
latest global/server state. Backend never substitutes the current deployment ID.
Managed owner CLI receives `[python, admin.py]` with action inside stdin JSON,
not in argv. The service action is owner-only and uses the same managed CLI lock
and deployment-ID guard as revoke. Only five exact units and start/stop/restart
are accepted; no shell, arbitrary argv, unit/path, actor or command proxy.

Success requires both zero process exit and top-level boolean `ok:true`, then an
exact action-specific result: e.g. revoke must return the requested UID. Raw
backend/config/key output never becomes an HTTP error or generic `data` passthrough.
Errors use fixed messages and finite `errorCode`, `outcomeUnknown`, HTTP `code`.
HTTP 2xx alone, a JSON scalar, missing/false `ok` or nonzero success JSON is NOT
success. Existing auth errors remain their original HTTP/error envelope.
The browser independently checks the original submitted target: revoke HTTP data
must be exactly `{revoked,serverId}`; service data is `{service:{serverId,unit,verb}}`
(including legacy gateway aliases). Missing/conflicting confirmation stays UNKNOWN;
it cannot clear the pending marker. The HTTP revoke serverId is bound to the
successful managed guard's submitted identity, not a later inspection.

Requests are capped at 64 KiB HTTP and 32768 bytes encoded admin input. Admin
stdout is captured intact up to 16 MiB; excess/invalid UTF-8/JSON, duplicate keys
or nonfinite numbers fail explicitly. Stderr is discarded. Separate pipe reader
and bounded input writer share the admin deadline (20 seconds); failed/expired
POSIX admin sessions are killed, not retried. This does not roll back effects.
Legacy read-only systemctl display commands retain their existing timeout/clip.
Large deployments beyond the output budget show unavailable, not partial users.

## State and uncertainty

GET first inspects A, then requests status with A, and rejects inconsistent IDs.
A conflicting native-inspect identity also invalidates the whole managed snapshot;
optional native-module unavailability without identity conflict remains distinct.
Login, manual refresh and timer observations share one request sequence: an older
success or auth failure cannot overwrite a newer observation in the same session.
A reinitialized deployment cannot be silently substituted. Failed observations
show unknown users/traffic and invalidate mutation context, never fabricated zero.
An empty successful list is known zero. Names need not be unique; UID is retained.
Traffic sums returned server RX/TX protocol counters (server received/sent), with
sample timestamp; missing/invalid counters stay unknown. These are observed server
counters, not guaranteed end-to-end delivery or billing. Whitelists have no managed
contract here and remain unavailable. **Status samples and saves counters**; GET
is observational at the product level, not literally zero filesystem writes.

A timeout, lost reply, inconsistent envelope, or generic mutating nonzero exit
without a typed no-effects guarantee is **PARTIAL / UNKNOWN**. `revoked:true` in
status alone does not prove every runtime peer/credential was removed: deployment
save occurs before final apply/reload. No automatic retry, compensating revoke,
rollback or direct fallback. Successful mutation and a later failed GET are
separate outcomes.

Before submission, the page stores only non-secret operation/target metadata in
sessionStorage. Duplicate submission is suppressed; uncertain outcomes remain
sticky across polls/reload/logout in that tab and block further mutations.
An independent operator must reconcile protocol runtime state; the UI does not
pretend a registry refresh resolves uncertainty. The marker is not a durable
server operation receipt and can be lost when the browser session is discarded.
Do not restart issuance/revocation blindly after losing a browser session. No
automatic “clear unknown” button is supplied because this panel cannot establish
all-protocol runtime reconciliation. Full durable owner workflows remain pending.

## Security / installation

TLS >=1.2, no compression; bounded TLS admission/handshake/HTTP deadlines; token
comparison with HMAC-safe comparison; cookie Secure/HttpOnly/SameSite=Strict;
12-hour session policy; CSRF on POST; five auth failures trigger rate limiting.
No-store, nosniff, frame denial, referrer policy, CSP and fixed service allowlists
are preserved. Logs omit token/cookie/request bodies and raw command errors.
There is no newly claimed Host-header allowlist. Reverse-proxy/public deployment
policy is unchanged: do not expose the raw administration port to the internet;
use a trusted HTTPS proxy and restrict access. X-Forwarded-For is not trusted for
rate limiting. Do not enable arbitrary browser-selected command identities.

The installer still copies exactly the backend, page, unit and README; no new
runtime dependency/module/build step. Ordinary installation (not a test command):

```bash
sudo ./install-webui.sh                 # default loopback TLS
```

The installer prints the token and certificate fingerprint to its operator;
protect that output. The backend generates a token/certificate beside itself on
first startup, so tests must never import it directly from the installed/source
directory. Keep existing credentials/certificates during an upgrade. Source-only
changes do not update an already installed service until separately deployed.

### Narrow writable-path inventory (sensitive; runtime unverified)

`ProtectSystem=full`, `ProtectHome=read-only` and the other unit hardening remain.
Optional `ReadWritePaths=-...` avoid failing startup when a variant is absent;
they do not enable that feature or prove it works. No whole `/etc` or home grant.

| Path / runtime boundary | Reason |
|---|---|
| `/etc/xio-managed` (existing exception) | Counter/deployment save and atomic replacement |
| `/etc/xio-stack` | Xray config, Cloak config/receipt, optional PKI CRL/certificate updates and IKE configs/symlinks |
| `/etc/xio-rivet` | RIVET CLI lock and atomic users/tokens updates; `/var/lib/xio-rivet` alone was insufficient |
| `/etc/wireguard` | Optional unrestricted WG config before `wg syncconf` |
| `/etc/xio-mesh` | Optional mesh statistics file |
| `/root/.ssh` | **Sensitive** owner admin-revoke grant: authorized_keys is atomically replaced via a sibling temp file, so parent-directory access is required; not a whole-home grant |
| Runtime sockets/kernel/systemd | AWG UAPI removal, WG syncconf, OpenVPN management kill, IKE terminate/load-creds/load-all, mesh Headscale operations, Cloak/Xray restart/check |

Static tests validate exact exceptions and preserved hardening. A separately
approved disposable installed-runtime gate must verify namespaces, capabilities,
Unix sockets, PKI/SSH replacement, all advertised protocol effects and SELinux/
AppArmor policy. Partial failure must remain unknown; never remove the sandbox
wholesale to make a green button. Live install/reload was not part of this repair.

## Tests

```bash
python3 -B server/webui/test_contract.py
node server/webui/test_frontend.cjs
python3 -B -m unittest discover -s server/webui -p test_webui.py -v
```

Contract tests AST-load actual definitions and exercise real Handler byte streams,
actual CLI admission/envelope branch and actual dispatch with commands/state fully
mocked. No root check/flock/main is launched. Frontend tests execute actual inline
JS with deterministic DOM/fetch fixtures. The existing six TLS tests are unchanged
and copy source into a temporary token directory, using only an ephemeral loopback
listener and bundled fixture certificates. Run those only in an authorized test
scope; they are not live deployment validation. Also retain existing managed
admission/authority/native RPC contract regressions. Independent review required.

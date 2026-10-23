# XIO Client 0.22.2

A separate, smaller Android client based on the current XIO 0.22.2+5006 application. Package ID: `app.x1o.client`; it coexists with the full app and has independent data. The client UI is Russian; legal and privacy documents are provided in Russian and English.

It imports existing client profiles, connects to the explicitly selected server and switches profiles only after confirming the previous tunnel stopped. Retained engines: AmneziaWG, Xray, RIVET/S1, RIVET/H3 and internal OpenVPN/Cloak. Removed standalone protocols are not restored. There is no server deployment, SSH administration, server administration, VPN sharing, endpoint geolocation, startup telemetry or external update installer. Administrative profiles are rejected. Android Keystore-backed encrypted profile storage, no-backup settings, separate legal/VPN acknowledgements and system VPN permission are retained. Screenshots are blocked with FLAG_SECURE.

Split tunnelling supports all applications, selected applications through VPN, selected applications bypassing VPN, or separate IPv4/IPv6 CIDR include/exclude modes. Rules apply across profiles and require disconnecting before changes. Domain routing and simultaneous app/IP policies are not supported. Android lockdown can prevent bypass. The app picker lists visible launchable applications; shared UIDs and work profiles require separate validation. Manual server switching has a gap without VPN unless system lockdown blocks direct traffic. A website availability probe can bypass VPN when the client itself is excluded; it does not establish protection of other applications.

Android 8.0 / API 26 or newer is required. Builds cover ARM32 (`armeabi-v7a`), ARM64 (`arm64-v8a`) and x86-64, with a universal APK containing all three. Earlier Android versions and 32-bit x86 are unsupported. Compatibility with every device or vendor firmware is not claimed. Import a client profile obtained from the existing server administrator; no private credentials or public server directory are embedded.

Build from the matching complete source tree and pinned native/vendor components:

```sh
python3 client/build.py
```

This stages the current app in `.build-support/client`, strips server assets and extra bundled fonts, adjusts only the staging manifest, builds `lib/client_main.dart` with `XIO_CLIENT_ONLY=true`, and uses an independent native `BuildConfig.CLIENT_ONLY` capability guard. It requires the installed Flutter/Android toolchain and locally configured signing in `.signing/signing.properties`; signing credentials are never included in reports. Native build provenance remains in `native-sources/android-runtime-0.22` and `docs/en/build.md`.

Four APKs are copied to `releases/client-0.22.2`. `client/verify.py` checks the package ID, all launcher aliases, removed update components/installer permission, the asset allowlist, absent SSH/geolocation strings in Dart AOT, APK signature, ZIP/ELF alignment and matching allocated native payload sections. Outputs include `verification.json`, `SHA256SUMS` and hashed `source-inputs.json`.

Previous 0.22.1 baseline validation: clean analysis of affected Dart files; five new client-specific tests; 32 passing related regression tests; 15 passing client-mode client/consent/routing tests (overlapping suites); production CIDR checks covering IPv4/IPv6 boundaries, invalid literals, scope intersections and 20,480 complement samples. No physical Android device or real VPN server was contacted. Actual device tunnelling, per-app routing and Always-on behaviour remain unverified. RIVET transports remain experimental; no blanket blocking-resistance, anonymity or independent cryptographic audit is claimed.

## 0.22.2: shared home screen and account-scoped subclients

The home screen now shares `app_theme.dart` with the full app: 230px circular connection control, status, compact split routing, selected-server card and RX/TX. The small primary Noto Sans font is included; CJK remains excluded.

Ordinary VPN profiles cannot create subclients. An explicitly issued schema-3 account profile enables the Subclients page. Live server status supplies used/remaining quota; only that account’s children can be created or revoked. Children receive VPN keys only, never the parent API capability or SSH/root/admin keys. The Android native readConfig/deleteConfig channels now reject non-profile IDs, including SSH vault entries. Child sharing uses a cache-only FileProvider.

Existing deployments need server recipe 21 and a newly issued client account profile. The owner uses the updated FULL Android app 0.22.2, disconnects VPN, selects a user with positive userLimit and chooses Share. An explicit confirmation describes the separate HTTPS API on TCP 9444 and rotation of that account’s token. Owner SSH identity is verified in the full app only. No VPS was changed during this task. Provider firewalls must also permit TCP 9444; systemd, OpenSSL, useradd/nologin and existing iptables/ip6tables are required. The public TLS frontend runs as a dedicated unprivileged account; a separate privileged dispatcher is reachable only over a local UNIX socket and independently checks the token, revocation, exact actions, ownership and quota under the deployment lock.

A random 256-bit API token is stored as a hash on the server and encrypted in Android Keystore-backed storage. The profile contains only endpoint, public certificate hash, token and account/server IDs. TLS pins the exact certificate, host/port and validity period, without redirects or token forwarding. The separate self-signed API certificate lasts 365 days; owner renewal/replacement requires new client pins/profiles. [Dart SecurityContext](https://api.dart.dev/dart-io/SecurityContext/SecurityContext.html), [certificate callback](https://api.flutter.dev/flutter/dart-io/HttpClient/badCertificateCallback.html).

Creation persists the operation ID and new client VPN keys before sending. An explicit reconciliation request reuses exactly those parameters. Completed operations return the same response; pending operations after a server crash require owner reconciliation and are never blindly repeated. Revoked child response secrets are pruned. Reimporting a renewed parent capability preserves pending state.

Validation includes 26 server unit tests, TLS mismatch/redirect tests, quota/ownership/concurrency checks, schema/root-field rejection, child export isolation and timeout recovery with unchanged operation IDs and keys, plus Flutter regressions and APK checks. No physical Android, live deployment or external cryptographic audit was performed. The bounded HTTPS frontend uses Python http.server, which [Python does not recommend for production](https://docs.python.org/3/library/http.server.html). The server component is preliminary and needs separate installation/load validation and a production transport review before mass deployment.

Final 0.22.2 validation: clean `flutter analyze`; 110 Flutter tests passed, 5 skipped; separately 10 client-mode tests and 26 server tests passed. Wire checks cover UTF-8 JSON with fixed Content-Length across a local UNIX socket. Screen previews use synthetic profiles.

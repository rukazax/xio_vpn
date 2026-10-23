# XIO Client 0.22.3

A lightweight client for existing VPN servers. Version 0.22.3+5012, package `app.x1o.client`. It installs alongside full XIO. The home screen uses the same theme: a large connection button, status, server picker, protocol and traffic counters. The interface and documentation support Russian and English.

## Connect

1. [Download an APK](https://github.com/rukazax/xio_vpn/releases/tag/v0.22.3). Android 8.0/API 26 or newer; ARM32, ARM64, x86-64 or universal. Physical tests cover a POCO X6 5G running Android 16/ARM64. Every device or firmware has not been tested.
2. Obtain a client profile from the server owner. Choose Add profile, paste a key or select a file. No third-party servers or credentials are embedded.
3. Select a connection and grant Android VPN permission. Supported transports are Xray/REALITY, RIVET/H3, RIVET/S1, AmneziaWG and OpenVPN/Cloak. The client connects the selected profile without silently choosing another protocol.
4. Confirm a switch while connected. The previous tunnel stops first. Traffic may leave without VPN between connections; Android's block-connections-without-VPN setting is separate.

## Split tunnelling

Disconnect VPN, open the rule on the home screen and save a mode: all apps, selected apps through VPN, selected apps bypassing VPN, selected IP/CIDR destinations through VPN, or selected IP/CIDR destinations bypassing VPN. Rules apply across this application's profiles. App selection and IP selection are separate modes. CIDR lists do not accept domain names.

Excluded traffic goes directly when Android lockdown allows it. DNS comes from the profile: when including individual destinations, include the required DNS server or use a suitable reachable resolver. A VPN status alone does not prove every application's route. Physical checks use a separate QA application to observe the actual exit address.

## Account-scoped subclients

An ordinary VPN profile cannot create other clients. The owner updates the server to recipe 24 with full XIO 0.22.3, creates an account with a positive quota and selects Share. Confirmation explains the separate HTTPS API on TCP 9444 and rotation of the account's previous token. Provider firewalls must also allow that port.

The client separately confirms importing this restricted account. Only that profile exposes Subclients. Every operation checks quota, revocation and child ownership on the server. A new child receives only its own VPN profiles, without the parent token or further delegation rights. Revocation restores quota and blocks another connection by the revoked client.

The client does not provision VPS servers, administer them over SSH, accept root/admin keys or bundle server archives. Administrative profile fields are rejected. Account access contains only an HTTPS endpoint, public certificate fingerprint, restricted token and identifiers. The client pins the exact certificate and its validity period and does not follow redirects. Renewing the separate API certificate requires owner action and reissued profiles with the new fingerprint.

VPN keys and tokens remain sensitive. Android Keystore/AES-GCM protects local storage, backups are disabled, and FLAG_SECURE remains enabled. Deleting a local profile does not revoke server access. Export uses a non-exported FileProvider and a temporary read grant for the selected file.

A lost response retains the same operation ID and keys. Checking an unfinished creation does not issue a different creation ID. A server-side pending operation after a crash requires owner reconciliation and is never blindly repeated.

## Verification and limits

[Physical/local test matrix, images and both app diagrams](../docs/dualstack/0.22.3.en.md). General Flutter suite: 113 passed, 6 skipped; client mode: 13 passed; server: 31 passed. Suites overlap. Public IPv6 remains unverified because the authorized VPS has no IPv6 route. IPv6 packets and server rules passed in an isolated local network. No full security audit, load, battery-life or universal blocking-resistance claim is made. The API remains preliminary and needs a separate production transport review before mass deployment.

Build: `python3 client/build.py`. Verify: `python3 client/verify.py`. Exact native runtime: `native-sources/android-runtime-0.22.3`. APKs, signatures, dependency inputs and checksums accompany the release. Private signing keys are excluded.


The five-protocol matrix in both apps (20 HTTPS checks) ran on build 5011. Final build 5012 uses the unchanged native engine/AAR and adds secret-free tile lifecycle logs. Build5012 separately passed the tile primary connect/disconnect commands, independent VPN HTTPS and a client Xray control. This does not represent a rerun of the entire matrix on 5012.

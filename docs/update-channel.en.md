# XIO update channel: releasing and verifying

[Русский](update-channel.ru.md) · [User-facing updates](en/updates.md) · [Build](en/build.md)

The in-app update channel was dead since 0.22.2: releases `v0.23.0`, `v0.23.1`, `v0.24.0`,
`v0.24.1` and `v0.24.2` carried no `XIO-update.json` asset, so the application offered no
update on any platform. This page documents the check, the release procedure and what a user
sees when the manifest is missing.

## What the application actually reads

```mermaid
flowchart TD
    A[Check due or button pressed] --> B[GET api.github.com/repos/rukazax/xio_vpn/releases?per_page=30]
    B --> C{Is there a vX.Y.Z tag newer than the installed version?}
    C -->|No| D[Next check in 7–8 days]
    C -->|Yes| E{Does the release carry exactly one XIO-update.json asset?}
    E -->|No| D
    E -->|Yes| F[GET the manifest from browser_download_url]
    F --> G[Ed25519 signature with the pinned key + payload parse]
    G --> H{tag matches, build greater than installed?}
    H -->|No| D
    H -->|Yes| I[assets[platformKey] → size and SHA-256]
    I --> J[Download after user consent]
    J --> K[Size and SHA-256 check → OS installer]
```

The source of truth is the code: `app/lib/update_service.dart` (`_check`,
`verifyReleaseEnvelope`, `XioRelease`, `UpdateAsset`, `validateAssetUrl`),
`app/lib/update_installer.dart` (extraction/install) and `app/lib/update_ui.dart` (dialog).
Version and build number live only in `app/lib/version.dart` (`xioVersion`, `xioBuild`);
`app/pubspec.yaml` must match it.

Client rules a manifest must satisfy (anything else is silently discarded):

| Field | Requirement |
|---|---|
| envelope | `{"payload": base64(JSON), "signature": base64(64-byte Ed25519)}` |
| `payload` | at most 64 000 bytes |
| signature | Ed25519 by the key whose public half is pinned in `app/assets/security/update-ed25519.pub` |
| `schema` | exactly `1` |
| `tag` | `vX.Y.Z`, and `tag == 'v' + version` |
| `version` | `X.Y.Z`, strictly newer than the installed version (otherwise the release is skipped) |
| `build` | integer ≥ 1, strictly greater than the installed `xioBuild` |
| `notes` | string of at most 12 000 characters (full release notes do not fit) |
| `assets` | at least one platform; `url` must be HTTPS on `github.com`, path prefix `/rukazax/xio_vpn/releases/download/<tag>/`, no port, userinfo, query or `..` |
| `sha256` | 64 lowercase hex characters |
| `size` | 1 … 800 MiB |

Platform keys the application asks for (`UpdateService.platformKey`):

| Key | Platform |
|---|---|
| `android-arm64-v8a`, `android-armeabi-v7a`, `android-x86_64` | Android, ABI from `updateAbi` |
| `linux-x64` | Ubuntu/Debian x64 (DEB) |
| `windows-x64` | Windows x64 (ZIP) |
| `ios` | iOS (no package — the release page opens) |

## Releasing the manifest

Generator: `tools/release/update-manifest.py`. It reads version and build from
`app/lib/version.dart`, cross-checks `app/pubspec.yaml`, hashes the packages, builds the
payload, signs it with the project key, **verifies the key's public half against the pinned
`update-ed25519.pub`**, then re-reads the written file and runs the client's own rules over it.
A manifest the application would reject is never written.

```bash
# 1. Make sure version.dart and pubspec.yaml describe the build being shipped
#    (0.24.2 is 0.24.2+5019).

# 2. Sign the manifest over the final packages (key lives outside the repository).
python3 tools/release/update-manifest.py \
  --key ~/.keys/update-ed25519.key \
  --asset android-arm64-v8a=releases/XIO-Full-0.24.2-android-arm64-v8a.apk \
  --asset android-armeabi-v7a=releases/XIO-Full-0.24.2-android-armeabi-v7a.apk \
  --asset linux-x64=releases/XIO-0.24.2-ubuntu-amd64.deb \
  --notes "XIO 0.24.2 — two-server cascade, quieter battery, −7 MiB APK." \
  --assume-installed-build 5018 \
  --out releases/XIO-update.json

# 3. Attach it to the same release (publish.ps1 uploads everything in a directory).
pwsh -NoProfile -File tools/release/publish.ps1 \
  -Tag v0.24.2 -AssetsDir releases -NotesFile docs/release-notes-0.24.2.md

# 4. Verify what is published: signature, client rules, and the packages themselves.
python3 tools/release/update-manifest.py --check releases/XIO-update.json \
  --asset-dir /path/to/downloaded/assets

# 5. Confirm the feed looks the way the application scans it.
curl -s "https://api.github.com/repos/rukazax/xio_vpn/releases?per_page=30" \
  | python3 -c 'import json,sys
for r in json.load(sys.stdin):
    if r["tag_name"].startswith("v") and not r["draft"]:
        print(r["tag_name"], [a["name"] for a in r["assets"] if a["name"]=="XIO-update.json"])'
```

Single-file upload, useful for a hotfix or for a re-check after publishing:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  -H "Content-Type: application/json" \
  --data-binary @releases/XIO-update.json \
  "https://uploads.github.com/repos/rukazax/xio_vpn/releases/433728341/assets?name=XIO-update.json"
```

Order matters: build the **final** packages first, sign afterwards. Any byte changed in an
APK/DEB after signing makes `sha256` wrong and the installation stops at the checksum check.

### Signing key

The private key is not part of the repository (`releases/`, `.signing/` and the archives never
contain it). Format: 32 raw Ed25519 bytes. Its public half must match
`app/assets/security/update-ed25519.pub`; the generator refuses to sign with any other key.

Forks: create your own pair, replace `update-ed25519.pub`, **rebuild and distribute the
application**, and only then publish manifests signed with your key. Key rotation is possible
only together with an application update, because installed builds trust the pinned key alone.

## What the user sees when the manifest is absent

The application walks the release feed and, for every tag newer than the installed version,
requires exactly one asset named `XIO-update.json`. Without it (as in 0.23.0–0.24.2 before this
fix) the release is **silently skipped**: no error, no dialog, no log entry. The weekly check
keeps running, and the manual "Check for updates" button answers "You have the latest version",
so a missing manifest is indistinguishable from "no new versions exist". That is why the channel
dies unnoticed.

With a broken manifest (signature, tag, build, size, SHA-256) the behaviour is the same: the
release is discarded and the user gets neither an update nor an explanation.

## Limitations of the current scheme

1. **One `build` for all platforms.** A manifest describes a single build, while packages may be
   built at different times. Never publish build 5019 while a platform still carries the previous
   build's package: the client would install it and then see the "new" build again. That is why
   the 0.24.2 manifest has no `windows-x64`: the only ZIP on the release is `XIO-Full-0.24.1`
   (Windows was not rebuilt for 0.24.2). On Windows the client opens the release page instead.
2. **One package per ABI.** The channel does not distinguish Client from Full builds: one APK per
   architecture goes into the manifest (Full today). A Client user therefore receives Full with
   the server part. For the opposite, pass a `XIO-Client-…apk` path to `--asset`.
3. **No staged rollout.** One manifest per release: either everyone sees the update or nobody
   does. Revoking means deleting the asset — the next check simply finds nothing.
4. **A symmetric (HMAC) signature is unusable.** The client only verifies Ed25519 against the
   pinned public key; it will not accept an HMAC manifest for any secret. An environment secret
   would be neither stronger nor simpler — it would just never work.
5. **Privacy.** A check is a plain HTTPS request to GitHub, which sees the IP address; no
   profiles or credentials are sent. The signature protects against swapped files and foreign
   releases, but not against a compromised release key or device.

## Verified for 0.24.2

* Manifest: `releases/XIO-update.json`, 1487 bytes, sha256
  `d372b9ccff86c6b4c613179e800bbf43a47abc4b6b714dc4fe5616400923108e`, asset of release
  `v0.24.2` (id 433728341, asset id 711270683).
* `android-arm64-v8a` → `XIO-Full-0.24.2-android-arm64-v8a.apk`, 53 365 651 B,
  `f14a37ce36678e4cd752e55e3f9a9d4ac2e77b01260a83abd14a0ee2eb2b3610`.
* `android-armeabi-v7a` → `XIO-Full-0.24.2-android-armeabi-v7a.apk`, 53 332 893 B,
  `75dd867279e5b3c261193556fb3ab3e375c399d6119baa0e02e15e0215dcb6a6`.
* `linux-x64` → `XIO-0.24.2-ubuntu-amd64.deb`, 43 981 120 B,
  `0767a1697ff51d45802b2fd07c64f88c066048f21295ab9b9cd36c93f990c170`.
* Client tests: `app/test/update_manifest_test.dart` (signature with the pinned key loaded from
  `rootBundle`, the whole `check()` path, a real APK download, tamper rejection) plus the
  existing `update_security_test.dart` and `update_download_test.dart` — 19 tests, all pass;
  `flutter analyze` — no issues.

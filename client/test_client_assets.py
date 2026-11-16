#!/usr/bin/env python3
"""Verify the ad-hoc debug Client APK asset contract without a device or network.

The client-only Gradle path must package only the keep-list Flutter asset tops
(help, licenses, l10n, security, fonts) and must never carry the managed-server
payload. The Full build is checked as the inverse control: it must still carry
the server payload.

This is an artifact check; it does not install or launch anything.
"""

from __future__ import annotations

import argparse
import sys
import zipfile

KEEP = {"help", "licenses", "l10n", "security", "fonts"}
PAYLOAD_PREFIX = "assets/flutter_assets/assets/"
SERVER_MARKERS = {
    "xio-server.tar.gz",
    "xio-server-update.py",
    "xio-server-release.json",
    "xio-admin.py",
    "xio-stack.py",
    "xio-network-stack.py",
    "xio-mesh-stack.py",
    "vpn-sharing.sh",
    "install-wireguard.sh",
}


def tops(apk: str) -> set[str]:
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
    return {
        name[len(PAYLOAD_PREFIX):].split("/", 1)[0]
        for name in names
        if name.startswith(PAYLOAD_PREFIX) and len(name) > len(PAYLOAD_PREFIX)
    }


def markers(apk: str) -> set[str]:
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
    return {name.rsplit("/", 1)[-1] for name in names if name.startswith(PAYLOAD_PREFIX)}


def check(apk: str, expect_server: bool) -> None:
    asset_tops = tops(apk)
    present = markers(apk)
    if expect_server:
        missing = SERVER_MARKERS - present
        assert not missing, f"{apk}: Full control lost server payload files: {sorted(missing)}"
        print(f"PASS Full control keeps server payload ({len(present)} top-level files)")
        return
    extra = asset_tops - KEEP
    missing = KEEP - asset_tops
    assert not extra, f"{apk}: Client APK carries non-client asset tops: {sorted(extra)}"
    assert not missing, f"{apk}: Client APK is missing essential asset tops: {sorted(missing)}"
    served = SERVER_MARKERS & present
    assert not served, f"{apk}: Client APK still carries server payload: {sorted(served)}"
    print(f"PASS Client asset contract: tops={sorted(asset_tops)} no server payload")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk")
    parser.add_argument("--expect-server", action="store_true",
                        help="assert the Full control still carries the server payload")
    args = parser.parse_args()
    try:
        check(args.apk, args.expect_server)
    except AssertionError as failure:
        print(f"FAIL {failure}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

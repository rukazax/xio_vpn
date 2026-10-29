#!/usr/bin/env python3
"""XIO tunnel readiness responder.

Listens **only** on the tunnel gateway addresses, never on the public
interface. A client sends 16 random bytes; the server answers with one status
byte (0x01) followed by SHA-256(nonce)[:31]. Nothing else is accepted, so the
service cannot be used as an HTTP proxy, a reflector or an amplification
source: one short request in, 32 fixed bytes out.

The point is to answer one question: "did my packets leave through the tunnel
and did the far side really answer?" — without touching the public internet and
without depending on any third-party site being reachable.
"""

import asyncio
import hashlib
import os
import re
import signal
import socket
import sys

ADDRESSES = [a for a in re.split(r"[,\s]+", os.environ.get("XIO_READY_ADDRESSES", "10.78.0.1,10.79.0.1")) if a]
PORT = int(os.environ.get("XIO_READY_PORT", "7447"))
NONCE_BYTES = 16
REPLY_BYTES = 32
BIND_RETRY_SECONDS = 5


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        nonce = await asyncio.wait_for(reader.readexactly(NONCE_BYTES), timeout=5)
    except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
        writer.close()
        return
    writer.write(b"\x01" + hashlib.sha256(nonce).digest()[: REPLY_BYTES - 1])
    try:
        await writer.drain()
    except (ConnectionError, asyncio.TimeoutError):
        pass
    finally:
        writer.close()


async def serve(address: str) -> None:
    """Bind one tunnel gateway address, retrying until it exists.

    Tunnel interfaces come and go (systemd restarts the stack), so a missing
    address is not fatal: we keep retrying instead of dying and leaving the
    client without a readiness endpoint.
    """
    while True:
        try:
            server = await asyncio.start_server(
                handle,
                address,
                PORT,
                family=socket.AF_INET,
                backlog=64,
                reuse_address=True,
            )
        except OSError as error:
            print(f"xio-ready: {address}:{PORT} not ready ({error}), retrying", file=sys.stderr, flush=True)
            await asyncio.sleep(BIND_RETRY_SECONDS)
            continue
        print(f"xio-ready: listening on {address}:{PORT}", flush=True)
        async with server:
            await server.serve_forever()


async def main() -> None:
    wanted = [a.strip() for a in ADDRESSES if a.strip()]
    if not wanted:
        raise SystemExit("xio-ready: no addresses configured")
    loop = asyncio.get_running_loop()
    for signame in ("SIGTERM", "SIGINT"):
        try:
            loop.add_signal_handler(getattr(signal, signame), lambda: loop.stop())
        except NotImplementedError:  # pragma: no cover - non-POSIX
            pass
    await asyncio.gather(*(serve(address) for address in wanted))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        pass

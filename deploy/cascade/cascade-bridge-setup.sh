#!/usr/bin/env bash
# Render only: applying these files is exclusively the container entrypoint's job.
set -euo pipefail
SCRIPT_DIR=$(cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 "$SCRIPT_DIR/cascade-config.py" --role bridge "$@"

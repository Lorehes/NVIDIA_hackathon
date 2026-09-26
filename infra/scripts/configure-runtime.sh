#!/usr/bin/env bash
# Run through `brev exec`: SSH receives the VM's external gateway authority;
# systemd user services do not inherit it. Persist only these non-secret values.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p "$ROOT/infra/runtime"
umask 077
python3 - "$ROOT/infra/runtime/openshell.env" <<'PY'
import os
import sys
from pathlib import Path

keys = (
    "NEMOCLAW_GATEWAY_MANAGEMENT", "NEMOCLAW_GATEWAY_PORT",
    "NEMOCLAW_OPENSHELL_GATEWAY_ENDPOINT", "NEMOCLAW_OPENSHELL_GATEWAY_STATE_DIR",
    "OPENSHELL_LOCAL_TLS_DIR",
)
lines = []
for key in keys:
    value = os.environ.get(key)
    if value:
        if any(c in value for c in '\n\r"\\'):
            raise SystemExit(f"Unsupported character in {key}")
        lines.append(f'{key}="{value}"')
Path(sys.argv[1]).write_text("\n".join(lines) + "\n")
print(f"Recorded {len(lines)} non-secret gateway settings for the API service")
PY

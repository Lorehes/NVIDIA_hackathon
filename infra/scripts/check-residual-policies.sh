#!/usr/bin/env bash
# 조사 전후로 실행: 조사용(job-, spike-) 프리셋이 남아 있는지 확인한다. (PRD F9)
set -euo pipefail
SANDBOX="${SANDBOX_NAME:-my-assistant}"
openshell policy get "$SANDBOX" --full -o json | python3 -c '
import json, re, sys
data = json.load(sys.stdin)
policies = (data.get("policy") or {}).get("network_policies")
if data.get("status") != "effective" or data.get("sandbox") != sys.argv[1] or not isinstance(policies, dict):
    raise SystemExit("effective policy could not be verified")
left = [n for n in policies if re.fullmatch(r"(?:job|spike)-[A-Za-z0-9_-]+", n)
        or re.fullmatch(r"nemoclaw_custom__(?:job|spike)-[A-Za-z0-9_-]+?__(?:job|spike)-[A-Za-z0-9_-]+", n)]
if left:
    raise SystemExit("RESIDUAL PRESET FOUND: " + ", ".join(left))
print("no residual investigation presets (effective policy verified)")
' "$SANDBOX"

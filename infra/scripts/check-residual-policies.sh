#!/usr/bin/env bash
# 조사 전후로 실행: 조사용(job-, spike-) 프리셋이 남아 있는지 확인한다. (PRD F9)
set -euo pipefail
SANDBOX="${SANDBOX_NAME:-my-assistant}"
out="$(nemoclaw "$SANDBOX" policy list)"
if echo "$out" | grep -E '\b(job|spike)-' ; then
  echo "RESIDUAL PRESET FOUND" >&2
  exit 1
fi
echo "no residual investigation presets"

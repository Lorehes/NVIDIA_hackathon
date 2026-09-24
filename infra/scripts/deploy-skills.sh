#!/usr/bin/env bash
# 검사 스킬을 샌드박스 workspace로 올린다. (상세 명세 5절, 아키텍처 7절)
# `openshell sandbox upload`는 대상 경로를 "상위 폴더"로 해석해 <대상>/<원본폴더이름>을 만든다(스파이크 확인).
# 그래서 sandbox/skills 폴더를 workspace 상위(.openclaw/workspace)로 올려 skills/ 가 생기게 한다.
set -euo pipefail
SANDBOX="${SANDBOX_NAME:-my-assistant}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

openshell sandbox upload "$SANDBOX" "$ROOT/sandbox/skills" /sandbox/.openclaw/workspace
openshell sandbox exec -n "$SANDBOX" -- mkdir -p /sandbox/work
openshell sandbox exec -n "$SANDBOX" -- ls /sandbox/.openclaw/workspace/skills
echo "deployed skills to $SANDBOX"

#!/usr/bin/env bash
# 샌드박스에 검사 스크립트 의존 패키지를 1회 설치한다. (httpx, tldextract, html5lib)
# 조사용 egress 정책은 기본 거부이므로, 이 작업은 조사 밖에서 운영자가 pip 경로를 잠시 열어 수행한다.
# PEP 668(externally-managed) 환경이라 --break-system-packages 를 운영자가 명시적으로 사용한다.
set -euo pipefail
SANDBOX="${SANDBOX_NAME:-my-assistant}"
openshell sandbox exec -n "$SANDBOX" -- python3 -m pip install --user --break-system-packages httpx tldextract html5lib
openshell sandbox exec -n "$SANDBOX" -- python3 -c "import httpx, tldextract, html5lib; print('ok', httpx.__version__, html5lib.__version__)"

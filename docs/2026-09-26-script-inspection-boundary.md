# 실행하지 않은 스크립트의 검사 범위 구분

2026-09-26. 동일 호스트의 외부 스크립트·인라인 스크립트·이벤트 처리기는 주소 이동 문자열이나 외부 등록 도메인이 없으면 검사 누락으로 표시되지 않았다. 따라서 정적 HTML만 읽고 공식 페이지를 safe로 판정할 수 있었다.

검사기는 실행 대상 코드가 관찰됐다는 unexecuted_code 플래그를 보존한다. 판정은 이를 검사 범위의 공백으로 사용해 공식 신원은 유지하면서 전체 안전 판정을 보류한다. 코드 존재 자체를 사칭·악성 신호로 추가하지 않는다. 이미 관찰된 HTTP 폼/외부 전송 등 위험은 그대로 경고한다. 실제 실행 여부, CSP 허용 여부, 스크립트 악성 여부를 판정한 것이 아니다.

HTML script type/language와 WHATWG JavaScript MIME 목록을 적용한다. module 및 브라우저 동작 지시인 importmap/speculationrules는 미검증 동작으로 남긴다. JSON/JSON-LD/text/plain 등의 데이터 블록은 실행 코드로 분류하지 않고, 데이터 안에 location.href 같은 문자열이 있다고 이동 코드로 오인하지 않는다. 실행용 script src, 인라인 코드, 이벤트 속성, SVG script 및 srcdoc 중첩도 관찰한다. 빈 script는 제외한다. 파싱 불완전/중첩 제한 등 기존 보수적 경계는 유지한다.

기준 출처:
- https://html.spec.whatwg.org/multipage/scripting.html#the-script-element (type/language와 스크립트 준비 절차)
- https://mimesniff.spec.whatwg.org/#javascript-mime-type (JavaScript MIME essence 목록)

특정 사이트별 예외나 허용 목록을 추가하지 않았다. 스크립트를 실제로 실행하거나 네트워크 권한을 늘리지 않았다. iframe 외부 문서의 모든 실행 동작·CSP·브라우저 상호작용 전반을 검증한 것은 아니다. 구형 저장 결과를 소급 변경하지 않는다.

관련243개 로컬15.08초 통과(기존 Starlette/httpx 경고1). 새 회귀21개: 실행 코드12형태/비활성 자료8형태/HTTP 폼 위험 보존1개. 공통 safe 판단에 영향을 주므로 최종 전체 회귀 검사를 진행한다.

최종 전체 로컬752개42.85초/VM752개68.56초 통과(기존 Starlette/httpx 경고1). 직전 전체723개 이후 파일 회귀8개와 이번 실행 범위21개가 추가된 결과다. 샌드박스에 업로드한 검사기로 같은 출처 script src=true/JSON 데이터블록=false/데이터 이동힌트=false를 확인했다. API 유휴 재시작 완료, 웹 코드/빌드 변경 없음.

실제 파파고 j_838e3135b32340e983987a8bf76f914d:13.812초/HTTP200, 공식신원verified/네이버 파파고, 전체unknown/behavior incomplete, 의심근거 없음. page의 unexecuted_code=true/js_redirect_hint=true/external_active_hosts=[] 확인. 파파고 기존 결과를 새롭게 safe에서unknown으로 바꿨다는 뜻이 아니라 새 플래그와 기존 공식 인식의 통합 회귀다. 새 로직 단독으로 safe를 제한하는 사례는 합성 테스트로 구분한다. TLS OpenShell중계/원본신원미검증, 브라우저 화면과 실제 스크립트 실행 미검사.

4파일 로컬/VM 해시 일치, health정상/실행·대기0/effective조사정책잔여0. 카탈로그22,070레코드/16,281호스트·제외2,465(미제공2,438+기타27)·공식연결212·보완115/inactive0 그대로, SHA36980060141a40af64380bdd06fb79455b06d65920423a5799d4dc76e777e139 불변. 완료 원자료 재수집 없음.

다음에는 검사 범위를 실제보다 넓게 표시하는 다른 설명과 정상 입력 분류, 공식근거 부족 자료·명부누락/폐지/이전·다른 운영사 출처를 보완한다. 실행 후 DOM/네트워크·CSP/브라우저 상호작용/전체보안 시나리오·엄격90초와 전체기관 범위는 여전히 미완료. 근거 docs/evidence/2026-09-26-script-inspection-boundary.json.

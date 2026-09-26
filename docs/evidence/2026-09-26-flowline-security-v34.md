# Flowline 보안 경계·시간 제한·실패 복구 검증 — version 34

현재 상태: in_progress. 전체 보안 검증 및 엄격한 총90초 제한은 미완료. 이전 version27 설명(19,280자)은 docs/evidence/2026-09-26-flowline-security-history-v27.md에 원문 보존했다. 상세 단계/실측은 docs/2026-09-25-catalog-progress.md와 단계별 docs/evidence에 유지한다.

구현·검증된 경계:
- OpenShell 기본 관리/추론 정책을 유지하며 조사별 정확 호스트+독립 검증한 공인 IP+GET 권한만 추가/회수. 사설·혼합DNS·IP 직접/사용자정보 주소 거부. CDN 회전은 호스트당1회/32IP 이내 독립 재검증; 오류의 IP를 그대로 신뢰하지 않음. provider 이름 정규화와 effective 정책 확인으로 잔여 정책 검사/시작 정리 보강.
- 실제 example.com GET200/POST403, 비허용 example.org/pypi 차단을 확인한 과거 증거 존재. 명령 시간초과는 미완료로 처리·정리. read/exec 허용, websearch/fetch/toolSearch 비활성; 설치용 넓은 preset 제거. 전체 공격 시나리오 완료와 구분.
- 정확 주소 조회 우선, PSL PRIVATE/학교/공유 호스트·경로·쿼리·비표준 포트 경계 보존. 인기 등재를 공식 운영사나 안전 근거로 쓰지 않음. 공유 기관의 한 경로를 호스트 전체 신원으로 확장하지 않음. 미지원 포트22레코드는 신원 조회만, DNS/샌드박스/권한 추가 없음.
- 공식 서비스/계열사/학교 출처 분리. 수집기 HTML·제한된 구조화 데이터는 실행하지 않고 구조·중복키·범위 검증. 실패 시 자료 원자 교체 중단. 기관 주소 보완은 원문 행+자료집 해시 또는 고유 ID와 공식 출처 대조, 추정 철자 교정 없음.
- 공식 홈페이지 이동 수집: 공인 IP에 고정 연결하면서 원 Host/SNI/TLS 검증, 제한된 HTTPS 루트 이동/정확 도착 주소24시간 근거. 403 등 접근제한은 safe 근거 아님.
- 조사 중 경로 이동: 최근7일 공식 서비스 목록의 정확 출발 URL에서 실제 HTTP 이동 관찰 시만 동일 HTTPS 기본443·호스트·출발 경로 세그먼트 내 정확 도착 URL을 해당 조사에 한정해 연결. 모든 중간 이동 확인. 인코딩/질의/fragment/점경로/경계 이탈·학교·계열사에는 확장하지 않음. 영구 경로 허용목록/카탈로그 승격 없음. 실제 세븐나이츠 j_d4a4653570194b0695da21d9ba6a3925:20.479초,200,공식verified,unknown/동작미검사.
- TLS 실측은 OpenShell Sandbox CA 중계 인증서. 실제 원본 서버 인증서·운영사 신원·CT·폐기 검증으로 표시하지 않음. TLS 유효만으로 safe 승격하지 않음.

2026-09-26 최신 수정:
HTTPS 공식 페이지가 같은 공식 호스트의 HTTP 주소로 입력을 보내도록 선언해도 safe가 될 수 있던 빈틈 수정. 폼/제출버튼 formaction/form 연결/base 상대주소의 모든 관찰 주소를 표시20개 제한 전에 검사. 숨김 값/파일 입력도 HTTP 전송이면 보존. 기존 증거의 action_urls 하위호환. insecure_form_action은 별도 mid 경고이며 safe를 제한하되 공식 신원과 구분한다. 실제 제출 또는 브라우저 HSTS/자동 승격을 실행한 결과는 아니다.
같은 사이트 전송이라는 이유로 ‘페이지 안에서만 처리’라 단정하던 비교·추적 문구를 관찰 주소 확인/실제 서버 처리 미검증으로 수정. 검색/만족도 명칭만으로 민감·모호한 폼을 면제하지 않는다. 사이트별 하드코딩 없음.
최종 전체 로컬723개43.03초/VM723개69.00초 통과(기존 Starlette/httpx 경고1). 관련101개13.02초. 파서·API·테스트5파일 해시 일치, 샌드박스 검사기 업로드 해시 확인, 유휴 API 재시작. 통신권한 확대 없음.
실제 합천 안내 j_eb0ca19009c949c5856cb31ed126da84:200/12.732초/공식14기관/unknown·behavior incomplete. 응답에 폼이 관찰되지 않아 HTTP 위험 경고는 합성 테스트 증거로 구분한다. 실제 입력 제출/브라우저 결과 화면 미검사. health정상, 실행·대기0, effective 조사정책잔여0.
자료22,070레코드/16,281호스트·제외2,465·공식연결212 그대로. SHA36980060141a40af64380bdd06fb79455b06d65920423a5799d4dc76e777e139.
근거 docs/2026-09-26-form-transport.md, docs/evidence/2026-09-26-form-transport.json.

남은 범위:
실제 내부주소/동시성 등 E1–E5/S1/S2 전체 보안 시나리오, 엄격한 총90초, 원본TLS 검증 범위, 팀소유HTTPS 데모 도메인(사용자 없음 답변), 정상 입력/미검증 분류 정확도. URL 입력의 비교·추적 기본 목적 ‘안내 문자’ 잔여 레이블 보완 필요. 명부누락·폐지·이전·동명이 지역 식별과 공식근거 없는 주소는 미해결이며 추정 등록하지 않는다. 전체기관 누락 없음·모든 페이지 안전·전체보안완료로 보고하지 않는다.

2026-09-26 파일 첨부 누락/검색 전용 분류 수정: input type=file이 제외되어 검색+파일을 검색만 있는 것으로 판단하거나 첨부만 있는 페이지를 입력란 없다고 표시할 수 있었다. 별도 file유형을 보존해 검색 예외에서 제외하고 다른 기관경로/외부전송 경고 유지. 공식 첨부 자체는 악성 판단하지 않고 파일내용·실제전송/서버처리 미검사로 남겨 safe승격 제한. form외부연결/대문자/multiple/accept 및 이름·autocomplete 오인식 검증, hidden 검색토큰 정상회귀 유지. API/웹에 첨부 내용 미검사 중립상태, 웹 기본 ‘페이지 내부 처리/보내는 곳 없음’ 단정도 수정. 특정 사이트 예외/통신권한 확대 없음.
관련133개 로컬13.12초/VM16.56초(새8개 포함) 통과. 로컬웹 tsc미설치로 미실행, VM 타입/운영빌드 통과. 샌드박스 업로드본 합성 검색+파일은 [other,file]/검색플래그false 확인. 9파일해시 일치, API/웹 유휴재시작.
실제 네이버 j_301cae038bdc4945abe542b353812c77 57.391초/www→302→m200/최종공식verified/unknown·동작미검사/의심근거없음. 정상검색의 처리주소미확인·URL목적null 유지. 실제파일첨부 양성사례는 아님; 실제파일전송/브라우저화면미검사. TLS중계/원본미검증. health정상/실행대기0/웹200/effective잔여0.
카탈로그22,070/16,281·제외2,465=2,438+27·공식212·보완115/inactive0 불변. 직전전체723 이후 관련회귀이며 전체재검사 아님. docs/2026-09-26-file-forms.md 및 evidence동명JSON. 만족도폼전반/스크립트 전송/첨부이후동작·기관누락/상태/주소근거·전체보안/엄격90초 남아 후속유지.

2026-09-26 스크립트 검사 범위 개선: 동일호스트 script src/인라인/이벤트 처리기를 실행하지 않았는데 주소이동·외부도메인 신호가 없다는 이유로 safe가 될 수 있던 빈틈 수정. unexecuted_code를 검사 공백으로 보존해 공식 신원 유지·전체 안전 보류. 스크립트 존재 자체는 악성/사칭 신호가 아니다. 기존 HTTP폼·외부전송 위험 유지. WHATWG HTML type/language 및 MIME 목록으로 module/importmap/speculationrules/기존JS형식을 구분하고 JSON/JSON-LD/text/plain 데이터를 실행코드·이동 문자열로 오인하지 않음. SVG/srcdoc/이벤트·빈스크립트 회귀 포함. 실제JS 실행/CSP판정·통신권한 확대 없음.
관련243개15.08초 이후 최종전체 로컬752개42.85초/VM752개68.56초 통과(기존 경고1). 새21개+직전파일8개로 이전723에서 증가. 4파일해시 일치. 업로드 샌드박스 합성검사: 같은출처src true/JSONcode false/JSONredirect false. API유휴재시작, 웹변경없음.
실제 파파고 j_838e3135b32340e983987a8bf76f914d 13.812초/200/공식verified·네이버파파고/unknown·동작미검사/의심근거없음. unexecuted_code=true/js_redirect_hint=true/외부activehosts없음. 파파고기존판정이 새로 바뀌었다는 뜻은 아니며 새단독safe제한은 합성검증. 실제JS실행·브라우저화면미검사, TLS중계/원본미검증, health정상/실행대기0/effective잔여0.
카탈로그22,070/16,281·제외2,465·공식212·보완115/inactive0 불변. 근거 docs/2026-09-26-script-inspection-boundary.md 및 evidence동명JSON. 기준 https://html.spec.whatwg.org/multipage/scripting.html#the-script-element 및 https://mimesniff.spec.whatwg.org/#javascript-mime-type . 실제DOM/스크립트네트워크·정상입력분류/주소출처·기관명부누락/상태·전체보안/엄격90초 미완료.

2026-09-26 세종시17기관 데이터 보완 시 기존 공유호스트 경계 규칙으로 세종시 대표 http://www.sejong.go.kr의 범위 host→url 축소. 새 기관3정확URL을 대표시청 신원으로 덮지 않도록 검증. 기존 다른22,088레코드 불변/정확이름17/비검토URL15거절, 관련31개 로컬0.81초/VM1.68초. 보안코드·권한변경/재시작 없음. 실측 j_8fc0308434094180a0c8fdc17b4d05b8 HTTP200/19.570초 공식verified7, 전체caution:같은호스트 /health/index.do 일반입력 처리 공식미확인. 실제악성 확인 아님; 외부전송/HTTP제출 미관찰/unexecuted_code=true. TLS중계CA/원본미검증, health정상/실행대기0/effective정책잔여0. 실제제출·JS실행/브라우저 미검사. 자료 및 근거 docs/evidence/2026-09-26-sejong-health-review.json. 정상검색/만족도 구분과 실제전체보안/엄격90초 미완료.

2026-09-26 추가 실측 개선사례(보안코드/권한 변경 없음): 달성군 공식조직도 j_a3312e8500594ba5a3daa7d2bfa891de HTTP200/16.430초/신원verified14, 전체caution. 같은호스트 검색 text+범주select 폼3개가 search_only=false/other로 분류되어 처리경로 미확인 경고. POST 검색2/메서드생략검색1, 외부도메인·HTTP제출 미관찰/unexecuted_code=true. 실제악성전송 확인 아님. 문구기반 일괄면제 없이 정상 검색 구조 분류 개선 대상. 관련31개 로컬0.85초/VM1.69초;기존22,106레코드불변/정확14이름·5경계 확인. TLS중계/원본미검증;health정상/실행대기0/effective잔여0. 브라우저/실제입력 제출/코드실행 미검사. docs/evidence/2026-09-26-dalseong-health-review.json.

2026-09-26 검색+범주선택 분류 개선(로컬만 완료/VM 반영 대기). 기존 type=search 외에도 검색 설명+query/q/keyword/search 식별자를 가진 단일 text 입력과 검색용 bounded native select(1~50 option/단일선택)를 구조적으로 확인. 민감입력/첨부/textarea/모호한추가입력/선택만 있는폼/다른origin·HTTP·포트/외부제출버튼·혼합메서드 예외거절. 검색힌트로 공식처리URL 등록/safe승격하지 않고 기존 미확인 표시 유지. 사이트 조건문 없음. 새회귀24개/관련88개0.34초, 전체로컬776개42.91초 통과(기존경고1). 저장 달성군HTML3폼 same_origin_search=true/search_only=false/unexecuted_code=true. 카탈로그22,120/16,282·제외2,415·보완165/inactive0 불변.
VM 배포4회는 명령실행 전 Brev SSH Permission denied(publickey). VM RUNNING/READY·Brev healthcheck Healthy·refresh성공, 기존 Chrome NVIDIA SSO 재로그인 성공 뒤에도 거절. 최초SSO는 브라우저지연으로 만료. 새 SSH인증서 생성/유효시간내 접속 확인, 비밀내용기록없음. 인스턴스초기화/접근권한변경없음. 신규VM테스트/샌드박스업로드/실제URL 재검증 미실행, 서비스는 기존분류. 이전 VM전체752개/자료단계31개와 로컬776개를 혼동하지 않음.
SSH복구·환경변화 전 같은 배포/SSO 재시도를 반복하지 말 것. docs/evidence/2026-09-26-search-selectors.json의 두파일 before/after 해시 보존, /tmp/deploy_search_selectors.py에 준비된 배포→VM전체검사→샌드박스갱신 절차 존재. 복구 후 업로드해시/실접속검증 필요. docs/2026-09-26-search-selectors.md 및 체크포인트에 재개지점 기록. SSH와 무관한 남은 기관 근거 연구는 진행 가능하며 전체범위 미완료/후속유지.

2026-09-26 공식서비스 출처수집 경계(로컬만 준비): 한컴소개페이지의 application/json 서비스배너 단일객체에서 지정제목·시작URL만 추출하도록 group_shape:object 추가. 목록기본방식/JSON중복키·실행식거절/템플릿·설치파일·userinfo·잘못된포트제외 유지, 다른객체·FAQ·포럼미채택. 새6 포함관련45개0.50초, 실제자료5정확조회/15하위경로·질의·다른호스트거절; 기존22,158자료불변. 문서/설문서비스의 공식시작주소가 사용자콘텐츠 안전성/공식신원으로확장되지않음. 공개스크립트는텍스트검토만, 실제5시작주소 직접HTTPS200/제목일치는VM검사·입력/JS실행·원본TLS검증과구분. 검토스크립트해시는기록이며자동갱신시해시검증게이트아님. runtime판정/통신권한변경없음. 수집기/설정/자료는SSH실패로VM미반영; 새로운SSH/SSO시도없음. 누적자료43건·검색분류/표준수집기와함께복구후반영/검증필요. docs/evidence/2026-09-26-hancom-service-homes.json. 전체보안/엄격90초 미완료.


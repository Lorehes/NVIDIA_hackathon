# 공식 기관의 비표준 포트 주소 등록

2026-09-26 (한국시간). 기존 원자료에서 제외됐던22행을 다시 평가했다. 출처나 주소를 새로 추정하지 않았다.

## 변경

- 공식 명부의 주소를 포트·경로·질의까지 그대로 등록하고 inspection_supported=false로 구분한다. 등록은 페이지 접속 권한을 부여하지 않는다.
- HTTP/HTTPS 기본 포트 밖의 출처는 스킴·포트·경로·질의가 일치해야 신원을 확인한다. 표준 주소도 비표준 포트로 확인 근거를 넘기지 않는다. 레코드 ID에 비표준 포트와 스킴을 포함해 충돌을 막는다.
- 미지원 포트는 DNS 조회·샌드박스/AI 실행·통신 권한 개방 없이 unknown으로 끝낸다. 공식 주소 근거는 보존하며 페이지·TLS 검사는 미완료로 표시한다.
- 실행되지 않은 조사를 not_run으로 표시하고, 한국어 설명에 재시도나 접속 성공을 주장하지 않는다.
- 접속 전 중단 시 원래 전체 URL을 공식 주소 비교에 사용하고 한글 호스트는 IDNA로 대조한다.

## 다시 등록한 출처 주소

| 기관 | 주소 | 출처 |
|---|---|---|
| 광주백운초등학교 | https://baekun.gen.es.kr:451 | https://open.neis.go.kr/portal/data/service/selectServicePage.do?infId=OPEN17020190531110010104913&infSeq=1 |
| 본촌초등학교 | https://bonchon.gen.es.kr:451/ | https://open.neis.go.kr/portal/data/service/selectServicePage.do?infId=OPEN17020190531110010104913&infSeq=1 |
| 대구광역시 서부노인전문병원 | https://dgsbgh.daegumc.co.kr:7443/ | https://www.ppm.or.kr/ |
| 양지초등학교 | https://gj-yangji.gen.es.kr:451/ | https://open.neis.go.kr/portal/data/service/selectServicePage.do?infId=OPEN17020190531110010104913&infSeq=1 |
| 효천다솜유치원 | https://hcdasom.gen.kg.kr:450 | https://e-childschoolinfo.moe.go.kr/openData.do |
| 임곡중학교 | https://imgok.gen.ms.kr:452/2016/ | https://open.neis.go.kr/portal/data/service/selectServicePage.do?infId=OPEN17020190531110010104913&infSeq=1 |
| 지한초등학교 | https://jihan.gen.es.kr:451/ | https://open.neis.go.kr/portal/data/service/selectServicePage.do?infId=OPEN17020190531110010104913&infSeq=1 |
| 광주지산초등학교 | https://k-jisan.gen.es.kr:451/ | https://open.neis.go.kr/portal/data/service/selectServicePage.do?infId=OPEN17020190531110010104913&infSeq=1 |
| 대성여자중학교 | https://kds.gen.ms.kr:452 | https://open.neis.go.kr/portal/data/service/selectServicePage.do?infId=OPEN17020190531110010104913&infSeq=1 |
| 산림자원연구소 | https://keumkang.chungnam.go.kr:452/ | https://www.gov.kr/portal/orgSite?pageIndex=47 |
| 설월여자고등학교 | https://seolwol.gen.hs.kr:453 | https://open.neis.go.kr/portal/data/service/selectServicePage.do?infId=OPEN17020190531110010104913&infSeq=1 |
| 운수유치원 | https://unsu.gen.kg.kr:450/ | https://e-childschoolinfo.moe.go.kr/openData.do |
| 서울강빛초등학교병설유치원 | https://www.gbk.kg.kr:510/home/ | https://e-childschoolinfo.moe.go.kr/openData.do |
| 경상남도립김해노인전문병원 | https://www.gimhaenoin.co.kr:452/html/?pCode=42 | https://www.ppm.or.kr/ |
| 칠곡경북대학교병원 | https://www.knuch.kr:442/index.asp | https://www.ppm.or.kr/ |
| 서울마들유치원 | https://www.mdkd.kg.kr:499/home/ | https://e-childschoolinfo.moe.go.kr/openData.do |
| 전북특별자치도 남원의료원 | https://www.namwonmed.or.kr:19005/ | https://www.ppm.or.kr/ |
| 한사랑유치원 | https://www.한사랑유치원.kr:475/home/ | https://e-childschoolinfo.moe.go.kr/openData.do |
| 서울수명유치원 | https://www.서울수명유치원.kr:493/home/ | https://e-childschoolinfo.moe.go.kr/openData.do |
| 서울솔방울유치원 | https://www.xn--vh3bn4gkky3oca8l5w657b.kr:497/home/ | https://e-childschoolinfo.moe.go.kr/openData.do |
| 서울청파유치원 | https://xn--2i4bq6hcctpy0vitc0ym.kr:446/home/ | https://e-childschoolinfo.moe.go.kr/openData.do |
| 서울강현유치원 | https://xn--939at21bd7d1czrv17a0pn.kr:462/home/ | https://e-childschoolinfo.moe.go.kr/openData.do |

로컬 재생성 결과21,841레코드/16,178호스트. 제외2,581행(미제공2,539·기타재확인42), 등록했지만 페이지 검사 미지원22행. 원자료 미수집 기관까지 포함한 전수 완료를 의미하지 않는다.

## 검증

관련31개 통과. DNS/샌드박스/AI 호출 시 실패하도록 만든 파이프라인 검사, 한글 호스트, 다른 포트/스킴/경로 격리, 실제22개 출처 주소 조회를 확인했다. 로컬/VM 전체515개 통과(66.15/66.91초), VM 웹 타입 검사·빌드 통과. VM 배포 후 실제 API에서 연구소·공립병원·한글 도메인 유치원3건과 다른 포트 대조군1건을 검사했다. 원래3개 공식 신원 verified/페이지미검사, 대조군unverified. 모두 not_run·통신 이벤트0·인증서0, 22~43ms. API health200, effective 정책/조사 잔여0. 목적지 사이트에는 접속하지 않았으며 실제 페이지 안전성 검증으로 표현하지 않는다. 상세 결과: docs/evidence/2026-09-26-catalog-ports.json.

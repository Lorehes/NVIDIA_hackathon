"""Controlled offline evaluation, not a measured real-world false-positive rate."""
import pytest

from app.kb import KB
from app.urls import parse_url
from app.verdict import Evidence, decide
from checklib.similarity import compare

KB_DATA = KB.load()
CASES = [
    ('epost', '[우체국택배] 배송 조회 안내', 'epost.go.kr'),
    ('cjlogistics', '[CJ 대한통운] 배송지 확인 안내', 'cjlogistics.com'),
    ('hanjin', '[한진택배] 운송장 확인 안내', 'hanjin.com'),
    ('lotte', '[롯데글로벌로지스] 배송 조회 안내', 'lotteglogis.com'),
    ('logen', '[로젠택배] 배송지 확인 안내', 'ilogen.com'),
    ('kbstar', '[국민은행] 계좌 보안 확인 안내', 'kbstar.com'),
    ('woori', '[우리 은행] 계정 보안 안내', 'wooribank.com'),
    ('hana', '[하나은행] 본인 확인 안내', 'kebhana.com'),
    ('ibk', '[기업은행] 계좌 확인 안내', 'ibk.co.kr'),
    ('nts', '[홈택스] 세금 신고 안내', 'hometax.go.kr'),
    ('nhis', '[건강보험공단] 보험료 확인 안내', 'nhis.or.kr'),
    ('gov24', '[정부 24] 민원 처리 안내', 'gov.kr'),
    ('customs', '[관세청] 통관 안내', 'customs.go.kr'),
    ('fsc', '[금융위] 공지 확인 안내', 'fsc.go.kr'),
    ('korea', '[정책브리핑] 정부 정책 안내', 'korea.kr'),
]


@pytest.mark.parametrize('entity_id,message,domain', CASES)
def test_real_brand_candidate_and_source(entity_id, message, domain):
    hits = KB_DATA.candidates(message)
    assert hits[0][0].id == entity_id
    entity = hits[0][0]
    assert not entity.fictional
    assert domain in entity.official_domains
    assert entity.sources and all(s['checked'] == '2026-09-25' for s in entity.sources)
    # Do not invent anti-phishing policies or third-party payment relationships.
    assert entity.policy_rules == [] and entity.partner_domains == []


def evidence(entity_id, url, fetched=True):
    p = parse_url(url)
    chain = [{'url': url, 'host': p['host_ascii'], 'registrable_domain': p['registrable_domain'],
              'status': 200, 'blocked': False, 'error': None}]
    return Evidence(
        parse=p, similarity=compare(p, KB_DATA.official_records()),
        claim={'ok': True, 'entity_id': entity_id, 'purpose': 'account_security'},
        candidates=[(KB_DATA.by_id[entity_id], 'exact')],
        fetch={'ok': True, 'chain': chain, 'final_registrable_domain': p['registrable_domain'],
               'tls': {'https': True, 'verified': True}, 'blocked_count': 0} if fetched else None,
        page={'ok': True, 'forms': [], 'apk_links': [], 'trust_claims': []} if fetched else None,
    )


@pytest.mark.parametrize('entity_id,message,domain', CASES)
def test_verified_official_page_has_no_impersonation_false_positive(entity_id, message, domain):
    result = decide(evidence(entity_id, f'https://www.{domain}/'), KB_DATA)
    assert result.verdict == 'safe'


@pytest.mark.parametrize('entity_id,message,domain', CASES)
def test_official_domain_inside_attacker_subdomain_is_detected(entity_id, message, domain):
    result = decide(evidence(entity_id, f'https://{domain}.account-check.test/'), KB_DATA)
    assert result.verdict == 'suspected_impersonation'
    assert 'subdomain_disguise' in {s['type'] for s in result.signals}


@pytest.mark.parametrize('entity_id,message,domain', CASES)
def test_official_address_without_fetch_cannot_be_safe(entity_id, message, domain):
    result = decide(evidence(entity_id, f'https://www.{domain}/', fetched=False), KB_DATA)
    assert result.verdict == 'unknown'

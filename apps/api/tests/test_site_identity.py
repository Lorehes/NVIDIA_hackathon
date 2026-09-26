from datetime import datetime, timezone, timedelta
import json

from app.config import settings
from app.kb import KB
from app.site_catalog import SiteCatalog
from app.site_relations import RelationStore
from app.verdict import Evidence, decide
from checklib.parse_url import parse_url
from checklib.similarity import compare


def record(host='school-a.school.example', **kw):
    return {'id': host, 'name': '가나다학교', 'host': host, 'family': 'school.example',
            'url': 'https://' + host + '/', 'scope': 'host', 'kind': 'school', 'verified': True,
            'checked': datetime.now(timezone.utc).date().isoformat(), 'source': 'https://directory.example/', **kw}


def test_public_suffix_private_tenants_and_arbitrary_subdomain_families():
    for host in ['naver.com', 'www.naver.com', 'm.naver.com', 'mail.naver.com', 'new.service.naver.com']:
        assert parse_url('https://' + host)['registrable_domain'] == 'naver.com'
    assert parse_url('https://naver.com.fake.com')['registrable_domain'] == 'fake.com'
    assert parse_url('https://alice.github.io')['registrable_domain'] == 'alice.github.io'
    assert parse_url('https://bob.github.io')['registrable_domain'] == 'bob.github.io'


def test_school_identity_does_not_spread_to_sibling_or_parent():
    kb = KB([], SiteCatalog([record()]))
    hit = kb.address_candidates('https://school-a.school.example/')[0][0]
    assert hit.matches('school-a.school.example')
    assert not hit.matches('school-b.school.example')
    assert not kb.address_candidates('https://school-b.school.example/')
    assert not kb.address_candidates('https://school.example/')


def test_shared_host_paths_keep_institutions_separate():
    records = [record('schools.example', id='a', name='가학교', url='https://schools.example/a/', scope='url'),
               record('schools.example', id='b', name='나학교', url='https://schools.example/b/', scope='url')]
    kb = KB([], SiteCatalog(records))
    a = kb.address_candidates('https://schools.example/a/')[0][0]
    assert a.id == 'a' and not a.matches('schools.example', 'https://schools.example/b/')
    assert kb.address_candidates('https://schools.example/b/')[0][0].id == 'b'
    assert not kb.address_candidates('https://schools.example/unknown/')


def test_bare_url_never_calls_embedding_and_unknown_stays_unknown(monkeypatch):
    kb = KB([], SiteCatalog([record()]))
    monkeypatch.setattr(kb, '_rank', lambda text: (_ for _ in ()).throw(AssertionError('must not embed URLs')))
    assert kb.address_candidates('https://school-a.school.example/')
    assert kb.address_candidates('https://never-seen.example/') == []


def test_expired_or_popularity_record_never_becomes_official_even_with_good_tls():
    for r in [record(verified=False, kind='popular_ranking'),
              record(checked=(datetime.now(timezone.utc).date() - timedelta(days=91)).isoformat())]:
        kb = KB([], SiteCatalog([r]))
        p = parse_url(r['url'])
        ev = Evidence(parse=p, candidates=kb.address_candidates(r['url']), address_only=True,
                      similarity=compare(p, []),
                      fetch={'ok': True, 'chain': [{'url': r['url'], 'status': 200}], 'final_url': r['url'],
                             'tls': {'verified': True}}, page={'ok': True, 'forms': []})
        outcome = decide(ev, kb)
        assert outcome.verdict == 'unknown'
        assert not any(s['type'] == 'official_match' for s in outcome.signals)


def test_no_model_claim_can_identify_unknown_bare_url():
    kb = KB.load()
    p = parse_url('https://brand-new-unrelated-site.example/')
    outcome = decide(Evidence(parse=p, address_only=True, claim={'ok': True, 'entity_id': 'hanbit'}), kb)
    assert outcome.entity is None and outcome.verdict == 'unknown'


def test_catalog_contains_1000_popular_families_and_bounded_check_payload():
    report = json.loads(settings.kb_path.with_name('sources').joinpath('coverage.json').read_text())
    assert report['popular_selected'] == 1000
    kb = KB.load()
    assert len(kb.catalog.by_host) > 10000
    assert len(kb.official_records(kb.address_candidates('https://www.bai.go.kr/'))) < 100


def test_observed_redirect_cache_expires_and_does_not_store_sensitive_urls(tmp_path):
    store = RelationStore(tmp_path / 'relations.sqlite')
    store.observe([{'host': 'a.example', 'url': 'https://a.example/?secret=123', 'status': 302},
                   {'host': 'b.example', 'url': 'https://b.example/?token=123', 'status': 200}], now=100)
    assert store.related('a.example', now=101)[0]['kind'] == 'redirect_observed'
    assert store.related('a.example', now=86501) == []
    assert b'secret' not in (tmp_path / 'relations.sqlite').read_bytes()


def test_shared_school_parent_does_not_exempt_sibling_password_destination():
    from checklib.inspect_page import inspect_page
    r = record()
    kb = KB([], SiteCatalog([r]))
    p = parse_url(r['url'])
    page = inspect_page(b'<form action="https://school-b.school.example/submit"><input type=password></form>', r['url'])
    ev = Evidence(parse=p, candidates=kb.address_candidates(r['url']), address_only=True,
                  similarity=compare(p, []), page=page,
                  fetch={'ok': True, 'chain': [{'url': r['url'], 'status': 200}], 'final_url': r['url'],
                         'final_registrable_domain': p['registrable_domain'], 'tls': {'verified': True}})
    outcome = decide(ev, kb)
    assert outcome.verdict == 'caution'
    assert 'cross_domain_form' in {s['type'] for s in outcome.signals}


def test_peer_certificate_metadata_does_not_assert_origin_ownership():
    from checklib.fetch_chain import _connection_certificate
    class Peer:
        def getpeercert(self, binary_form=False, /):
            return b'peer-certificate' if binary_form else {
                'issuer': ((('organizationName', 'Inspection proxy'),),),
                'subjectAltName': (('DNS', 'service.example'),), 'notAfter': 'Dec 31 00:00:00 2026 GMT'}
        def version(self):
            return 'TLSv1.3'
    class Stream:
        def get_extra_info(self, name):
            return Peer()
    class Response:
        extensions = {'network_stream': Stream()}
    info = _connection_certificate(Response())
    assert info['dns_names'] == ['service.example']
    assert info['scope'] == 'connection_peer' and info['origin_identity_verified'] is False


def test_official_service_directory_recognizes_papago_and_preserves_page_limits():
    from app.presentation import build_explanation, verdict_label
    kb = KB.load()
    url = 'https://papago.naver.com/'
    candidates = kb.address_candidates(url)
    assert candidates[0][0].name == '네이버 파파고'
    assert candidates[0][0].identity_verified
    ev = Evidence(parse=parse_url(url), candidates=candidates, address_only=True,
                  similarity=compare(parse_url(url), kb.official_records(candidates)),
                  fetch={'ok': True, 'chain': [{'url': url, 'status': 200}], 'final_url': url,
                         'final_registrable_domain': 'naver.com', 'tls': {'verified': True}},
                  page={'ok': True, 'forms': [], 'js_redirect_hint': True})
    outcome = decide(ev, kb)
    assert outcome.verdict == 'unknown' and outcome.unknown_reason == 'unverified'
    assert 'official_match' in {s['type'] for s in outcome.signals}
    identity = kb.identity_summary(url, outcome)
    assert identity['status'] == 'verified' and identity['behavior'] == 'incomplete'
    assert identity['source'] == 'https://www.navercorp.com/service/all'
    assert '네이버 파파고 공식 주소' in build_explanation(outcome, ev.page, 'naver.com', None, False)['headline']
    assert '공식 주소 확인' in verdict_label(outcome)


def test_publisher_directory_is_not_a_blanket_domain_or_user_content_grant():
    kb = KB.load()
    for url in ['https://papago.naver.com.attacker.example/', 'https://unlisted-subdomain.naver.com/',
                'https://service.naver.com@attacker.example/']:
        assert not any(e.identity_verified for e, _ in kb.address_candidates(url))
    assert kb.address_candidates('https://map.naver.com/')[0][0].identity_verified
    # Multiple service URLs on one host retain their individual path scope.
    health = kb.catalog.lookup('https://healthcare.naver.com/symptomchecker/')
    assert health and health['scope'] == 'url'
    assert kb.catalog.lookup('https://healthcare.naver.com/unlisted-service') is None


def test_service_collector_requires_service_home_link_and_keeps_source():
    import importlib.util
    script = settings.kb_path.parents[1] / 'scripts/catalog/collect_services.py'
    spec = importlib.util.spec_from_file_location('service_collector', script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    publisher = {'name': '예시 회사', 'url': 'https://corp.example/services',
                 'card_class': 'service-card', 'heading_tag': 'h4', 'home_icon_class': 'home'}
    rows = mod.extract_services('''<div class="service-card"><h4>번역</h4>
        <a href="https://translate.example/"><span class="home"></span></a>
        <a href="https://apps.store.example/app"><span class="app"></span></a></div>
        <footer><a href="https://ad.example/"><span class="home"></span></a></footer>''', publisher)
    assert len(rows) == 1
    assert rows[0]['url'] == 'https://translate.example/'
    assert rows[0]['source'] == publisher['url'] and rows[0]['name'] == '예시 회사 번역'


def test_popularity_entry_does_not_turn_same_site_search_into_an_exfiltration_warning():
    from checklib.inspect_page import inspect_page
    url = 'https://portal.example.com/'
    r = record('portal.example.com', family='example.com', name='인기 사이트', verified=False, kind='popular_ranking')
    kb = KB([], SiteCatalog([r]))
    page = inspect_page(b'<form action="https://search.example.com/search"><input type=search name=q></form>', url)
    outcome = decide(Evidence(parse=parse_url(url), candidates=kb.address_candidates(url), address_only=True,
                              similarity=compare(parse_url(url), []), page=page,
                              fetch={'ok': True, 'chain': [{'url': url, 'status': 200}], 'final_url': url,
                                     'final_registrable_domain': 'example.com', 'tls': {'verified': True}}), kb)
    assert outcome.verdict == 'unknown'
    assert 'cross_domain_form' not in {s['type'] for s in outcome.signals}


def test_verified_final_service_takes_priority_over_popularity_only_entry():
    kb = KB([], SiteCatalog([record('entry.example.com', family='example.com', verified=False),
                            record('mobile.example.com', family='example.com', name='공식 서비스')]))
    url = 'https://entry.example.com/'
    final = 'https://mobile.example.com/'
    ev = Evidence(parse=parse_url(url), candidates=kb.address_candidates(url), address_only=True,
                  similarity=compare(parse_url(url), []), page={'ok': True, 'forms': []},
                  fetch={'ok': True, 'chain': [{'url': url, 'status': 302}, {'url': final, 'status': 200}],
                         'final_url': final, 'final_registrable_domain': 'example.com', 'tls': {'verified': True}})
    out = decide(ev, kb)
    assert out.entity.name == '공식 서비스' and 'official_match' in {s['type'] for s in out.signals}


def test_same_family_search_is_a_gap_but_password_and_post_still_warn():
    from checklib.inspect_page import inspect_page
    url = 'https://school-a.school.example/'
    kb = KB([], SiteCatalog([record()]))
    for method, field, expected_search in [('get', 'search', True), ('post', 'search', False), ('get', 'password', False)]:
        page = inspect_page(f'<form role=search method={method} action="https://school-b.school.example/search">'
                            f'<input type={field} name=q></form>'.encode(), url)
        out = decide(Evidence(parse=parse_url(url), candidates=kb.address_candidates(url), address_only=True,
                              similarity=compare(parse_url(url), []), page=page,
                              fetch={'ok': True, 'chain': [{'url': url, 'status': 200}], 'final_url': url,
                                     'final_registrable_domain': 'school.example', 'tls': {'verified': True}}), kb)
        if expected_search:
            assert out.verdict == 'unknown'
            assert 'same_site_search' in {s['type'] for s in out.signals}
            assert 'cross_domain_form' not in {s['type'] for s in out.signals}
            assert 'search_destination_unverified' in out.verification_gaps
        else:
            assert out.verdict == 'caution' and 'cross_domain_form' in {s['type'] for s in out.signals}


def test_submit_override_and_cross_registration_do_not_gain_search_exception():
    from checklib.inspect_page import inspect_page
    url = 'https://school-a.school.example/'
    html = b'<form id=f role=search><input type=search name=q></form><button form=f formmethod=post>Go</button>'
    assert inspect_page(html, url)['forms'][0]['search_only'] is False
    page = inspect_page(b'<form role=search action="https://unrelated.example/"><input type=search name=q></form>', url)
    kb = KB([], SiteCatalog([record()]))
    out = decide(Evidence(parse=parse_url(url), candidates=kb.address_candidates(url), address_only=True, page=page), kb)
    assert 'cross_domain_form' in {s['type'] for s in out.signals}


def redirect_collector():
    import importlib.util
    path = settings.kb_path.parents[1] / 'scripts/catalog/collect_service_redirects.py'
    spec = importlib.util.spec_from_file_location('redirect_collector', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_only_sourced_https_home_redirects_create_short_lived_exact_evidence():
    mod = redirect_collector()
    row = {'name': '서비스', 'url': 'https://service.example.com/', 'source': 'https://corp.example/services'}
    responses = {'https://service.example.com/': (302, 'https://touch.example.com/'),
                 'https://touch.example.com/': (200, None)}
    records = mod.observe(row, responses.__getitem__)
    assert len(records) == 1 and records[0]['scope'] == 'url'
    assert records[0]['source'] == row['source']
    assert records[0]['canonical_from'] == row['url'] and records[0]['expires_at']
    for target in ['http://touch.example.com/', 'https://attacker.example/',
                   'https://touch.example.com/?token=secret', 'https://touch.example.com/login']:
        calls = []
        def get(url):
            calls.append(url)
            return 302, target
        assert mod.observe(row, get) == [] and calls == [row['url']]
    row['url'] = 'https://alice.github.io/'
    assert mod.observe(row, lambda url: (302, 'https://bob.github.io/')) == []


def test_canonical_expiry_and_primary_directory_priority():
    from datetime import datetime, timezone
    canonical = record('mobile.example.com', id='a', evidence_type='publisher_home_redirect',
                       expires_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat())
    assert not SiteCatalog.fresh(canonical)
    canonical['expires_at'] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    original = record('mobile.example.com', id='z', name='원래 기관')
    assert SiteCatalog([canonical, original]).lookup('https://mobile.example.com/')['id'] == 'z'


def test_kindergarten_disclosure_keeps_homepage_provenance_and_discards_staff_data():
    import importlib.util
    path = settings.kb_path.parents[1] / 'scripts/catalog/collect_kindergartens.py'
    spec = importlib.util.spec_from_file_location('kindergarten_collector', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    data = {'header': ['유치원명', '설립유형', '홈페이지', '교육지원청명', '원장명', '주소'],
            'body': [['테스트유치원', '공립(단설)', 'https://kinder.school.example/', '테스트교육지원청', '비공개테스트이름', '상세주소']]}
    rows = mod.normalize(data, '20261')
    assert rows[0]['url'] == 'https://kinder.school.example/' and rows[0]['kind'] == 'kindergarten'
    assert rows[0]['source'] == 'https://e-childschoolinfo.moe.go.kr/openData.do'
    assert '비공개테스트이름' not in json.dumps(rows, ensure_ascii=False)
    assert '상세주소' not in json.dumps(rows, ensure_ascii=False)


def test_national_kindergarten_snapshot_is_indexed_without_inventing_missing_homepages():
    source = json.loads(settings.kb_path.with_name('sources').joinpath('kindergartens.json').read_text())
    assert len(source['records']) >= 5000
    kb = KB.load()
    row = next(r for r in source['records'] if r['url'].startswith('http'))
    assert kb.catalog.lookup(row['url'])['verified']
    report = json.loads(settings.kb_path.with_name('sources').joinpath('coverage.json').read_text())
    assert report['source_rows']['kindergartens'] == len(source['records'])
    assert any(r['source'] == 'https://e-childschoolinfo.moe.go.kr/openData.do' for r in report['excluded'])


def catalog_builder():
    import importlib.util
    path = settings.kb_path.parents[1] / 'scripts/catalog/build_catalog.py'
    spec = importlib.util.spec_from_file_location('catalog_builder', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_one_listed_tenant_does_not_identify_entire_shared_host():
    mod = catalog_builder()
    for url in ['https://shared.example/school-a', 'https://shared.example/?school=a']:
        row = mod.clean({'url': url})
        scope = mod.identity_scope(row, {'가학교'})
        kb = KB([], SiteCatalog([record('shared.example', url=url, scope=scope)]))
        entity = kb.address_candidates(url)[0][0]
        assert entity.matches('shared.example', url)
        for other in ['https://shared.example/', 'https://shared.example/school-b',
                      'https://shared.example/?school=b']:
            assert not kb.address_candidates(other)
            assert not entity.matches('shared.example', other)


def test_source_cleanup_only_repairs_export_bom_and_classifies_exclusions():
    mod = catalog_builder()
    original = '\ufeff\ufeffhttp://school.example/a/'
    row, reason = mod.clean_with_reason({'url': original})
    assert reason is None and row['url'] == 'http://school.example/a/'
    assert row['original_url'] == original and row['normalization']
    cases = [('', 'missing_homepage'), ('http://', 'missing_homepage'),
             ('https://school.example:0/', 'invalid_port'),
             ('http://210.106.100.174/', 'ip_literal_not_supported'),
             ('http://school@naver.com', 'userinfo_or_email'),
             ('http://school. example', 'malformed_or_multiple_values'),
             ('https://one.example, https://two.example', 'malformed_or_multiple_values'),
             ('ftp://school.example', 'unsupported_or_malformed_scheme')]
    for value, expected in cases:
        row, reason = mod.clean_with_reason({'url': value})
        assert row is None and reason == expected


def test_index_never_broadens_sourced_paths_and_exclusion_report_reconciles():
    from urllib.parse import urlsplit
    kb = KB.load()
    for r in kb.catalog.by_id.values():
        parts = urlsplit(r['url'])
        if r['verified'] and ((parts.path or '/') != '/' or parts.query):
            assert r['scope'] == 'url', r['url']
    # Real single-tenant short link previously claimed all bit.ly addresses.
    assert kb.catalog.describe('https://bit.ly/3IuoU6C')['status'] == 'verified'
    assert kb.catalog.describe('https://bit.ly/unlisted-tenant')['status'] == 'unverified'
    report = json.loads(settings.kb_path.with_name('sources').joinpath('coverage.json').read_text())
    assert sum(report['excluded_by_source'].values()) == len(report['excluded'])
    assert sum(report['excluded_by_reason'].values()) == len(report['excluded'])
    assert sum(sum(c.values()) for c in report['excluded_source_reasons'].values()) == len(report['excluded'])

import importlib.util
import json

import pytest

from app.config import settings
from app.kb import KB
from app.site_catalog import SiteCatalog
from app.verdict import Evidence, decide
from checklib.parse_url import parse_url


def collector():
    path = settings.kb_path.parents[1] / 'scripts/catalog/collect_services.py'
    spec = importlib.util.spec_from_file_location('service_collector', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_literal_state_resolves_only_data_and_never_runs_code():
    read = collector().read_nuxt_literal
    assert read('window.__NUXT__=(function(a,b){return {data:[a,b],empty:void 0}}("가나다",false));') == {
        'data': ['가나다', False], 'empty': None}
    for script in [
        'window.__NUXT__=(function(){return {data:fetch("https://evil.example/")}}());',
        'window.__NUXT__=(function(){return {data:globalThis.process}}());',
        'window.__NUXT__=(function(){return {__proto__:{polluted:true}}}());',
        'window.__NUXT__=(function(a,a){return {data:a}}(1,2));',
        'window.__NUXT__=(function(){return {data:1,data:2}}());',
        'window.__NUXT__=(function(){return {data:1}}());alert(1);',
        'window.__NUXT__=(function(){return ' + '[' * 65 + '0' + ']' * 65 + '}());',
    ]:
        with pytest.raises(ValueError):
            read(script)


def test_publisher_state_keeps_only_live_web_links_and_exact_scope():
    mod = collector()
    publisher = {'url': 'https://corp.example/services', 'format': 'nuxt_literal_directory',
                 'state_path': ['data', 0, 'listData'], 'content_type': 'SERVICE_ALL',
                 'web_icon_type': 'ICON', 'web_link_titles': ['PC'], 'scope': 'url'}
    links = [{'linkUrl': url, 'linkTitle': title, 'resourceType': 'ICON' if title is None else None,
              'deleteYn': deleted, 'templateType': 'LINKS'} for url, title, deleted in [
                  ('https://service.example/tenant-a', None, 'N'),
                  ('https://store.example/app', 'Android', 'N'),
                  ('https://files.example/app.exe', 'PC', 'N'),
                  ('https://retired.example/', None, 'Y'),
                  ('https://broken.example:bad/', None, 'N'),
                  ('javascript:alert(1)', None, 'N')]]
    card = {'title': '공식 서비스', 'contentType': 'SERVICE_ALL', 'deleteYn': 'N', 'temporaryYn': 'N',
            'linkGroups': [{'links': links}]}
    data = {'data': [{'listData': {'발행사': [card, {**card, 'temporaryYn': 'Y', 'title': '초안'}]}}],
            'footer': {'linkUrl': 'https://unrelated.example/'}}
    html = '<script>window.__NUXT__=(function(){return ' + json.dumps(data) + '}());</script>'
    rows = mod.extract_services(html, publisher)
    assert len(rows) == 1 and rows[0]['url'] == 'https://service.example/tenant-a'
    assert rows[0]['publisher'] == '발행사' and rows[0]['scope'] == 'url'
    assert rows[0]['source'] == publisher['url'] and len(rows[0]['source_sha256']) == 64


def test_kakao_source_registers_map_and_mail_without_user_content_or_store_grants():
    kb = KB.load()
    for url, name in [('https://map.kakao.com/', '카카오맵'),
                      ('https://mail.kakao.com/', '카카오메일'),
                      ('https://talk.mail.kakao.com/', '카카오메일')]:
        r = kb.catalog.lookup(url)
        assert r['name'] == name and r['verified'] and r['scope'] == 'url'
        assert r['source'] == 'https://www.kakaocorp.com/page/service/all'
    assert kb.catalog.describe('https://brunch.co.kr/@unlisted-author/1')['status'] == 'unverified'
    assert kb.catalog.describe('https://unlisted-service.kakao.com/')['status'] == 'unverified'
    source = json.loads(settings.kb_path.with_name('sources').joinpath('official_services.json').read_text())
    added = [r for r in source['records'] if r['source'] == 'https://www.kakaocorp.com/page/service/all']
    assert len(added) >= 15
    assert not any('apps.apple.com' in r['url'] or 'play.google.com' in r['url'] for r in added)


def test_official_redirect_access_denial_is_identity_evidence_but_never_safe():
    from datetime import datetime, timezone
    path = settings.kb_path.parents[1] / 'scripts/catalog/collect_service_redirects.py'
    spec = importlib.util.spec_from_file_location('redirect_collector', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    source = {'name': '공식 지도', 'url': 'https://map.example.com/', 'source': 'https://corp.example/services'}
    for status in (401, 403, 429):
        def get(url):
            return (302, 'https://mobile.example.com/') if url == source['url'] else (status, None)
        records = mod.observe(source, get)
        assert len(records) == 1 and records[0]['page_access_confirmed'] is False
        r = {**records[0], 'id': 'map', 'host': 'mobile.example.com', 'family': 'example.com',
             'kind': 'official_service_directory', 'verified': True, 'checked': datetime.now(timezone.utc).date().isoformat()}
        kb = KB([], SiteCatalog([r]))
        final = r['url']
        evidence = Evidence(parse=parse_url(final), address_only=True, candidates=kb.address_candidates(final),
                            fetch={'ok': True, 'chain': [{'url': final, 'status': status}], 'final_url': final,
                                   'final_registrable_domain': 'example.com', 'tls': {'verified': True}},
                            page={'ok': True, 'forms': []})
        outcome = decide(evidence, kb)
        assert outcome.verdict == 'unknown' and 'http_status' in outcome.verification_gaps
        assert kb.identity_summary(final, outcome)['status'] == 'verified'
        from app.presentation import build_explanation
        explanation = build_explanation(outcome, evidence.page, 'example.com', None, False)
        assert '공식 주소로 확인' in explanation['headline']
        assert '정상 페이지 응답' in explanation['detail']
        assert explanation['unverified'] == ['정상 응답을 받지 못한 페이지의 내용과 동작']
        assert '다시 확인' not in explanation['recommended_action']
    for status in (404, 500):
        assert mod.observe(source, lambda url: (302, 'https://mobile.example.com/')
                           if url == source['url'] else (status, None)) == []
    # An isolated access-denied response has no source-to-destination edge.
    assert mod.observe(source, lambda url: (403, None)) == []

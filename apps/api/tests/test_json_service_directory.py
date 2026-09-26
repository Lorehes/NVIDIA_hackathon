import importlib.util
import json
from pathlib import Path

import pytest

from app.kb import KB

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('json_service_collector', ROOT / 'scripts/catalog/collect_services.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
CONFIG = {'name': '운영사', 'url': 'https://corp.example/services', 'format': 'json_directory',
          'script_id': 'DATA', 'state_path': ['services'], 'groups': ['web'],
          'title_key': 'title', 'url_key': 'linkUrl', 'schemes': ['http', 'https']}


def html(data):
    return '<script id="DATA" type="application/json">' + data + '</script>'


def test_only_configured_home_fields_qualify_and_http_stays_http():
    data = {'services': {'web': [{'title': '서비스', 'linkUrl': 'http://home.example/main/',
                                 'appDownLoad': {'apple': 'https://store.example/app'},
                                 'extraLink': {'devUrl': 'https://alpha.example/'} }],
                         'unreviewed': [{'title': '광고', 'linkUrl': 'https://ad.example/'}]},
            'footer': {'linkUrl': 'https://footer.example/'}}
    rows = collector.extract_services(html(json.dumps(data)), CONFIG)
    assert len(rows) == 1
    assert rows[0]['url'] == 'http://home.example/main/' and rows[0]['scope'] == 'url'
    assert rows[0]['source'] == CONFIG['url']


def test_ambiguous_template_and_download_values_are_not_home_addresses():
    urls = ['https://game.example/{{m}}mobile{{/m}}', 'https://files.example/app.exe',
            'https://one.example/https://two.example/', 'https://broken.example:bad/',
            'https://user@service.example/', 'https://white space.example/',
            'https://service.example\\@evil.example/', '', 'javascript:alert(1)']
    data = {'services': {'web': [{'title': '서비스', 'linkUrl': url} for url in urls]}}
    assert collector.extract_services(html(json.dumps(data)), CONFIG) == []


def test_reviewed_object_group_reads_only_its_home_field():
    config = {**CONFIG, 'group_shape': 'object'}
    data = {'services': {'web': {'title': '도구', 'linkUrl': 'https://tool.example/',
                                'faq': 'https://support.example/',
                                'unreviewed': [{'title': '광고', 'linkUrl': 'https://ad.example/'}]},
                         'other': {'title': '다른 서비스', 'linkUrl': 'https://other.example/'}}}
    rows = collector.extract_services(html(json.dumps(data)), config)
    assert len(rows) == 1 and rows[0]['url'] == 'https://tool.example/'
    assert rows[0]['scope'] == 'url' and rows[0]['name'] == '운영사 도구'


@pytest.mark.parametrize('value', [[], [{'title': '목록', 'linkUrl': 'https://list.example/'}], None, 'text'])
def test_object_group_rejects_changed_shapes(value):
    with pytest.raises(ValueError):
        collector.extract_services(html(json.dumps({'services': {'web': value}})),
                                   {**CONFIG, 'group_shape': 'object'})


def test_object_group_does_not_weaken_existing_url_or_json_validation():
    config = {**CONFIG, 'group_shape': 'object'}
    for url in ['javascript:alert(1)', 'https://user@tool.example/', 'https://tool.example/app.exe',
                'https://tool.example:bad/', 'https://tool.example/{{route}}']:
        assert collector.extract_services(html(json.dumps({'services': {'web': {'title': '도구', 'linkUrl': url}}})), config) == []
    with pytest.raises(ValueError):
        collector.extract_services(html('{"services":{"web":{"title":"one","title":"two","linkUrl":"https://tool.example/"}}}'), config)
    with pytest.raises(ValueError):
        collector.extract_services(html('{"services":{"web":{}}}'), {**config, 'group_shape': 'unknown'})


def test_json_does_not_execute_scripts_or_accept_ambiguous_state():
    for raw in ['{"services":fetch("https://evil.example/")}',
                '{"services":{},"services":{"web":[]}}', '{"__proto__":{}}']:
        with pytest.raises(ValueError):
            collector.extract_services(html(raw), CONFIG)
    with pytest.raises(ValueError):
        collector.extract_services(html('{}') + html('{}'), CONFIG)
    with pytest.raises(ValueError):
        collector.extract_services(html(' ' * 2_000_001), CONFIG)


def test_partial_refresh_preserves_each_unfetched_evidence_date():
    existing = {'checked': '2020-01-01', 'records': [
        {'source': 'old', 'name': 'old'}, {'source': 'newer', 'checked': '2021-01-01'},
        {'source': 'refresh', 'name': 'retired'}]}
    new = {'source': 'refresh', 'name': 'current', 'checked': '2026-09-26'}
    rows = collector.refresh_rows(existing, [new], {'refresh'})
    assert [r['checked'] for r in rows] == ['2020-01-01', '2021-01-01', '2026-09-26']
    assert not any(r.get('name') == 'retired' for r in rows)
    assert 'checked' not in existing['records'][0]


def test_redirect_collection_cannot_use_new_snapshot_date_to_renew_old_source():
    from datetime import date
    spec = importlib.util.spec_from_file_location('dated_redirect_collector', ROOT / 'scripts/catalog/collect_service_redirects.py')
    redirects = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(redirects)
    with pytest.raises(ValueError):
        redirects.require_fresh_sources([{'checked': '2020-01-01'}], '2026-09-26', date(2026, 9, 26))
    with pytest.raises(ValueError):
        redirects.require_fresh_sources([{'checked': '2026-09-27'}], '2026-09-26', date(2026, 9, 26))
    redirects.require_fresh_sources([{'checked': '2026-09-25'}], '2020-01-01', date(2026, 9, 26))
    redirects.require_fresh_sources([{}], '2026-09-26', date(2026, 9, 26))


def test_source_freshness_uses_utc_day_not_host_local_day(monkeypatch):
    from datetime import date, datetime, timezone
    import app.site_catalog as module
    class LocalDate(date):
        @classmethod
        def today(cls):
            raise AssertionError('host local date must not decide source freshness')
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            assert tz is timezone.utc
            return datetime(2026, 9, 25, 15, 30, tzinfo=tz)
    monkeypatch.setattr(module, 'date', LocalDate)
    monkeypatch.setattr(module, 'datetime', Clock)
    assert module.SiteCatalog.fresh({'checked': '2026-09-25'})
    assert not module.SiteCatalog.fresh({'checked': '2026-09-26'})
    assert not module.SiteCatalog.fresh({'checked': '2020-01-01'})


def test_nhn_source_exact_addresses_and_unfetched_publisher_dates_survive_build():
    source = json.loads((ROOT / 'kb/sources/official_services.json').read_text())
    nhn = [r for r in source['records'] if r['source'] == 'https://www.nhn.com/services']
    assert len(nhn) == 24
    kb = KB.load()
    for r in source['records']:
        matches = [v for v in kb.catalog.by_id.values()
                   if v['source'] == r['source'] and v['name'] == r['name'] and v['url'] == r['url']]
        assert matches and all(v['checked'] == r['checked'] for v in matches)
    for url in ['https://www.payco.com/', 'https://music.bugs.co.kr/', 'https://dooray.com/main/',
                'http://www.ticketlink.co.kr/home']:
        r = kb.catalog.lookup(url)
        assert r['source'] == 'https://www.nhn.com/services' and r['scope'] == 'url'
        assert kb.catalog.describe(url)['status'] == 'verified'
    for url in ['https://unlisted.hangame.com/', 'https://customer.dooray.com/',
                'https://dooray.com/main/unlisted/', 'https://www.godo.co.kr/customer-store/']:
        assert kb.catalog.describe(url)['status'] == 'unverified'

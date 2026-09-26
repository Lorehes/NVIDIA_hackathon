import importlib.util
import json
from pathlib import Path
import pytest
from app.kb import KB
from app.site_catalog import SiteCatalog

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('affiliate_collector', ROOT / 'scripts/catalog/collect_services.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
CONFIG = {'name':'발행자','url':'https://publisher.example/company','format':'named_affiliate_group',
          'group_class':'group','group_heading_tag':'p','group_heading':'계열사','maximum_records':2}


def group(items, heading='계열사'):
    return f'<div class="group"><p>{heading}</p><ul>{items}</ul></div>'


def item(url, name='계열사 하나'):
    return f'<li><a href="{url}">{name}</a></li>'


def test_only_named_affiliate_group_not_general_footer_links():
    html = group(item('https://one.example/?ref=publisher')) + group(item('https://blog.example/'), '블로그')
    html += '<footer><a href="https://advertiser.example/">광고</a></footer>'
    rows = collector.extract_services(html, CONFIG)
    assert len(rows) == 1 and rows[0]['name'] == '계열사 하나'
    assert rows[0]['url'] == 'https://one.example/?ref=publisher'
    assert rows[0]['kind'] == 'official_affiliate_directory'
    assert rows[0]['evidence_type'] == 'publisher_affiliate_link' and rows[0]['scope'] == 'url'


@pytest.mark.parametrize('html', [
    group(item('https://one.example/'), '계열사 안내가 변경됨'),
    group(item('https://one.example/')) * 2,
    '<div class=group><p>계열사</p><ul></ul><ul></ul></div>',
    group('<li><a href="https://one.example/">하나</a><a href="https://two.example/">둘</a></li>'),
    group(''.join(item(f'https://{n}.example/',str(n)) for n in range(3))),
])
def test_changed_missing_or_ambiguous_group_fails_closed(html):
    with pytest.raises(ValueError): collector.extract_services(html, CONFIG)


@pytest.mark.parametrize('url', ['javascript:alert(1)', 'http://plain.example/', 'https://user@wrong.example/',
                               'https://broken.example:bad/', 'https://bad.example:444/',
                               'https://files.example/app.apk', 'https://one.example/https://two.example/',
                               'https://one.example\\@two.example/', 'https://white space.example/'])
def test_unsafe_or_non_home_url_is_not_registered(url):
    assert collector.extract_services(group(item(url)),CONFIG) == []


def test_real_affiliates_keep_exact_paths_queries():
    data = json.loads((ROOT/'kb/sources/official_services.json').read_text())
    rows = [r for r in data['records'] if r['source'] == 'https://toss.im/company']
    assert len(rows) == 8 and all(r['scope'] == 'url' for r in rows)
    assert {r['name'] for r in rows} == {'토스뱅크','토스증권','토스페이먼츠','토스플레이스','토스모바일','토스인컴','토스인슈어런스','토스씨엑스'}
    kb = KB.load()
    registered = [r for r in kb.catalog.by_id.values() if r.get('source') == 'https://toss.im/company']
    exact = SiteCatalog(registered)
    for row in rows:
        assert exact.describe(row['url'])['status'] == 'verified'
        assert exact.lookup(row['url'] + ('&other=1' if '?' in row['url'] else '?other=1')) is None
    for u in ['https://corp.tossinvest.com/', 'https://www.tossinvest.com/',
              'https://tossincome.com/', 'https://merchant.tosspayments.com/', 'https://tossbank.com.unrelated.example/']:
        assert exact.lookup(u) is None

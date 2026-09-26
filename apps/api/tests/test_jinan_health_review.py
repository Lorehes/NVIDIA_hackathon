import json
from collections import defaultdict
from pathlib import Path

from app.kb import KB
from app.site_catalog import SiteCatalog

ROOT = Path(__file__).resolve().parents[3]


def test_jinan_shared_official_directories_keep_all_names_and_exact_boundaries():
    kb = KB.load()
    rows = [r for r in kb.catalog.by_id.values()
            if r.get('correction_source_row_sha256') and r['host'] == 'www.jinan.go.kr']
    assert len(rows) == 21
    grouped = defaultdict(set)
    for row in rows:
        assert row['scope'] == 'url' and row['original_url'] == ''
        assert row['correction_source_id'] is None
        grouped[row['url']].add(row['name'])
    assert sorted(len(v) for v in grouped.values()) == [1, 10, 10]
    exact = SiteCatalog(rows)
    for url, names in grouped.items():
        for catalog in (kb.catalog, exact):
            identity = catalog.describe(url)
            assert identity['status'] == 'verified'
            assert identity['matched_entities_total'] == len(names)
            assert {e['name'] for e in identity['matched_entities']} == names
        assert exact.lookup(url + ('&' if '?' in url else '?') + 'unreviewed=1') is None
        assert exact.lookup(url.replace('www.jinan.go.kr', 'other.jinan.go.kr')) is None
    assert exact.lookup('https://www.jinan.go.kr/') is None
    assert exact.lookup('https://www.jinan.go.kr/health/') is None
    assert exact.lookup('https://www.jinan.go.kr/health/board/list.jinan') is None
    # Source menu redirects are evidence, not an unreviewed family-wide alias.
    assert exact.lookup('https://www.jinan.go.kr/health/index.jinan?menuCd=DOM_000000601005001000') is None


def test_ambiguous_names_and_spelling_disagreement_remain_unmodified():
    raw = json.loads((ROOT / 'kb/sources/public_health.json').read_text())['records']
    corrections = json.loads((ROOT / 'kb/sources/verified_corrections.json').read_text())['records']
    health = [r for r in corrections if r['source_dataset'] == 'public_health']
    assert not {'반송보건진료소', '수항보건진료소', '수향보건진료소'} & {r['name'] for r in health}
    assert len([r for r in raw if r['name'] == '반송보건진료소' and r['url'] == '']) == 2
    assert any(r['name'] == '수항보건진료소' and r['url'] == '' for r in raw)
    coverage = json.loads((ROOT / 'kb/sources/coverage.json').read_text())
    assert len([r for r in coverage['excluded'] if r['name'] == '반송보건진료소']) == 2
    assert any(r['name'] == '수항보건진료소' for r in coverage['excluded'])

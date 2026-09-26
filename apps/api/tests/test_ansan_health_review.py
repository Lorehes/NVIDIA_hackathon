import json
from pathlib import Path

from app.kb import KB
from app.site_catalog import SiteCatalog

ROOT = Path(__file__).resolve().parents[3]


def test_ansan_health_institutions_remain_separate_on_shared_municipal_host():
    kb = KB.load()
    rows = [r for r in kb.catalog.by_id.values()
            if r.get('correction_source_row_sha256') and r['host'] == 'www.ansan.go.kr']
    assert {r['name'] for r in rows} == {
        '단원보건소', '상록수보건소', '원곡보건지소', '대부보건지소',
        '수암보건지소', '풍도보건진료소', '안산시남동보건진료소',
    }
    assert len({r['url'] for r in rows}) == 7
    exact = SiteCatalog(rows)
    for row in rows:
        assert row['scope'] == 'url' and row['original_url'] == ''
        for catalog in (exact, kb.catalog):
            identity = catalog.describe(row['url'])
            assert identity['status'] == 'verified'
            assert {e['name'] for e in identity['matched_entities']} == {row['name']}
        assert exact.lookup(row['url'] + ('&' if '?' in row['url'] else '?') + 'unreviewed=1') is None
        assert exact.lookup(row['url'].replace('www.ansan.go.kr', 'other.ansan.go.kr')) is None
    for other in ['https://www.ansan.go.kr/', 'https://www.ansan.go.kr/health/',
                  'https://www.ansan.go.kr/health/common/cntnts/selectContents.do',
                  'https://www.ansan.go.kr/health/common/cntnts/selectContents.do?cntnts_id=health19']:
        assert exact.lookup(other) is None
    corrections = json.loads((ROOT / 'kb/sources/verified_corrections.json').read_text())['records']
    namdong, = [r for r in corrections if r['name'] == '안산시남동보건진료소']
    evidence = namdong['evidence'][1]
    assert evidence['confirmed_institution'] == '남동보건진료소'
    assert evidence['name_mapping_reason'] == 'municipal_prefix_confirmed_by_location'
    assert evidence['institution_addresses'][0].startswith('안산시 단원구 ')
    coverage = json.loads((ROOT / 'kb/sources/coverage.json').read_text())
    assert not {r['name'] for r in rows} & {r['name'] for r in coverage['excluded']}

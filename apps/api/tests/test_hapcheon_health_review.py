import json
from pathlib import Path

from app.kb import KB
from app.site_catalog import SiteCatalog

ROOT = Path(__file__).resolve().parents[3]
BASE = 'https://www.hc.go.kr'
BRANCH = BASE+'/06237/06249/06259.web'
CLINIC = BASE+'/06237/06249/06260.web'
HOME = BASE+'/health.web'
BRANCH_NAMES = {'봉산면보건지소','묘산면보건지소','가야면보건지소','북부보건지소','쌍백면보건지소',
    '삼가면보건지소','가회면보건지소','대병면보건지소','초계면보건지소','쌍책면보건지소','덕곡면보건지소',
    '청덕면보건지소','적중면보건지소','율곡면보건지소','대양면보건지소','용주면보건지소'}
CLINIC_NAMES = {'장인보건진료소','양지보건진료소','숭산보건진료소','와리보건진료소','하남보건진료소',
    '이책보건진료소','대동보건진료소','소례보건진료소','낙진보건진료소','평지보건진료소',
    '동리보건진료소','대기보건진료소','장단보건진료소','병목보건진료소'}


def test_hapcheon_shared_pages_keep_all_reviewed_names_and_boundaries():
    kb=KB.load()
    rows=[r for r in kb.catalog.by_id.values() if r.get('correction_source_row_sha256') and r['host']=='www.hc.go.kr']
    assert len(rows)==31
    exact=SiteCatalog(rows)
    for url,names in [(BRANCH,BRANCH_NAMES),(CLINIC,CLINIC_NAMES),(HOME,{'합천군보건소'})]:
        for catalog in (exact,kb.catalog):
            result=catalog.describe(url)
            assert result['status']=='verified'
            assert {e['name'] for e in result['matched_entities']}==names
        assert exact.lookup(url+'?unreviewed=1') is None
        assert exact.lookup(url.replace('www.hc.go.kr','other.hc.go.kr')) is None
    for other in [BASE+'/',BASE+'/main.web',BASE+'/06260.web',BASE+'/06237/06249.web',BASE+'/health/other']:
        assert exact.lookup(other) is None
    assert all(r['scope']=='url' and r['original_url']=='' for r in rows)
    assert kb.catalog.by_id['site_9ce8156f3ccdbfa86dc8']['scope']=='url'
    coverage=json.loads((ROOT/'kb/sources/coverage.json').read_text())
    assert not (BRANCH_NAMES|CLINIC_NAMES|{'합천군보건소'}) & {r['name'] for r in coverage['excluded']}


def test_same_name_baeksan_is_deferred_without_altering_other_region():
    raw=json.loads((ROOT/'kb/sources/public_health.json').read_text())['records']
    names=[r for r in raw if r['name']=='백산보건진료소']
    assert len(names)==2 and sum(r['url']=='' for r in names)==1
    supplied=next(r for r in names if r['url'])
    assert 'jeongeup.go.kr' in supplied['url']
    coverage=json.loads((ROOT/'kb/sources/coverage.json').read_text())
    assert any(r['name']=='백산보건진료소' and r['reason']=='missing_homepage' for r in coverage['excluded'])
    assert not any(r['name']=='백산보건진료소' and r['source'].startswith(BASE)
                   for r in coverage['corrected_source_rows'])
    # The display is capped at 20 names; inspect all matches for preservation.
    matches=KB.load().catalog.lookup_all(supplied['url'])
    assert '백산보건진료소' in {r['name'] for r in matches}

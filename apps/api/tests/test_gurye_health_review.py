import json
from pathlib import Path

from app.kb import KB
from app.site_catalog import SiteCatalog

ROOT = Path(__file__).resolve().parents[3]
URL = 'https://www.gurye.go.kr/health/subPage.do?menuNo=130002002000'


def test_gurye_shared_directory_preserves_nineteen_institutions_and_scope():
    kb = KB.load()
    rows = [r for r in kb.catalog.by_id.values()
            if r.get('correction_source_row_sha256') and r['host'] == 'www.gurye.go.kr']
    assert len(rows) == 19 and {r['url'] for r in rows} == {URL}
    names = {r['name'] for r in rows}
    assert len([n for n in names if n.endswith('보건지소')]) == 7
    assert len([n for n in names if n.endswith('보건진료소')]) == 12
    for row in rows:
        assert row['scope'] == 'url' and row['original_url'] == ''
        assert row['correction_source_id'] is None
    exact = SiteCatalog(rows)
    for catalog in (exact, kb.catalog):
        identity = catalog.describe(URL)
        assert identity['status'] == 'verified'
        assert identity['matched_entities_total'] == 19
        assert {e['name'] for e in identity['matched_entities']} == names
    for other in [URL + '&unreviewed=1', URL.replace('menuNo=', 'other='),
                  URL.replace('www.gurye.go.kr', 'other.gurye.go.kr'),
                  'https://www.gurye.go.kr/health/subPage.do',
                  'https://www.gurye.go.kr', 'https://www.gurye.go.kr/health/main.do']:
        assert exact.lookup(other) is None
    # Existing city and medical-center identities remain distinct from their directory.
    assert not (names & {e['name'] for e in kb.catalog.describe('https://www.gurye.go.kr')['matched_entities']})
    assert not (names & {e['name'] for e in kb.catalog.describe('https://www.gurye.go.kr/health/main.do')['matched_entities']})
    coverage = json.loads((ROOT / 'kb/sources/coverage.json').read_text())
    excluded = {r['name'] for r in coverage['excluded'] if r['source_dataset'] == 'public_health'}
    assert not names & excluded
    assert {'반송보건진료소', '수항보건진료소'} <= excluded

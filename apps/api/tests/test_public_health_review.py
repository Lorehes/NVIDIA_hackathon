import json
from pathlib import Path
from app.kb import KB
from app.site_catalog import SiteCatalog

ROOT=Path(__file__).resolve().parents[3]


def test_municipal_health_pages_preserve_institution_query_boundaries():
    kb=KB.load()
    rows=[r for r in kb.catalog.by_id.values() if r.get('correction_source_row_sha256') and r['kind']=='public_health' and r['host']=='www.gjcity.go.kr']
    assert len(rows)==14 and len({r['url'] for r in rows})==14
    exact=SiteCatalog(rows)
    for row in rows:
        assert row['scope']=='url' and row['original_url']==''
        assert row['correction_source_id'] is None
        identity=exact.describe(row['url'])
        assert identity['status']=='verified' and identity['name']==row['name']
        assert {x['name'] for x in identity['matched_entities']}=={row['name']}
        assert {x['name'] for x in kb.catalog.describe(row['url'])['matched_entities']}=={row['name']}
        assert exact.lookup(row['url']+'&unreviewed=1') is None
        assert exact.lookup(row['url'].replace('mId=','otherId=')) is None
    for url in ['https://www.gjcity.go.kr/', 'https://www.gjcity.go.kr/depart/contents.do',
                'https://www.gjcity.go.kr/depart/contents.do?mId=0803040000',
                'https://other.gjcity.go.kr/depart/contents.do?mId=0803041100',
                'https://www.gwangju.go.kr/depart/contents.do?mId=0803041100']:
        assert exact.lookup(url) is None
    coverage=json.loads((ROOT/'kb/sources/coverage.json').read_text())
    excluded={r['name'] for r in coverage['excluded'] if r['source_dataset']=='public_health'}
    assert not ({r['name'] for r in rows}&excluded)
    assert {'반송보건진료소','수항보건진료소'}<=excluded
    city=[r for r in kb.catalog.by_id.values() if r['name']=='경기도 광주시청']
    assert city and all(r['scope']=='url' for r in city if r['host']=='www.gjcity.go.kr')

"""Collect only institution/homepage facts from the official national disclosure.

The public JSON includes staff names and precise addresses; those are not copied
into the site catalog. Discover the latest published round from the download UI.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

import html5lib
import httpx

ROOT = Path(__file__).resolve().parents[2]
SOURCE = 'https://e-childschoolinfo.moe.go.kr/openData.do'
ORIGIN = 'https://e-childschoolinfo.moe.go.kr'


def normalize(data, round_code):
    required = ['유치원명', '설립유형', '홈페이지', '교육지원청명']
    columns = {name: data['header'].index(name) for name in required}
    rows = []
    for values in data['body']:
        if len(values) != len(data['header']):
            raise ValueError('incomplete disclosure row')
        get = lambda name: str(values[columns[name]] or '').strip()
        rows.append({'name': get('유치원명'), 'url': get('홈페이지'), 'kind': 'kindergarten',
                     'establishment': get('설립유형'), 'education_office': get('교육지원청명'),
                     'source': SOURCE, 'source_updated': round_code,
                     'source_id': hashlib.sha256((get('교육지원청명') + '\n' + get('유치원명')).encode()).hexdigest()[:20]})
    return rows


def main():
    with httpx.Client(timeout=90, follow_redirects=False) as client:
        response = client.get(SOURCE)
        response.raise_for_status()
        tree = html5lib.parse(response.text, namespaceHTMLElements=False)
        timing = next(e for e in tree.iter('select') if e.get('id') == 'timingList')
        round_code = next(e.get('value') for e in timing.iter('option') if e.get('value'))
        fields = client.get(f'{ORIGIN}/gongsi/{round_code}/findGongsiList.do')
        fields.raise_for_status()
        scope = fields.json()['일반 현황']
        parameters = {'combineSidoName': '전체 시/도', 'combineSidoCode': '99',
                      'timingListCode': round_code, 'gongsiListCode': scope, 'ExcelCsv': '3'}
        response = client.get(ORIGIN + '/download/getTotalOpenData.do', params=parameters)
        response.raise_for_status()
        rows = normalize(response.json(), round_code)
        if len(rows) < 5000:
            raise ValueError('unexpectedly incomplete national disclosure; previous snapshot retained')
    target = ROOT / 'kb/sources/kindergartens.json'
    temporary = target.with_suffix('.tmp')
    temporary.write_text(json.dumps({'checked': datetime.now(timezone.utc).date().isoformat(), 'disclosure_round': round_code,
                                    'source_sha256': hashlib.sha256(response.content).hexdigest(),
                                    'download_url': str(response.url), 'records': rows}, ensure_ascii=False, indent=2))
    temporary.replace(target)
    print('official kindergarten disclosure:', round_code, 'rows:', len(rows),
          'with homepage:', sum(bool(r['url']) for r in rows))


if __name__ == '__main__':
    main()

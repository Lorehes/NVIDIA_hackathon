from datetime import datetime, timezone, timedelta

from app.kb import KB
from app.site_catalog import SiteCatalog


def record(id, name, **changes):
    return {'id':id,'name':name,'host':'schools.example','family':'schools.example',
            'url':'https://schools.example/one/?tenant=1','scope':'url','verified':True,
            'kind':'school','source':'https://directory.example/'+id,
            'checked':datetime.now(timezone.utc).date().isoformat(),**changes}


def test_shared_names_require_matching_scope_and_current_official_evidence():
    rows=[record('school','학교'),record('kindergarten','병설유치원'),
          record('stale','오래된 기관',checked=(datetime.now(timezone.utc).date()-timedelta(days=91)).isoformat()),
          record('popular','인기 등재',verified=False),
          record('different-path','다른 학교',url='https://schools.example/two/?tenant=1'),
          record('different-query','다른 사용자',url='https://schools.example/one/?tenant=2'),
          record('different-port','다른 서비스',url='https://schools.example:444/one/?tenant=1')]
    catalog=SiteCatalog(rows)
    info=catalog.describe('https://schools.example/one/?tenant=1')
    assert info['status']=='verified' and info['matched_entities_total']==2
    assert {r['name'] for r in info['matched_entities']}=={'학교','병설유치원'}
    assert all(r['source'].startswith('https://directory.example/') for r in info['matched_entities'])
    assert catalog.describe('https://schools.example/unknown/')['matched_entities']==[]
    assert catalog.describe('https://unlisted.schools.example/one/?tenant=1')['matched_entities']==[]


def test_same_name_is_not_duplicated_and_payload_is_bounded_without_hiding_total():
    rows=[record(str(i),'기관 '+str(i)) for i in range(25)]
    rows.append(record('same-again','기관 0'))
    catalog=SiteCatalog(rows)
    info=catalog.describe(rows[0]['url'])
    assert len(info['matched_entities'])==20 and info['matched_entities_total']==25
    assert catalog.lookup(rows[0]['url'])['id']==catalog.lookup_all(rows[0]['url'])[0]['id']


def test_real_school_kindergarten_and_shared_game_directory_show_all_names():
    kb=KB.load()
    for url,names in [
        ('https://sinheungcho.goegu.kr/',{'신흥초등학교','신흥초등학교병설유치원'}),
        ('https://haneulbit-e.gpoe.kr/',{'하늘빛초등학교','하늘빛초등학교병설유치원'}),
        ('https://www.nhn-playart.com/game.nhn',{'NHN #콤파스','NHN LINE : 디즈니 츠무츠무','NHN 요괴워치 뿌니뿌니'})]:
        info=kb.catalog.describe(url)
        assert {r['name'] for r in info['matched_entities']}==names
        assert info['matched_entities_total']==len(names)
    assert kb.catalog.describe('https://sinheungcho.goegu.kr/unlisted-school/')['matched_entities']==[]


def test_no_expired_or_popularity_names_are_presented_as_shared_identity():
    catalog=SiteCatalog([record('rank','인기 사이트',verified=False),
                         record('expired','폐기된 근거',checked='2020-01-01')])
    info=catalog.describe('https://schools.example/one/?tenant=1')
    assert info['status']=='unverified' and info['matched_entities_total']==0
    assert info['matched_entities']==[]

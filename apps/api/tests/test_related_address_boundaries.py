from datetime import datetime, timedelta, timezone

from app.site_catalog import SiteCatalog


def record(id, host, path='/', **extra):
    return {'id':id, 'host':host, 'family':'school.example', 'name':id, 'url':'https://'+host+path,
            'verified':True, 'scope':'url', 'source':'https://directory.example/list',
            'checked':datetime.now(timezone.utc).date().isoformat(), **extra}


def test_different_schools_do_not_become_related_from_one_family():
    c=SiteCatalog([record('a','a.school.example'), record('b','b.school.example')])
    assert c.describe('https://a.school.example/')['related_addresses']==['a.school.example']
    assert c.describe('https://missing.school.example/')['related_addresses']==[]


def test_shared_host_does_not_relax_path_or_year_boundaries():
    c=SiteCatalog([record('a','help.school.example','/a?year=2025'),record('b','help.school.example','/b')])
    assert c.describe('https://help.school.example/a?year=2025')['related_addresses']==['help.school.example']
    assert c.describe('https://help.school.example/a?year=2026')['related_addresses']==[]
    assert c.describe('https://help.school.example/')['status']=='unverified'


def test_fresh_canonical_home_redirect_is_related_in_both_directions():
    a=record('a','www.school.example')
    b=record('b','m.school.example',canonical_from=a['url'],evidence_type='publisher_home_redirect',
             expires_at=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())
    c=SiteCatalog([a,b,record('unrelated','tenant.school.example')])
    for url in (a['url'],b['url']):
        assert c.describe(url)['related_addresses']==['m.school.example','www.school.example']
    assert c.describe(b['url']+'user-document')['status']=='unverified'


def test_expired_or_unverified_redirect_never_relates_hosts():
    a=record('a','www.school.example')
    fresh=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()
    for extra in ({'verified':False},{'expires_at':'2000-01-01T00:00:00+00:00'},{'expires_at':None}):
        b=record('b','m.school.example',canonical_from=a['url'],evidence_type='publisher_home_redirect',
                 **{'expires_at':fresh,**extra})
        assert SiteCatalog([a,b]).describe(a['url'])['related_addresses']==[a['host']]


def test_missing_stale_or_different_source_cannot_anchor_redirect():
    a=record('a','www.school.example')
    b=record('b','m.school.example',canonical_from=a['url'],evidence_type='publisher_home_redirect',
             expires_at=(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat())
    for rows in ([b],[{**a,'checked':'2000-01-01'},b],[{**a,'source':'https://other.example/'},b]):
        assert SiteCatalog(rows).describe(b['url'])['related_addresses']==[b['host']]


def test_popular_family_is_not_an_identity_relation():
    popular=record('popular','www.school.example',verified=False)
    c=SiteCatalog([popular,record('a','a.school.example')])
    assert c.describe(popular['url'])['related_addresses']==[]

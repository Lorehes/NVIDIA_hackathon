from datetime import datetime, timezone
import json

from app.config import settings
from app.db import DB
from app.kb import KB
from app.models import InvestigationResult, Trace
from app.site_catalog import SiteCatalog
from app.worker import Investigator, make_steps
from checklib.parse_url import parse_url


def record(url):
    p = parse_url(url)
    return {'id': 'test', 'url': url, 'host': p['host_ascii'], 'family': p['registrable_domain'],
            'name': '테스트학교', 'scope': 'url', 'kind': 'school', 'verified': True,
            'source': 'https://directory.example/', 'checked': datetime.now(timezone.utc).date().isoformat(),
            'inspection_supported': False, 'inspection_limit_reason': 'unsupported_port'}


def test_nonstandard_port_identity_stays_on_the_sourced_service_and_path():
    url = 'https://school.example:451/home/'
    kb = KB([], SiteCatalog([record(url)]))
    entity = kb.address_candidates(url)[0][0]
    assert entity.matches('school.example', url)
    for other in ['https://school.example/home/', 'https://school.example:452/home/',
                  'http://school.example:451/home/', 'https://school.example:451/other/']:
        assert kb.catalog.describe(other)['status'] == 'unverified'
        assert not entity.matches('school.example', other)
    default = record('https://school.example/')
    default.update(scope='host', inspection_supported=True)
    assert SiteCatalog([default]).lookup('https://school.example:451/') is None


def test_unsupported_port_pipeline_preserves_identity_without_dns_sandbox_or_ai(tmp_env):
    class NoNetwork:
        def investigate(self, *args, **kwargs):
            raise AssertionError('must not open any sandbox policy')
        def explain(self, *args, **kwargs):
            raise AssertionError('must not call AI')
    def no_dns(host):
        raise AssertionError('must not resolve unsupported ports')
    for i, url in enumerate(['https://school.example:451/home/', 'https://한글학교.kr:451/home/']):
        kb = KB([], SiteCatalog([record(url)]))
        db = DB(':memory:')
        db.create({'job_id': f'port-{i}', 'status': 'queued', 'stage': 'parse', 'mode': 'live',
                   'input': url, 'url': url, 'steps': make_steps()})
        Investigator(db, NoNetwork(), kb, resolver=no_dns).run(f'port-{i}')
        job = db.get(f'port-{i}')
        assert job['status'] == 'done', job.get('error')
        result = InvestigationResult.model_validate(job['result'])
        Trace.model_validate(job['trace'])
        assert result.verdict == 'unknown' and result.identity['status'] == 'verified'
        assert result.identity['behavior'] == 'incomplete' and result.agent.kind == 'not_run'
        assert result.url_parts.matches_official
        assert result.connection['verified'] is None and result.redirect_chain == []
        assert '공식 주소로 확인' in result.explanation.headline
        assert '사이트에 접속하지 않았어요' in result.explanation.detail
        assert '다시 확인' not in result.explanation.recommended_action
        assert not any(s.type == 'domain_not_official' for s in result.signals)
        assert job['trace']['sandbox']['events'] == []


def test_official_port_records_are_registered_separately_from_inspection_gaps():
    report = json.loads(settings.kb_path.with_name('sources').joinpath('coverage.json').read_text())
    assert len(report['inspection_limited']) == 22
    kb = KB.load()
    for row in report['inspection_limited']:
        r = kb.catalog.lookup(row['url'])
        assert r and r['verified'] and r['scope'] == 'url'
        assert r['inspection_supported'] is False
        assert row['url'] not in {x['url'] for x in report['excluded']}
        assert r['source'] == row['source']

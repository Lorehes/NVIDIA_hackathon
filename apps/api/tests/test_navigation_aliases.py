import httpx
import pytest
import yaml

from app.sandbox import render_preset, SandboxError
from checklib.navigation import navigation_hosts
from checklib.fetch_chain import HttpxFetcher, fetch_chain


@pytest.mark.parametrize('host', ['naver.com', 'www.naver.com', 'm.naver.com'])
def test_standard_navigation_addresses(host):
    assert set(navigation_hosts(host)) == {'naver.com', 'www.naver.com', 'm.naver.com'}
    assert navigation_hosts(host)[0] == host


@pytest.mark.parametrize('host', ['login.naver.com', 'www.naver.com.evil.test', 'github.io',
                                  'alice.github.io', 'www.alice.github.io', 'blogspot.com',
                                  '127.0.0.1', 'localhost', 'www.internal', 'co.kr'])
def test_no_alias_expansion_for_other_hosts(host):
    assert navigation_hosts(host) == (host,)


def test_co_kr_is_one_registration_boundary():
    assert set(navigation_hosts('www.example.co.kr')) == {'example.co.kr', 'www.example.co.kr', 'm.example.co.kr'}


def test_policy_has_only_exact_aliases_get_and_standard_ports():
    hosts = list(navigation_hosts('www.naver.com'))
    policy = yaml.safe_load(render_preset('j_alias', 'www.naver.com', hosts))['network_policies']['job-j-alias']
    assert {(e['host'], e['port']) for e in policy['endpoints']} == {(h, p) for h in hosts for p in [80, 443]}
    assert all(e['rules'] == [{'allow': {'method': 'GET', 'path': '/**'}}] for e in policy['endpoints'])
    with pytest.raises(SandboxError):
        render_preset('j_alias', 'naver.com', ['naver.com', 'naver.com.evil.test'])


@pytest.mark.parametrize('start', ['naver.com', 'www.naver.com'])
def test_mobile_redirect_reaches_page(start):
    seen = []
    def handler(request):
        seen.append(request.url.host)
        if request.url.host == 'm.naver.com':
            return httpx.Response(200, headers={'content-type': 'text/html'}, stream=httpx.ByteStream(b'<html>mobile</html>'))
        return httpx.Response(302, headers={'location': 'https://m.naver.com/'}, stream=httpx.ByteStream(b''))
    f = HttpxFetcher(allowed_hosts=list(navigation_hosts(start)))
    f._client.close()
    f._client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result, html = fetch_chain('https://' + start, f)
        assert result['blocked_count'] == 0 and result['chain'][-1]['status'] == 200
        assert html == b'<html>mobile</html>' and seen == [start, 'm.naver.com']
    finally:
        f.close()


@pytest.mark.parametrize('destination', ['https://naver.com.evil.test/', 'https://evil.com/',
                                       'https://login.naver.com/', 'http://127.0.0.1/',
                                       'http://169.254.169.254/', 'https://m.naver.com:8443/'])
def test_redirect_outside_scope_is_blocked_before_network(destination):
    seen = []
    def handler(request):
        seen.append(str(request.url))
        return httpx.Response(302, headers={'location': destination}, stream=httpx.ByteStream(b''))
    f = HttpxFetcher(allowed_hosts=list(navigation_hosts('naver.com')))
    f._client.close()
    f._client = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        result, _ = fetch_chain('https://naver.com/', f)
        assert result['blocked_count'] == 1 and len(seen) == 1
    finally:
        f.close()


def test_worker_starts_with_only_requested_host_and_discovers_destinations(tmp_env):
    from app.config import settings
    from app.db import DB
    from app.kb import KB
    from app.worker import Investigator
    class StopAfterCapture(Exception):
        pass
    class Capture:
        def investigate(self, job_id, payload, target, allowed, on_stage):
            assert allowed and payload['allowed_hosts'] == ['naver.com']
            assert payload['navigation_mode'] == 'discover'
            raise StopAfterCapture()
    db = DB(settings.db_path)
    inv = Investigator(db, Capture(), KB([]), resolver=lambda h: h == 'm.naver.com')
    inv._set = lambda *a, **kw: None
    with pytest.raises(StopAfterCapture):
        inv._run({'job_id': 'j_alias', 'url': 'https://naver.com', 'input': 'naver.com'}, {})

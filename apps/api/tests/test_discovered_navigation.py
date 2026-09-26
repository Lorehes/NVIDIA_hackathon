import json
import socket
from pathlib import Path

import pytest
import yaml

from app.sandbox import OpenShellSandbox, CmdResult
from checklib.navigation import public_destination
from checklib.parse_url import parse_url
from tests.test_sandbox_openshell import FakeRunner


def dns(*ips):
    return lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 443)) for ip in ips]


@pytest.mark.parametrize('url', ['http://127.0.0.1/', 'http://169.254.169.254/', 'https://service.local/',
                                 'https://user@example.com/', 'https://example.com:8443/', 'file:///etc/passwd'])
def test_reject_unsafe_navigation(url):
    with pytest.raises(ValueError):
        public_destination(url, dns('8.8.8.8'))


@pytest.mark.parametrize('addresses', [[], ['10.0.0.1'], ['8.8.8.8', '127.0.0.1'], ['::ffff:127.0.0.1'], ['224.0.0.1']])
def test_dns_must_have_only_public_answers(addresses):
    with pytest.raises(ValueError):
        public_destination('https://never-seen.example/', dns(*addresses))


def test_any_public_host_can_be_investigated_without_a_site_list():
    assert public_destination('https://brand-new.example/path', dns('8.8.8.8')) == 'brand-new.example'


def hop(url, status=200, **kw):
    p = parse_url(url)
    return {'url': url, 'host': p['host_ascii'], 'registrable_domain': p['registrable_domain'],
            'status': status, 'error': None, 'blocked': False, **kw}


class RedirectRunner(FakeRunner):
    def __init__(self, destination='https://login.new-service.com/', reject_add=False):
        super().__init__()
        self.destination = destination
        self.grants = []
        self.reject_add = reject_add
        self.live = {}
        self.download_files = {'fetch_chain': {'ok': True, 'chain': [
            hop('https://entry.example/', 302, redirect_url=destination),
            hop(destination, 403, blocked=True, block_reason='navigation outside allowed site addresses')]}}

    def __call__(self, args, timeout=None):
        if args[:3] == ['openshell', 'policy', 'set']:
            self.calls.append(args)
            policy = yaml.safe_load(Path(args[args.index('--policy') + 1]).read_text())
            self.live = policy['network_policies']
            self.active_policies = set(self.live)
            self.grants.append(next(iter(self.live.values()))['endpoints'])
            if self.reject_add and len(self.grants) == 2:
                raise TimeoutError('added but response lost')
            return CmdResult(0, '', '')
        if args[:3] == ['openshell', 'policy', 'update']:
            self.calls.append(args)
            name = args[args.index('--remove-rule') + 1]
            self.live.pop(name, None)
            self.active_policies.discard(name)
            return CmdResult(0, '', '')
        if args[:3] == ['openshell', 'policy', 'get']:
            self.calls.append(args)
            return CmdResult(0, json.dumps({'status': 'effective', 'sandbox': 'my-assistant',
                                           'policy': {'network_policies': self.live}}), '')
        result = super().__call__(args, timeout)
        if 'python3' in args and any('run_checks.py' in a for a in args):
            self.download_files['fetch_chain']['chain'][-1] = hop(self.destination)
        return result


def run_case(tmp_path, monkeypatch, runner, permit=True):
    import app.sandbox as mod
    if permit:
        monkeypatch.setattr(mod, 'resolve_public_destination', lambda u: (parse_url(u)['host_ascii'], ['8.8.8.8']))
    else:
        def denied(u):
            if parse_url(u)['host_ascii'] == 'entry.example':
                return ('entry.example', ['8.8.8.8'])
            raise ValueError('private_destination')
        monkeypatch.setattr(mod, 'resolve_public_destination', denied)
    payload = {'url': 'https://entry.example/', 'message_text': '문자 내용', 'navigation_mode': 'discover',
               'allowed_hosts': ['entry.example']}
    return OpenShellSandbox(runner, workdir=tmp_path).investigate('j_1', payload, 'entry.example', True)


def test_new_redirect_host_is_granted_exact_get_only_then_revoked(tmp_path, monkeypatch):
    runner = RedirectRunner()
    result = run_case(tmp_path, monkeypatch, runner)
    assert result.incomplete is None
    assert result.files['fetch_chain']['chain'][-1]['status'] == 200
    assert runner.active_policies == set()
    assert {e['host'] for e in runner.grants[-1]} == {'entry.example', 'login.new-service.com'}
    assert all(e['rules'] == [{'allow': {'method': 'GET', 'path': '/**'}}] for e in runner.grants[-1])
    assert all(e['allowed_ips'] == ['8.8.8.8'] for e in runner.grants[-1])
    assert result.agent['navigation'][0]['allowed'] is True


def test_private_redirect_never_gains_policy(tmp_path, monkeypatch):
    runner = RedirectRunner('http://private.example/')
    result = run_case(tmp_path, monkeypatch, runner, permit=False)
    assert len(runner.grants) == 1 and not runner.active_policies
    assert result.agent['navigation'][0]['reason'] == 'private_destination'
    assert result.files['fetch_chain']['chain'][-1]['blocked']


def test_replacement_timeout_still_removes_new_policy(tmp_path, monkeypatch):
    runner = RedirectRunner(reject_add=True)
    result = run_case(tmp_path, monkeypatch, runner)
    assert result.incomplete is not None and not runner.active_policies and not result.residual_policy


def test_invented_redirect_edge_never_grants_policy(tmp_path, monkeypatch):
    runner = RedirectRunner()
    runner.download_files['fetch_chain']['chain'][-2]['redirect_url'] = 'https://different.example/'
    result = run_case(tmp_path, monkeypatch, runner)
    assert len(runner.grants) == 1
    assert result.agent['navigation'][0]['allowed'] is False


class RotatingDnsRunner(RedirectRunner):
    def __init__(self):
        super().__init__('https://entry.example/')
        self.download_files['fetch_chain']['chain'] = [hop(self.destination, 403, blocked=True, block_reason='403 Forbidden')]


def test_public_cdn_rotation_refreshes_exact_ips_once_and_revokes(tmp_path, monkeypatch):
    import app.sandbox as mod
    answers = iter([['8.8.8.8'], ['1.1.1.1']])
    monkeypatch.setattr(mod, 'resolve_public_destination', lambda u: ('entry.example', next(answers)))
    runner = RotatingDnsRunner()
    payload = {'url': 'https://entry.example/', 'message_text': 'message', 'navigation_mode': 'discover',
               'allowed_hosts': ['entry.example']}
    result = OpenShellSandbox(runner, workdir=tmp_path).investigate('j_1', payload, 'entry.example', True)
    assert result.incomplete is None and not runner.active_policies
    assert runner.grants[-1][0]['allowed_ips'] == ['1.1.1.1', '8.8.8.8']
    assert {e['host'] for e in runner.grants[-1]} == {'entry.example'}
    assert result.agent['navigation'][0]['reason'] == 'public_dns_refresh'


def test_unchanged_dns_does_not_retry_or_widen_a_proxy_denial(tmp_path, monkeypatch):
    runner = RotatingDnsRunner()
    result = run_case(tmp_path, monkeypatch, runner)
    assert len(runner.grants) == 1 and not runner.active_policies
    assert result.agent['navigation'][0]['reason'] == 'dns_answers_unchanged'


def test_dns_rotation_to_private_destination_never_replaces_policy(tmp_path, monkeypatch):
    import app.sandbox as mod
    calls = []
    def resolver(url):
        calls.append(url)
        if len(calls) > 1:
            raise ValueError('private_destination')
        return 'entry.example', ['8.8.8.8']
    monkeypatch.setattr(mod, 'resolve_public_destination', resolver)
    runner = RotatingDnsRunner()
    payload = {'url': 'https://entry.example/', 'message_text': 'message', 'navigation_mode': 'discover',
               'allowed_hosts': ['entry.example']}
    result = OpenShellSandbox(runner, workdir=tmp_path).investigate('j_1', payload, 'entry.example', True)
    assert len(runner.grants) == 1 and not runner.active_policies
    assert result.agent['navigation'][0]['reason'] == 'private_destination'

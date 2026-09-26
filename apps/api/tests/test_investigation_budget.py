import threading
import time

import pytest

from app import budget
from app.config import settings
from app.db import DB
from app.kb import KB
from app.sandbox import CmdResult, OpenShellSandbox
from app.worker import Investigator
from .test_sandbox_openshell import FakeRunner, payload


def test_phases_share_monotonic_deadline_and_cleanup_is_reserved(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(budget.time, 'monotonic', lambda: clock[0])
    with budget.investigation(90, 15):
        assert budget.timeout(60) == 60
        clock[0] += 50
        args, limit = budget.command(['openshell', '--timeout=65', '--', 'openclaw', '--timeout', '60'], 70)
        assert limit == 25
        assert args == ['openshell', '--timeout=24', '--', 'openclaw', '--timeout', '24']
        clock[0] = 175
        with pytest.raises(budget.BudgetExpired):
            budget.command(['openshell', 'policy', 'set'], 35)
        with budget.cleanup():
            assert budget.timeout(35) == 15
        with pytest.raises(budget.BudgetExpired):
            budget.timeout()
        assert budget.timeout(finishing=True) == 15
        clock[0] = 190
        with budget.cleanup(), pytest.raises(budget.BudgetExpired):
            budget.timeout()
    assert budget.timeout(60) == 60


def test_remote_command_not_started_with_subsecond_budget(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr(budget.time, 'monotonic', lambda: clock[0])
    with budget.investigation(90, 15):
        clock[0] = 74.5
        with pytest.raises(budget.BudgetExpired):
            budget.command(['openshell', '--timeout=35'], 40)


def test_dns_read_stops_waiting_and_discards_late_answer():
    release = threading.Event()
    try:
        started = time.monotonic()
        with budget.investigation(.15, .10), pytest.raises(budget.BudgetExpired):
            budget.read_only(lambda: (release.wait(2), 'public-address'))
        assert time.monotonic() - started < .5
    finally:
        release.set()


def test_read_worker_capacity_fails_closed(monkeypatch):
    monkeypatch.setattr(budget, '_read_slots', threading.BoundedSemaphore(0))
    with budget.investigation(), pytest.raises(budget.BudgetExpired):
        budget.read_only(lambda: pytest.fail('must not launch a read'))


def test_agent_deadline_still_releases_permissions(monkeypatch, tmp_path):
    clock = [0.0]
    monkeypatch.setattr(budget.time, 'monotonic', lambda: clock[0])

    class SlowAgent(FakeRunner):
        def __call__(self, args, timeout=None):
            if 'openclaw' in args:
                clock[0] = 75.0
                raise TimeoutError('simulated exhausted investigation')
            return super().__call__(args, timeout)

    runner = SlowAgent()
    box = OpenShellSandbox(runner, workdir=tmp_path)
    with budget.investigation():
        result = box.investigate('j_' + 'a'*32, payload(), 'a.test', True)
    assert result.incomplete == 'agent_timeout'
    assert not result.residual_policy and not box.quarantined
    assert not runner.active_policies
    assert any(c[2:4] == ['policy', 'remove'] for c in runner.calls)
    assert not any(c[:3] == ['openshell', 'sandbox', 'download'] for c in runner.calls)


def test_cleanup_deadline_quarantines_and_preserves_pending_purge(monkeypatch, tmp_path):
    clock = [0.0]
    monkeypatch.setattr(budget.time, 'monotonic', lambda: clock[0])

    class StuckCleanup(FakeRunner):
        def __call__(self, args, timeout=None):
            if 'openclaw' in args:
                clock[0] = 75.0
                raise TimeoutError('agent')
            if args[2:4] == ['policy', 'remove']:
                clock[0] = 90.0
                raise TimeoutError('cleanup')
            return super().__call__(args, timeout)

    runner = StuckCleanup()
    box = OpenShellSandbox(runner, workdir=tmp_path)
    jid = 'j_' + 'b'*32
    with budget.investigation():
        result = box.investigate(jid, payload(), 'a.test', True)
    assert result.incomplete and result.residual_policy and box.quarantined
    assert jid in box._pending_purge
    assert runner.active_policies


def test_worker_dns_timeout_finishes_without_opening_sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'investigation_timeout_s', .15)
    monkeypatch.setattr(settings, 'cleanup_reserve_s', .10)
    db = DB(tmp_path/'jobs.sqlite')
    jid = 'j_' + 'c'*32
    db.create({'job_id':jid, 'status':'queued', 'stage':'parse', 'mode':'live',
               'input':'https://example.com/', 'url':'https://example.com/'})
    release = threading.Event()

    class NeverOpen:
        def investigate(self, *args):
            pytest.fail('DNS timed out; must never open policy')

    inv = Investigator(db, NeverOpen(), KB([]), resolver=lambda h: release.wait(2))
    try:
        inv.run(jid)
    finally:
        release.set()
    row = db.get(jid)
    assert row['status'] == 'failed' and row['result'] is None
    assert '시간 제한' in row['error']
    assert row['timings']['total'] < 500


def test_cleanup_failure_without_timeout_never_reports_complete(tmp_path):
    runner = FakeRunner(remove_fail_times=5)
    result = OpenShellSandbox(runner, workdir=tmp_path).investigate('j_'+'d'*32, payload(), 'a.test', True)
    assert result.residual_policy and result.incomplete == 'policy_error'


@pytest.mark.parametrize('address_only', [False, True])
def test_remote_exit_124_is_a_timeout_and_still_closes_policy(tmp_path, address_only):
    class RemoteTimeout(FakeRunner):
        def __call__(self, args, timeout=None):
            if 'openclaw' in args or any(a.endswith('/run_checks.py') for a in args):
                return CmdResult(124, '', 'command deadline exceeded')
            return super().__call__(args, timeout)
    inp = payload()
    if address_only:
        inp.update(navigation_mode='discover', message_text=None, allowed_hosts=[])
    runner = RemoteTimeout()
    result = OpenShellSandbox(runner, workdir=tmp_path).investigate('j_'+'e'*32, inp, 'a.test', not address_only)
    assert result.incomplete == 'agent_timeout' and not result.residual_policy
    assert not runner.active_policies

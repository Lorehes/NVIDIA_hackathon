"""보안 점검 1라운드(Codex R1-01~R1-12) 회귀 테스트. 각 시험은 해당 지적의 재현 조건을 그대로 쓴다."""
import time

import pytest
from fastapi.testclient import TestClient

from app import verdict as V
from app.limits import RateLimiter
from app.main import app

from .conftest import SESSION_A
from .test_sandbox_openshell import FULL_ID, FakeRunner, payload, sb
from .test_urls_kb_explain import GOOD, TEMPLATE, _payload, kb
from .test_verdict import CAND, claim, decide, fetch, page, parse, similarity, types

from checklib import fetch_chain as fc  # noqa: E402
from checklib.parse_url import parse_url  # noqa: E402


# ── R1-01: 백슬래시로 브라우저와 해석이 갈리는 주소 ────────────────────────────────
def test_backslash_url_is_read_like_a_browser_and_marked_ambiguous():
    p = parse_url("https://evil.test\\@hanbit.example/")
    assert p["host_ascii"] == "evil.test" and p["ambiguous"] is True  # 브라우저(WHATWG)는 evil.test로 간다
    assert parse_url("https://hanbit.example/login")["ambiguous"] is False
    assert parse_url("https://hanbit.example/a\\b?x=\\")["host_ascii"] == "hanbit.example"


class Seq:
    """미리 정한 응답을 차례로 돌려주고 접속한 주소를 기록하는 가짜 접속기."""

    def __init__(self, *responses):
        self.responses, self.urls = list(responses), []

    def get(self, url):
        self.urls.append(url)
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r

    def close(self):
        pass


def test_fetcher_connects_to_the_browsers_destination_not_the_parsers():
    f = Seq(fc.Response(200, None, b"<html></html>"))
    fc.fetch_chain("https://evil.test\\@hanbit.example/", f)
    assert f.urls == ["https://evil.test/@hanbit.example/"]


def test_backslash_in_location_header_is_normalized():
    f = Seq(fc.Response(302, "\\\\evil.test\\x"), fc.Response(200, None, b"<html></html>"))
    fc.fetch_chain("https://a.test/", f)
    assert f.urls[1] == "https://evil.test/x"


def _safe_ev(**over):
    base = dict(parse=parse("hanbit.example"), similarity=similarity(), fetch=fetch("hanbit.example"),
                page=page(), claim=claim())
    base.update(over)
    return base


def test_baseline_official_page_is_safe():
    assert decide(**_safe_ev()).verdict == "safe"


def test_ambiguous_userinfo_ip_or_internal_never_safe():
    o = decide(**_safe_ev(parse={**parse("hanbit.example"), "ambiguous": True}))
    assert o.verdict != "safe" and "ambiguous_url" in V.verification_gaps(V.Evidence(**_safe_ev(
        parse={**parse("hanbit.example"), "ambiguous": True})))
    assert decide(**_safe_ev(parse=parse("hanbit.example", userinfo=True))).verdict != "safe"
    assert decide(**_safe_ev(), internal_resolution=True).verdict != "safe"


# ── R1-02: 이동 경로의 파생 값 위조 ────────────────────────────────────────────
def _host(url="https://hanbit.example.attacker.test/login"):
    return parse_url(url)


def _files(host, chain, final_domain, final_url=None):
    hop = lambda u: {"url": u, "host": parse_url(u)["host_ascii"],  # noqa: E731
                     "registrable_domain": parse_url(u)["registrable_domain"], "blocked": False, "error": None}
    hops = [hop(u) for u in chain]
    return {"parse_url": {"ok": True, "host_ascii": host["host_ascii"], "registrable_domain": host["registrable_domain"]},
            "fetch_chain": {"ok": True, "chain": hops, "final_registrable_domain": final_domain,
                            "final_url": final_url if final_url is not None else hops[-1]["url"]}}


def test_files_mismatch_helper():
    from app.worker import files_mismatch

    host = _host("https://hanblt.example/login")
    ok = _files(host, ["https://hanblt.example/login"], "hanblt.example")
    assert files_mismatch(ok, host) is None
    assert files_mismatch({"parse_url": {"ok": True, "host_ascii": "x.test",
                                         "registrable_domain": host["registrable_domain"]}}, host)
    assert files_mismatch({}, host) is None  # 파일이 없는 것은 판정 쪽에서 unknown으로 처리한다


def test_final_domain_only_tampering_is_rejected():
    from app.worker import files_mismatch

    host = _host()
    files = _files(host, ["https://hanbit.example.attacker.test/login"], "hanbit.example")
    assert files_mismatch(files, host) == "fetch_chain.final_domain"  # 경로는 그대로 두고 최종 도메인만 공식으로 바꿈


def test_hop_host_and_first_host_tampering_are_rejected():
    from app.worker import files_mismatch

    host = _host()
    files = _files(host, ["https://hanbit.example.attacker.test/login"], "attacker.test")
    files["fetch_chain"]["chain"][0]["registrable_domain"] = "hanbit.example"
    assert files_mismatch(files, host) == "fetch_chain.hop_host"
    other = _files(host, ["https://elsewhere.test/"], "elsewhere.test")
    assert files_mismatch(other, host) == "fetch_chain.first_host"
    assert files_mismatch({"fetch_chain": {"ok": True, "chain": ["x"]}}, host) == "fetch_chain.shape"


# ── R1-03: 브라우저 쪽 이동을 감지하고도 safe ─────────────────────────────────────
def test_client_side_redirect_hint_blocks_safe():
    ev = _safe_ev(page={**page(), "js_redirect_hint": True})
    assert decide(**ev).verdict != "safe"
    assert "client_redirect" in V.verification_gaps(V.Evidence(**ev))


def test_truncated_body_blocks_safe():
    ev = _safe_ev(fetch={**fetch("hanbit.example"), "body_truncated": True})
    assert decide(**ev).verdict != "safe"


# ── R1-04: 이동 응답의 오래된 본문 ────────────────────────────────────────────────
def test_html_of_a_redirect_is_not_analyzed_as_the_final_page():
    f = Seq(fc.Response(302, "https://a.test/dl", b"<html>harmless</html>"),
            fc.Response(200, None, b"MZ\x90", "application/octet-stream"))
    res, html = fc.fetch_chain("https://a.test/", f)
    assert html == b"" and res["html_saved"] is False and res["final_content_type"] == "application/octet-stream"


def test_redirect_body_is_kept_only_when_the_chain_ends_without_a_final_response():
    f = Seq(fc.Response(302, "https://b.test/", b"<html>form</html>"), fc.Blocked("policy"))
    res, html = fc.fetch_chain("https://a.test/", f)
    assert html == b"<html>form</html>" and res["html_from_redirect"] is True and res["blocked_count"] == 1


def test_truncated_body_is_reported():
    f = Seq(fc.Response(200, None, b"<html>", "text/html", truncated=True))
    res, _ = fc.fetch_chain("https://a.test/", f)
    assert res["body_truncated"] is True


# ── R1-05: 클라이언트 IP를 믿을 수 없을 때 ──────────────────────────────────────
def _post(c, i, ip=None):
    h = {"X-Session-Id": f"rotating-session-{i:016d}"}
    if ip:
        h["X-Client-Ip"] = ip
    return c.post("/api/investigations", json={"input": "https://a.test/x"}, headers=h).status_code


def test_rotating_sessions_without_client_ip_share_one_low_budget(tmp_env, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "rate_limit_untrusted_per_min", 2)
    with TestClient(app) as c:
        assert [_post(c, i) for i in range(4)] == [202, 202, 429, 429]


def test_malformed_client_ip_is_treated_as_unknown(tmp_env, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "rate_limit_untrusted_per_min", 2)
    with TestClient(app) as c:
        assert [_post(c, i, ip=f"not-an-ip-{i}") for i in range(4)] == [202, 202, 429, 429]


def test_global_budget_caps_distributed_clients(tmp_env, monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "rate_limit_global_per_min", 2)
    with TestClient(app) as c:
        assert [_post(c, i, ip=f"203.0.113.{i + 1}") for i in range(4)] == [202, 202, 429, 429]


# ── R1-06: 격리 중에는 설명 에이전트도 실행하지 않는다 ────────────────────────────────
def test_explain_agent_is_not_launched_while_quarantined(tmp_path):
    r = FakeRunner()
    s = sb(r, tmp_path)
    s.quarantined = True
    assert s.explain("j_1", {"verdict": "safe"}) is None
    assert not any("openclaw" in c for c in r.calls)


def test_explain_is_skipped_after_policy_removal_fails(tmp_env, monkeypatch):
    from app import sandbox as sb_mod

    orig = sb_mod.LocalSandbox.investigate
    called = []

    def dirty(self, *a, **kw):
        res = orig(self, *a, **kw)
        res.residual_policy = True
        return res

    monkeypatch.setattr(sb_mod.LocalSandbox, "investigate", dirty)
    monkeypatch.setattr(sb_mod.LocalSandbox, "explain", lambda self, jid, p: called.append(jid))
    from .test_e2e import run_job

    with TestClient(app, headers={"X-Session-Id": SESSION_A}) as c:
        v = run_job(c, "https://hanbit.example/track")
    assert v["status"] == "done" and v["job_id"] not in called  # (앞선 시험이 남긴 작업의 호출은 세지 않는다)


# ── R1-07: 설명 검증 우회 ─────────────────────────────────────────────────────
@pytest.mark.parametrize("text", [
    "링크를 열고 비밀번호를 입력하면 됩니다.",
    "입력하세요​",
    "입 력 하 세 요",
    "이 사이트는 안전합니다. 안전하지 않다는 경고는 오해예요.",
    "링크를 눌러서 확인하는 게 좋아요.",
])
def test_explanation_guard_bypasses_are_rejected(text):
    for field in ("detail", "confirmed_facts", "suspicion_evidence"):
        bad = {**GOOD, field: [text] if field != "detail" else text}
        assert __import__("app.explain", fromlist=["validate"]).validate(bad, _payload(), kb, TEMPLATE) is None


def test_invisible_characters_are_stripped_from_accepted_text():
    from app import explain as ex

    ok = {**GOOD, "confirmed_facts": ["진짜​ 사이트 이름은 account-check.test예요."]}
    out = ex.validate(ok, _payload(), kb, TEMPLATE)
    assert out and "​" not in out["confirmed_facts"][0]


def test_legitimate_descriptive_text_still_passes():
    from app import explain as ex

    ok = {**GOOD, "confirmed_facts": ["안전한 공간에서 열어 봤어요.", "비밀번호를 적는 칸이 있어요."]}
    assert ex.validate(ok, _payload(), kb, TEMPLATE)


# ── R1-09: 제한기 키 상한 ─────────────────────────────────────────────────────
def test_rate_limiter_has_a_hard_key_cap():
    lim = RateLimiter(6, max_keys=3)
    assert [lim.allow(f"k{i}") for i in range(20)].count(True) == 3
    assert len(lim._hits) == 3
    assert lim.allow("k0")  # 이미 있는 키는 계속 쓸 수 있다


def test_rate_limiter_frees_expired_keys_and_evicts_at_most_once_per_second():
    lim = RateLimiter(1, window_s=0.05, max_keys=2, evict_interval_s=0.05)
    assert lim.allow("a") and lim.allow("b") and not lim.allow("c")
    time.sleep(0.08)
    assert lim.allow("c")  # 만료된 키를 정리해 자리가 났다
    lim = RateLimiter(1, window_s=60, max_keys=2)
    assert lim.allow("a") and lim.allow("b")
    scans = []
    orig = lim._evict
    lim._evict = lambda now: (scans.append(1), orig(now))[1]
    for i in range(50):  # 가득 찬 상태에서 새 키를 몰아쳐도 매번 전체를 훑지 않는다
        lim.allow(f"flood{i}")
    assert len(scans) <= 1


def test_rate_limiter_per_call_limit_override():
    lim = RateLimiter(5)
    assert [lim.allow("x", 2) for _ in range(3)] == [True, True, False]


def test_session_state_is_not_allocated_when_the_ip_is_already_rejected(tmp_env, monkeypatch):
    from app import main
    from app.config import settings

    monkeypatch.setattr(settings, "rate_limit_per_min", 1)
    with TestClient(app) as c:
        _post(c, 0, ip="203.0.113.7")
        before = len(main.state.limiter._hits)
        for i in range(1, 20):
            assert _post(c, i, ip="203.0.113.7") == 429
        assert len(main.state.limiter._hits) == before


# ── R1-10: 공개 health 경로 ──────────────────────────────────────────────────
def test_health_runs_the_external_check_at_most_once_per_interval(tmp_env):
    with TestClient(app) as c:
        from app import main

        calls = []
        orig = main.state.sandbox.health
        main.state.sandbox.health = lambda: (calls.append(1), orig())[1]
        for _ in range(8):
            assert c.get("/api/health").status_code == 200
    assert len(calls) == 1


# ── R1-11: 샌드박스 안 작업 폴더 정리 ────────────────────────────────────────────
def _rm_calls(r):
    return [c for c in r.calls if "rm" in c and "-rf" in c]


def test_remote_workdir_is_deleted_even_when_policy_add_fails(tmp_path):
    r = FakeRunner(fail={"policy add": "boom"})
    res = sb(r, tmp_path).investigate(FULL_ID, {**payload(), "job_id": FULL_ID}, "a.test", True)
    assert res.incomplete == "policy_error" and len(_rm_calls(r)) == 1


def test_remote_workdir_is_deleted_after_a_partial_upload_failure(tmp_path):
    r = FakeRunner(fail={"sandbox upload": "boom"})
    sb(r, tmp_path).investigate(FULL_ID, {**payload(), "job_id": FULL_ID}, "a.test", True)
    assert len(_rm_calls(r)) == 1


def test_failed_remote_delete_is_retried_before_the_next_job(tmp_path):
    r = FakeRunner(fail={"rm -rf": "nope"})
    s = sb(r, tmp_path)
    s.investigate(FULL_ID, {**payload(), "job_id": FULL_ID}, "a.test", True)
    assert s._pending_purge == {FULL_ID}
    r.fail = {}
    other = "j_" + "b2" * 16
    s.investigate(other, {**payload(), "job_id": other}, "a.test", True)
    assert s._pending_purge == set()
    assert any(FULL_ID in c[-1] for c in _rm_calls(r))


def test_nothing_is_purged_remotely_when_no_upload_was_attempted(tmp_path):
    r = FakeRunner()
    s = sb(r, tmp_path)
    s.quarantined = True
    r.list_fail = True  # 정리를 확인하지 못해 격리가 풀리지 않는다
    res = s.investigate(FULL_ID, {**payload(), "job_id": FULL_ID}, "a.test", True)
    assert res.incomplete == "sandbox_unsafe" and _rm_calls(r) == []


# ── R1-12: 보관 기간 ─────────────────────────────────────────────────────────
def _job(job_id, finished_ago, owner="o"):
    return dict(job_id=job_id, owner=owner, status="done", stage="done", mode="live", input="문자", url="https://a.test",
                finished_at=time.time() - finished_ago)


def test_expired_result_is_not_readable_even_before_the_purge_runs():
    from app.db import DB

    db = DB(":memory:", retention_s=3600)
    db.create(_job("old", 7200))
    db.create(_job("new", 60))
    assert db.get("old", "o") is None and db.get("new", "o") is not None
    assert DB(":memory:").get("old") is None  # 보관 기간을 주지 않으면(기존 동작) 제한하지 않는다


def test_running_job_is_never_expired_by_reads():
    from app.db import DB

    db = DB(":memory:", retention_s=1)
    db.create({**_job("q", 0), "status": "queued", "finished_at": None})
    time.sleep(1.1)
    assert db.get("q") is not None


def test_retention_runs_without_any_new_request(tmp_env, monkeypatch):
    from app import main
    from app.config import settings

    monkeypatch.setattr(settings, "purge_interval_s", 0.05)
    with TestClient(app) as c:
        main.state.db.create(_job("j_" + "c3" * 16, 100 * 3600))
        deadline = time.time() + 3
        while time.time() < deadline:
            n = main.state.db._conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
            if n == 0:
                break
            time.sleep(0.05)
        assert n == 0
        assert c.get("/api/health").status_code == 200

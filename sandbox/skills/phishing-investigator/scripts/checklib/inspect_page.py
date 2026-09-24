"""3-4. 페이지 분석: 입력란, 전송 대상, 앱 설치 유도, 브랜드 주장, 자동 이동 흔적.

HTML은 파싱만 한다(실행하지 않음). 페이지 문구는 공격자가 만든 데이터이므로
길이를 제한한 구조화 필드로만 내보내고, 그 문구의 지시를 해석하지 않는다.
"""
from __future__ import annotations

import codecs
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .parse_url import backslash_to_slash, registrable_of, to_ascii_host

FIELD_TYPES = [
    "password", "card_number", "card_cvc", "card_expiry", "bank_account", "resident_id",
    "otp", "phone", "name", "address", "other",
]

_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("card_cvc", ("cvc", "cvv", "보안코드", "카드 뒷면", "카드뒷면", "cvc2")),
    ("card_expiry", ("expiry", "expiration", "유효기간", "만료", "mm/yy", "mmyy", "cc-exp")),
    ("card_number", ("cardnumber", "card_number", "card-number", "cardno", "카드번호", "카드 번호",
                     "cc-number", "ccnum", "card number")),
    ("bank_account", ("계좌", "accountnumber", "account_no", "account-no", "bankaccount", "acctno")),
    ("resident_id", ("주민", "rrn", "resident", "ssn", "생년월일 뒤")),
    ("otp", ("otp", "인증번호", "인증 번호", "verification", "passcode", "보안카드")),
    ("password", ("password", "passwd", "비밀번호", "비번", "pwd")),
    ("phone", ("phone", "tel", "전화", "휴대폰", "핸드폰", "mobile", "연락처")),
    ("address", ("address", "addr", "주소", "우편")),
    ("name", ("name", "성함", "이름")),
]

_TRUST_RE = re.compile(r"(공식|안전|인증|보증|정식|official|verified|secure|authentic)", re.I)
# 스크립트·이벤트 핸들러 속 이동 시도와 그것을 숨기는 난독화 흔적. JavaScript는 실행하지 않으므로 도착지를 알 수 없다.
_JS_REDIRECT_RE = re.compile(
    r"(?:\b(?:window|self|top|parent|document|globalThis)\s*\.\s*location\b"
    r"|\blocation\s*(?:\.\s*(?:href|replace|assign|reload)\b|=(?!=))"
    r"|\bwindow\s*\.\s*open\s*\(|\bnavigate\s*\(|\bhistory\s*\.\s*(?:push|replace)State\s*\("
    r"|\beval\s*\(|\batob\s*\(|\bnew\s+Function\s*\(|\bunescape\s*\(|\bdocument\s*\.\s*write(?:ln)?\s*\("
    r"|\bset(?:Timeout|Interval)\s*\(\s*[\"'`]|javascript\s*:)", re.I)
_SKIP_INPUT_TYPES = {"hidden", "submit", "button", "image", "reset", "checkbox", "radio", "file"}


def classify_field(attrs: dict, label_text: str = "") -> str:
    typ = (attrs.get("type") or "text").lower()
    ac = (attrs.get("autocomplete") or "").lower()
    if typ == "password":
        return "password"
    if "cc-number" in ac:
        return "card_number"
    if "cc-csc" in ac:
        return "card_cvc"
    if "cc-exp" in ac:
        return "card_expiry"
    if "one-time-code" in ac:
        return "otp"
    if typ == "tel":
        return "phone"
    hay = " ".join(
        [attrs.get("name") or "", attrs.get("id") or "", attrs.get("placeholder") or "",
         attrs.get("aria-label") or "", label_text or ""]
    ).lower()
    for ftype, words in _KEYWORDS:
        if any(w in hay for w in words):
            return ftype
    return "other"


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self._in_title = False
        self.metas: list[dict] = []
        self.imgs: list[dict] = []
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None
        self.loose_inputs: list[dict] = []
        self.label_for: dict[str, str] = {}
        self._label_for: str | None = None
        self._label_buf: list[str] = []
        self._in_label = False
        self._pending_wrapped_inputs: list[dict] = []
        self._in_script = False
        self._in_style = False
        self.script_text: list[str] = []
        self.text_nodes: list[str] = []
        self.base_href: str | None = None  # 첫 <base href>만 효력이 있다
        self.active_srcs: list[str] = []  # 다른 곳의 코드를 끌어오는 script·iframe·frame·embed·object 주소
        self.handler_text: list[str] = []  # onload="…" 같은 이벤트 핸들러 속성값

    # 태그 처리
    def handle_starttag(self, tag: str, attrs_list) -> None:
        a = {k: (v or "") for k, v in attrs_list}
        for k, v in a.items():
            if k.lower().startswith("on") and v:
                self.handler_text.append(v)
        if tag == "base" and self.base_href is None and a.get("href"):
            self.base_href = a["href"]
        if tag in ("script", "iframe", "frame", "embed", "object"):
            src = a.get("src") or (a.get("data") if tag == "object" else "")
            if src:
                self.active_srcs.append(src)
        if a.get("formaction") and self._form is not None:
            self._form.setdefault("formactions", []).append(a["formaction"])
        if tag == "title":
            self._in_title = True
        elif tag == "meta":
            self.metas.append(a)
        elif tag == "img":
            self.imgs.append(a)
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                          "inputs": []}
            self.forms.append(self._form)
        elif tag == "label":
            self._in_label = True
            self._label_for = a.get("for") or None
            self._label_buf = []
            self._pending_wrapped_inputs = []
        elif tag in ("input", "textarea", "select"):
            if tag == "input" and (a.get("type") or "text").lower() in _SKIP_INPUT_TYPES:
                return
            item = dict(a)
            item["_tag"] = tag
            (self._form["inputs"] if self._form is not None else self.loose_inputs).append(item)
            if self._in_label:
                self._pending_wrapped_inputs.append(item)
        elif tag == "script":
            self._in_script = True
        elif tag == "style":
            self._in_style = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form":
            self._form = None
        elif tag == "label":
            text = " ".join("".join(self._label_buf).split())
            if self._label_for:
                self.label_for[self._label_for] = text
            for it in self._pending_wrapped_inputs:
                it["_label"] = text
            self._in_label = False
            self._label_for = None
        elif tag == "script":
            self._in_script = False
        elif tag == "style":
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        if self._in_script:
            self.script_text.append(data)
            return
        if self._in_style:
            return
        if self._in_label:
            self._label_buf.append(data)
        s = " ".join(data.split())
        if s:
            self.text_nodes.append(s)


def _trim(s: str, n: int) -> str:
    s = " ".join((s or "").split())
    return s[:n]


_BOMS = [(codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"), (codecs.BOM_UTF8, "utf-8-sig"),
         (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16")]
_CT_CHARSET = re.compile(r"charset\s*=\s*[\"']?([\w.:-]+)", re.I)
_META_CHARSET = re.compile(rb"<meta[^>]+charset\s*=\s*[\"']?([\w.:-]+)", re.I)


def _declared_charset(html_bytes: bytes, content_type: str) -> str | None:
    names = []
    m = _CT_CHARSET.search(content_type or "")
    if m:
        names.append(m.group(1))
    m2 = _META_CHARSET.search(html_bytes[:2048])
    if m2:
        names.append(m2.group(1).decode("ascii", "ignore"))
    for name in names:
        try:
            return codecs.lookup(name).name
        except LookupError:
            continue
    return None


def _decode(html_bytes: bytes, content_type: str = "") -> str | None:
    """브라우저와 같은 순서(BOM → HTTP 헤더 → meta 선언 → 추정)로 해석한다. 마크업으로 읽히지 않으면 None."""
    text = None
    for bom, enc in _BOMS:
        if html_bytes.startswith(bom):
            text = html_bytes.decode(enc, errors="replace")
            break
    if text is None:
        declared = _declared_charset(html_bytes, content_type)
        for enc in ([declared] if declared else []) + ["utf-8", "euc-kr"]:
            try:
                text = html_bytes.decode(enc)
                break
            except (UnicodeDecodeError, LookupError):
                continue
    if text is None:
        text = html_bytes.decode("utf-8", errors="replace")
    # 태그가 하나도 안 보이거나 NUL이 섞여 있으면 해석에 실패한 것이다(분석 결과를 믿지 않는다)
    return text if "<" in text and "\x00" not in text else None


def _resolve(base: str, ref: str) -> str:
    """브라우저처럼 상대 주소를 푼다(탭·줄바꿈 제거, 경로의 백슬래시를 슬래시로)."""
    ref = re.sub(r"[\t\r\n]", "", ref or "").strip()
    return urljoin(base, backslash_to_slash(ref))


def inspect_page(html_bytes: bytes, page_url: str, content_type: str = "") -> dict:
    text = _decode(html_bytes, content_type)
    if text is None:
        return {"ok": False, "error": "undecodable html"}
    p = _PageParser()
    p.feed(text)
    p.close()

    page_host = to_ascii_host(urlsplit(page_url).hostname or "")
    page_reg = registrable_of(page_host) if page_host else ""
    base_url = _resolve(page_url, p.base_href) if p.base_href else page_url  # 상대 주소는 <base>를 기준으로 풀린다

    # 브랜드 후보: title 조각, og:site_name, 로고 alt
    brands: list[str] = []

    def add_brand(s: str) -> None:
        s = _trim(s, 40)
        if s and s not in brands:
            brands.append(s)

    for part in re.split(r"[|\-–—·:]", p.title):
        add_brand(part)
    for m in p.metas:
        if (m.get("property") or m.get("name") or "").lower() in ("og:site_name", "application-name"):
            add_brand(m.get("content", ""))
    for im in p.imgs:
        blob = " ".join([im.get("alt", ""), im.get("src", ""), im.get("class", ""), im.get("id", "")]).lower()
        if "logo" in blob or "로고" in blob:
            add_brand(im.get("alt", ""))
    brands = brands[:6]

    # 폼
    forms_out: list[dict] = []
    all_groups = [([f["action"], *f.get("formactions", [])], f["inputs"]) for f in p.forms]
    if p.loose_inputs:
        all_groups.append(([""], p.loose_inputs))
    for actions, inputs in all_groups:
        if not inputs:
            continue
        # 전송 대상 후보(form의 action과 버튼의 formaction) 중 하나라도 다른 도메인이면 교차 도메인으로 본다
        dests: list[tuple[str, str, bool]] = []  # (호스트, 등록 도메인, 교차 도메인 여부)
        for action in actions:
            target = _resolve(base_url, action) if action else base_url
            sp = urlsplit(target)
            if sp.scheme.lower() not in ("http", "https"):  # javascript:·data: 등은 목적지를 알 수 없다
                dests.append(("", "(script)", True))
                continue
            a_host = to_ascii_host(sp.hostname or page_host)
            a_reg = registrable_of(a_host) if a_host else page_reg
            dests.append((a_host, a_reg, bool(a_reg and page_reg and a_reg != page_reg)))
        a_host, a_reg, _ = next((d for d in dests if d[2]), dests[0])
        ftypes: list[str] = []
        for it in inputs:
            label = it.get("_label") or p.label_for.get(it.get("id", ""), "")
            t = classify_field(it, label)
            if t not in ftypes:
                ftypes.append(t)
        forms_out.append({
            "action_host": a_host,
            "action_registrable_domain": a_reg,
            "cross_domain": any(d[2] for d in dests),
            "field_types": ftypes,
        })

    apk_links = []
    for href in p.links:
        low = href.lower().split("?")[0].split("#")[0]
        if low.endswith(".apk"):
            apk_links.append(_trim(urljoin(page_url, href), 200))
    apk_links = apk_links[:5]

    meta_refresh = any((m.get("http-equiv") or "").lower() == "refresh" for m in p.metas)
    js_hint = (meta_refresh or any(_JS_REDIRECT_RE.search(t) for t in p.script_text + p.handler_text)
               or any(h.strip().lower().startswith("javascript:") for h in p.links))

    # 다른 도메인의 코드·문서를 끌어오는 요소. 실행하지 않으므로 무엇을 하는지 알 수 없다(판정에서 안전 불가 사유).
    ext: list[str] = []
    for src in p.active_srcs:
        sp = urlsplit(_resolve(base_url, src))
        dom = registrable_of(to_ascii_host(sp.hostname)) if sp.hostname else ""
        if sp.scheme.lower() not in ("http", "https", ""):
            dom = "(script)"
        if dom and dom != page_reg and dom not in ext:
            ext.append(dom)

    # "공식·안전·인증" 류 주장 문구: 길이 제한, 최대 3개. 검증 대상 주장일 뿐이다.
    claims: list[str] = []
    for t in p.text_nodes:
        if _TRUST_RE.search(t) and len(t) >= 6:
            c = _trim(t, 200)
            if c not in claims:
                claims.append(c)
        if len(claims) >= 3:
            break

    return {
        "ok": True,
        "title": _trim(p.title, 100),
        "brand_candidates": brands,
        "forms": forms_out,
        "apk_links": apk_links,
        "trust_claims": claims,
        "js_redirect_hint": bool(js_hint),
        "external_active_domains": ext[:10],
    }

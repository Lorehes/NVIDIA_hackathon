"""3-4. 페이지 분석: 입력란, 전송 대상, 앱 설치 유도, 브랜드 주장, 자동 이동 흔적.

HTML은 파싱만 한다(실행하지 않음). 페이지 문구는 공격자가 만든 데이터이므로
길이를 제한한 구조화 필드로만 내보내고, 그 문구의 지시를 해석하지 않는다.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from .parse_url import registrable_of, to_ascii_host

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
_JS_REDIRECT_RE = re.compile(r"(location\.(href|replace|assign)|window\.location|top\.location)", re.I)
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

    # 태그 처리
    def handle_starttag(self, tag: str, attrs_list) -> None:
        a = {k: (v or "") for k, v in attrs_list}
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


def _decode(html_bytes: bytes) -> str:
    for enc in ("utf-8", "euc-kr", "latin-1"):
        try:
            return html_bytes.decode(enc)
        except UnicodeDecodeError:
            continue
    return html_bytes.decode("utf-8", errors="replace")


def inspect_page(html_bytes: bytes, page_url: str) -> dict:
    p = _PageParser()
    p.feed(_decode(html_bytes))
    p.close()

    page_host = to_ascii_host(urlsplit(page_url).hostname or "")
    page_reg = registrable_of(page_host) if page_host else ""

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
    all_groups = [(f["action"], f["inputs"]) for f in p.forms]
    if p.loose_inputs:
        all_groups.append(("", p.loose_inputs))
    for action, inputs in all_groups:
        if not inputs:
            continue
        target = urljoin(page_url, action) if action else page_url
        a_host = to_ascii_host(urlsplit(target).hostname or page_host)
        a_reg = registrable_of(a_host) if a_host else page_reg
        ftypes: list[str] = []
        for it in inputs:
            label = it.get("_label") or p.label_for.get(it.get("id", ""), "")
            t = classify_field(it, label)
            if t not in ftypes:
                ftypes.append(t)
        forms_out.append({
            "action_host": a_host,
            "action_registrable_domain": a_reg,
            "cross_domain": bool(a_reg and page_reg and a_reg != page_reg),
            "field_types": ftypes,
        })

    apk_links = []
    for href in p.links:
        low = href.lower().split("?")[0].split("#")[0]
        if low.endswith(".apk"):
            apk_links.append(_trim(urljoin(page_url, href), 200))
    apk_links = apk_links[:5]

    meta_refresh = any((m.get("http-equiv") or "").lower() == "refresh" for m in p.metas)
    js_hint = meta_refresh or any(_JS_REDIRECT_RE.search(t) for t in p.script_text)

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
    }

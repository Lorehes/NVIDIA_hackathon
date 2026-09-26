"""KB 로딩과 사칭 대상 후보 검색(F4): 정확 일치 → 별칭 → 임베딩(NeMo Retriever) 상위 3개."""
from __future__ import annotations

import json
import math
import re
import unicodedata
from dataclasses import dataclass, field

from .config import settings
from .site_catalog import load_catalog, SiteCatalog, same_service_port
from .urls import parse_url

CATEGORY_DESC = {
    "delivery": "택배 배송 물류 운송장",
    "bank": "은행 계좌 이체 대출",
    "card": "신용카드 체크카드 결제",
    "government": "공공기관 정부 세금 과태료 민원",
    "telecom": "통신사 휴대폰 요금",
    "fictional": "가상 브랜드 데모",
}


@dataclass
class Entity:
    id: str
    name: str
    aliases: list[str]
    category: str
    official_domains: list[str]
    partner_domains: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)
    policy_rules: list[dict] = field(default_factory=list)
    official_app: str | None = None
    sources: list[dict] = field(default_factory=list)
    fictional: bool = False
    identity_verified: bool = True
    address_scope: str = 'registration'
    source_url: str | None = None
    observed_from: str | None = None

    def matches(self, host: str, url: str | None = None, partner=False) -> bool:
        if not self.identity_verified:
            return False
        domains = self.partner_domains if partner else self.official_domains
        if self.address_scope == 'registration':
            return (parse_url('https://' + host).get('registrable_domain') or host) in domains
        if host not in domains:
            return False
        if self.source_url and url and not same_service_port(self.source_url, url):
            return False
        if self.address_scope == 'url':
            from urllib.parse import urlsplit
            if not url or not self.source_url:
                return False
            a, b = urlsplit(url), urlsplit(self.source_url)
            return (a.path or '/', a.query) == (b.path or '/', b.query)
        return True

    def as_candidate(self) -> dict:
        """샌드박스로 올리는 후보 레코드(input.json). 출처 등 불필요한 필드는 뺀다."""
        return {
            "id": self.id, "name": self.name, "aliases": self.aliases,
            "official_domains": self.official_domains, "partner_domains": self.partner_domains,
            "policies": self.policies,
        }


class KB:
    def __init__(self, entities: list[Entity], catalog: SiteCatalog | None = None):
        self.entities = entities
        self.by_id = {e.id: e for e in entities}
        self._vecs: dict[str, list[float]] | None = None
        self.catalog = catalog or SiteCatalog([])
        self.catalog_path = None

    @classmethod
    def load(cls, path=None) -> "KB":
        raw = json.loads((path or settings.kb_path).read_text(encoding="utf-8"))
        ents = []
        for r in raw["entities"]:
            ents.append(Entity(
                id=r["id"], name=r["name"], aliases=r.get("aliases", []), category=r["category"],
                official_domains=[d.lower() for d in r["official_domains"]],
                partner_domains=[d.lower() for d in r.get("partner_domains", [])],
                policies=r.get("policies", []), policy_rules=r.get("policy_rules", []),
                official_app=r.get("official_app"), sources=r.get("sources", []),
                fictional=bool(r.get("fictional", False)),
            ))
        catalog_path = (path or settings.kb_path).with_name('site_catalog.json')
        kb = cls(ents, load_catalog(catalog_path))
        kb.catalog_path = catalog_path
        return kb

    def refresh_catalog(self):
        if self.catalog_path:
            self.catalog = load_catalog(self.catalog_path)

    def _catalog_entity(self, record):
        e = Entity(id=record['id'], name=record['name'], aliases=[], category=record['kind'],
                   official_domains=[record['host']], identity_verified=bool(record['verified'] and self.catalog.fresh(record)),
                   address_scope=record['scope'], source_url=record['url'],
                   sources=[{'url': record['source'], 'checked': record['checked']}])
        self.by_id[e.id] = e
        return e

    def address_candidates(self, url: str) -> list[tuple[Entity, str]]:
        """No embedding or model guess for a bare URL."""
        self.refresh_catalog()
        p = parse_url(url)
        host = p.get('host_ascii', '')
        for e in self.entities:
            if e.matches(host, url) or e.matches(host, url, partner=True):
                return [(e, 'address')]
        record = self.catalog.lookup(url)
        return [(self._catalog_entity(record), 'address')] if record else []

    def official_records(self, candidates=()) -> list[dict]:
        entities = {e.id: e for e in self.entities}
        entities.update({e.id: e for e, _ in candidates if e.identity_verified})
        return [{'entity_id': e.id, 'domain': d, **({'scope': e.address_scope} if e.address_scope != 'registration' else {})}
                for e in entities.values() for d in e.official_domains]

    def identity_summary(self, url, outcome, input_url=None):
        result = self.catalog.describe(url)
        if input_url and result['status'] != 'verified':
            entry = self.catalog.describe(input_url)
            if entry['status'] == 'verified':
                result['source_address'] = {k: entry[k] for k in
                                            ('name', 'source', 'checked', 'host', 'matched_entities')}
        from .site_relations import RelationStore
        try:
            result['observed_redirects'] = RelationStore(settings.db_path.with_name('site_relations.sqlite')).related(result.get('host'))
        except Exception:
            result['observed_redirects'] = []
        types = {s['type'] for s in outcome.signals}
        if {'official_match', 'partner_match'} & types and outcome.entity:
            entity = outcome.entity
            reason = result['reason'] if result['status'] == 'verified' else 'sourced_address_match'
            result.update(status='verified', name=entity.name, reason=reason)
            if entity.sources:
                result.update(source=entity.sources[0].get('url'), checked=entity.sources[0].get('checked'))
            if entity.observed_from:
                result.update(reason='observed_service_redirect', canonical_from=entity.observed_from,
                              evidence_scope='this_investigation')
        # Identity remains independent of detected behavior, including on official sites.
        result['behavior'] = ('incomplete' if outcome.unknown_reason == 'incomplete' or outcome.verification_gaps else
                              'risk_found' if any(s['strength'] in ('mid', 'strong') for s in outcome.signals) else
                              'no_risk_observed')
        if any(s['strength'] in ('mid', 'strong') for s in outcome.signals):
            result['behavior'] = 'risk_found'
        return result

    def all_known_domains(self) -> set[str]:
        s: set[str] = set()
        for e in self.entities:
            s.update(e.official_domains)
            s.update(e.partner_domains)
        return s

    # ── 후보 검색 ────────────────────────────────────────────────
    def candidates(self, text: str, limit: int = 3) -> list[tuple[Entity, str]]:
        """(엔티티, 출처) 목록. 정확·별칭 일치가 있으면 그것만, 없으면 임베딩 상위 limit개."""
        self.refresh_catalog()
        norm = _norm(text)
        exact, alias = [], []
        for e in self.entities:
            if _norm(e.name) in norm:
                exact.append((e, "exact"))
            elif any(_norm(a) in norm for a in e.aliases if len(_norm(a)) >= 2):
                alias.append((e, "alias"))
        hits = exact + alias
        if hits:
            return hits[:limit]
        catalog_hits = self.catalog.name_matches(text, limit)
        if catalog_hits:
            return [(self._catalog_entity(r), 'exact') for r in catalog_hits]
        return [(e, "embedding") for e in self._rank(text)[:limit]]

    def _rank(self, text: str) -> list[Entity]:
        try:
            return self._rank_embedding(text)
        except Exception:  # noqa: BLE001 - API 실패·키 없음 → 로컬 n-gram 대체
            return self._rank_ngram(text)

    def _entity_sentence(self, e: Entity) -> str:
        return f"{e.name} {' '.join(e.aliases)} {CATEGORY_DESC.get(e.category, e.category)}"

    def _rank_ngram(self, text: str) -> list[Entity]:
        q = _ngrams(_norm(text))
        scored = []
        for e in self.entities:
            s = _cos_sparse(q, _ngrams(_norm(self._entity_sentence(e))))
            scored.append((s, e))
        scored.sort(key=lambda x: -x[0])
        return [e for s, e in scored if s > 0.02]

    def _rank_embedding(self, text: str) -> list[Entity]:
        if not settings.nvidia_api_key:
            raise RuntimeError("no api key")
        import httpx

        def embed(texts: list[str], kind: str) -> list[list[float]]:
            from . import budget
            r = budget.read_only(httpx.post,
                settings.embed_url,
                headers={"Authorization": f"Bearer {settings.nvidia_api_key}"},
                json={"model": settings.embed_model, "input": texts, "input_type": kind,
                      "encoding_format": "float", "truncate": "END"},
                timeout=15,
            )
            r.raise_for_status()
            return [d["embedding"] for d in r.json()["data"]]

        if self._vecs is None:  # KB 벡터는 프로세스당 1회만 계산
            vecs = embed([self._entity_sentence(e) for e in self.entities], "passage")
            self._vecs = {e.id: v for e, v in zip(self.entities, vecs)}
        q = embed([redact_for_external(text)[:1000]], "query")[0]
        scored = sorted(((_cos_dense(q, self._vecs[e.id]), e) for e in self.entities), key=lambda x: -x[0])
        return [e for _, e in scored]


_URL_IN_TEXT = re.compile(r"(?:https?://|www\.)\S+", re.I)
_LONG_DIGITS = re.compile(r"\d(?:[\s.-]?\d){3,}")  # 전화번호·인증번호·계좌·카드 번호처럼 4자리 이상 이어진 숫자


def redact_for_external(text: str) -> str:
    """외부 임베딩 API로 보내기 전에 개인 식별·인증 정보를 지운다. 기관 이름 같은 단어는 그대로 둔다."""
    text = _URL_IN_TEXT.sub("[링크]", text or "")
    return _LONG_DIGITS.sub("[숫자]", text)


def _norm(s: str) -> str:
    s = unicodedata.normalize("NFKC", s).lower()
    return re.sub(r"\s+", "", s)


def _ngrams(s: str, n: int = 2) -> dict[str, int]:
    d: dict[str, int] = {}
    for i in range(len(s) - n + 1):
        d[s[i:i + n]] = d.get(s[i:i + n], 0) + 1
    return d


def _cos_sparse(a: dict[str, int], b: dict[str, int]) -> float:
    if not a or not b:
        return 0.0
    dot = sum(v * b.get(k, 0) for k, v in a.items())
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb) if na and nb else 0.0


def _cos_dense(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


_kb: KB | None = None


def get_kb() -> KB:
    global _kb
    if _kb is None:
        _kb = KB.load()
    return _kb

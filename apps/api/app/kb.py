"""KB 로딩과 사칭 대상 후보 검색(F4): 정확 일치 → 별칭 → 임베딩(NeMo Retriever) 상위 3개."""
from __future__ import annotations

import json
import math
import re
import unicodedata
from dataclasses import dataclass, field

from .config import settings

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

    def as_candidate(self) -> dict:
        """샌드박스로 올리는 후보 레코드(input.json). 출처 등 불필요한 필드는 뺀다."""
        return {
            "id": self.id, "name": self.name, "aliases": self.aliases,
            "official_domains": self.official_domains, "partner_domains": self.partner_domains,
            "policies": self.policies,
        }


class KB:
    def __init__(self, entities: list[Entity]):
        self.entities = entities
        self.by_id = {e.id: e for e in entities}
        self._vecs: dict[str, list[float]] | None = None

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
        return cls(ents)

    def official_records(self) -> list[dict]:
        return [{"entity_id": e.id, "domain": d} for e in self.entities for d in e.official_domains]

    def all_known_domains(self) -> set[str]:
        s: set[str] = set()
        for e in self.entities:
            s.update(e.official_domains)
            s.update(e.partner_domains)
        return s

    # ── 후보 검색 ────────────────────────────────────────────────
    def candidates(self, text: str, limit: int = 3) -> list[tuple[Entity, str]]:
        """(엔티티, 출처) 목록. 정확·별칭 일치가 있으면 그것만, 없으면 임베딩 상위 limit개."""
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
            r = httpx.post(
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
        q = embed([text[:1000]], "query")[0]
        scored = sorted(((_cos_dense(q, self._vecs[e.id]), e) for e in self.entities), key=lambda x: -x[0])
        return [e for _, e in scored]


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

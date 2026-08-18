"""ATT&CK retrieval — Qdrant primary, keyword index fallback.

Retrieval strategy
------------------
The Qdrant collection stores several document types per technique (summary,
detection, datasource, procedure, mitigation, detects — see spark1/attack_ingest.py).
Raw top-k over that mixture is biased toward whichever type happens to be most
verbose. This module instead:

  1. over-fetches (k * 3) across all doc types,
  2. weights by doc_type — `detection` prose is the most useful signal for
     triage, `mitigation` the least,
  3. collapses to distinct techniques by best weighted score,
  4. optionally filters by platform, which cheaply removes whole families of
     wrong answers (Linux techniques for a Windows alert).

If Qdrant is unreachable the module degrades to a keyword index built at
ingestion time. Retrieval quality drops; the pipeline does not stop. Degradation
is reported on the result so the verdict can be flagged and the model told.
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import re
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

import httpx

from .llm import EmbeddingClient
from .models import AttackHit, RagResult

LOG = logging.getLogger("sparksoc.rag")

# Empirically ordered: detection guidance and real procedures describe observable
# behaviour, which is what an alert looks like. Mitigations describe controls,
# which almost never match a log line.
DOC_TYPE_WEIGHT = {
    "detection": 1.00,
    "procedure": 0.95,
    "summary": 0.90,
    "detects": 0.85,
    "datasource": 0.70,
    "mitigation": 0.40,
}

PLATFORM_MAP = {
    "windows": ["Windows"],
    "linux": ["Linux"],
    "network": ["Network", "Network Devices"],
    "cloud": ["IaaS", "SaaS", "Office Suite", "Identity Provider", "Azure AD"],
}


class AttackRetriever:
    def __init__(
        self,
        qdrant_url: str,
        qdrant_api_key: str,
        collection: str,
        embedder: EmbeddingClient,
        keyword_index_path: Path,
        top_k: int = 12,
        max_techniques: int = 8,
    ):
        self.collection = collection
        self.embedder = embedder
        self.top_k = top_k
        self.max_techniques = max_techniques
        self._client = httpx.AsyncClient(
            base_url=qdrant_url.rstrip("/"),
            timeout=httpx.Timeout(20.0, connect=5.0),
            headers={"api-key": qdrant_api_key, "Content-Type": "application/json"},
        )
        self._keyword_index: dict[str, Any] | None = None
        self._keyword_path = keyword_index_path
        self._qdrant_ok = True

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------
    async def health(self) -> bool:
        try:
            r = await self._client.get(f"/collections/{self.collection}", timeout=5.0)
            self._qdrant_ok = r.status_code == 200
            return self._qdrant_ok
        except Exception:
            self._qdrant_ok = False
            return False

    async def collection_size(self) -> int:
        try:
            r = await self._client.get(f"/collections/{self.collection}")
            r.raise_for_status()
            return int(r.json()["result"]["points_count"] or 0)
        except Exception:
            return -1

    # ------------------------------------------------------------------
    async def retrieve(self, query: str, platform: str = "unknown") -> RagResult:
        start = time.perf_counter()
        try:
            hits = await self._retrieve_vector(query, platform)
            result = self._collapse(hits)
            result.latency_ms = int((time.perf_counter() - start) * 1000)
            return result
        except Exception as exc:
            LOG.error("Vector retrieval failed (%s); falling back to keyword index", exc)
            result = self._retrieve_keyword(query, platform)
            result.degraded = True
            result.degraded_reason = f"qdrant unavailable: {type(exc).__name__}"
            result.latency_ms = int((time.perf_counter() - start) * 1000)
            return result

    # ------------------------------------------------------------------
    async def _retrieve_vector(self, query: str, platform: str) -> list[AttackHit]:
        vec = (await self.embedder.embed([query]))[0]

        body: dict[str, Any] = {
            "query": vec,
            "limit": self.top_k * 3,
            "with_payload": True,
        }

        # Platform filter is a `should` rather than a `must`: many techniques
        # legitimately list no platform, and excluding them loses real answers.
        platform_values = PLATFORM_MAP.get(platform)
        if platform_values:
            body["filter"] = {
                "should": [
                    {"key": "platforms", "match": {"any": platform_values}},
                    {"is_empty": {"key": "platforms"}},
                ]
            }

        r = await self._client.post(f"/collections/{self.collection}/points/query", json=body)
        r.raise_for_status()
        points = r.json()["result"]["points"]

        hits: list[AttackHit] = []
        for p in points:
            payload = p.get("payload", {})
            doc_type = payload.get("doc_type", "summary")
            raw_score = float(p.get("score", 0.0))
            hits.append(AttackHit(
                technique_id=payload.get("technique_id", ""),
                technique_name=payload.get("technique_name", ""),
                doc_type=doc_type,
                score=raw_score * DOC_TYPE_WEIGHT.get(doc_type, 0.8),
                tactics=payload.get("tactics", []) or [],
                platforms=payload.get("platforms", []) or [],
                text=payload.get("text", ""),
                url=payload.get("url", ""),
            ))
        return hits

    # ------------------------------------------------------------------
    def _collapse(self, hits: list[AttackHit]) -> RagResult:
        """Keep the best-scoring chunk per (technique, doc_type), then rank techniques.

        Retaining two doc types per technique gives the triage model both the
        'what it is' and the 'how you would see it' views, which measurably
        improves its rationales.
        """
        best: dict[tuple[str, str], AttackHit] = {}
        for h in hits:
            if not h.technique_id:
                continue
            key = (h.technique_id, h.doc_type)
            if key not in best or h.score > best[key].score:
                best[key] = h

        by_technique: dict[str, list[AttackHit]] = defaultdict(list)
        for h in best.values():
            by_technique[h.technique_id].append(h)

        ranked = sorted(
            by_technique.items(),
            key=lambda kv: max(x.score for x in kv[1]),
            reverse=True,
        )[: self.max_techniques]

        selected: list[AttackHit] = []
        for _tid, group in ranked:
            group.sort(key=lambda x: x.score, reverse=True)
            selected.extend(group[:2])

        selected.sort(key=lambda x: x.score, reverse=True)
        return RagResult(
            hits=selected,
            technique_ids=[tid for tid, _ in ranked],
        )

    # ------------------------------------------------------------------
    def _load_keyword_index(self) -> dict[str, Any]:
        if self._keyword_index is None:
            try:
                self._keyword_index = json.loads(self._keyword_path.read_text(encoding="utf-8"))
                LOG.info("Loaded keyword fallback index: %d techniques", len(self._keyword_index))
            except Exception as exc:
                LOG.error("Keyword fallback index unavailable at %s (%s). "
                          "Retrieval will return nothing if Qdrant is down.",
                          self._keyword_path, exc)
                self._keyword_index = {}
        return self._keyword_index

    def _retrieve_keyword(self, query: str, platform: str) -> RagResult:
        index = self._load_keyword_index()
        if not index:
            return RagResult(hits=[], technique_ids=[], degraded=True,
                             degraded_reason="qdrant down and no keyword index available")

        q_terms = set(re.findall(r"[A-Za-z][A-Za-z0-9_.\-]{3,}", query.lower()))
        if not q_terms:
            return RagResult(hits=[], technique_ids=[], degraded=True,
                             degraded_reason="query produced no searchable terms")

        platform_values = set(PLATFORM_MAP.get(platform, []))
        scored: list[tuple[float, dict[str, Any]]] = []

        for tid, entry in index.items():
            terms = set(entry.get("terms", []))
            if not terms:
                continue
            overlap = q_terms & terms
            if not overlap:
                continue
            # Jaccard-ish with a length penalty so verbose techniques do not win
            # purely by having more terms.
            score = len(overlap) / math.sqrt(len(terms) + 1)

            if platform_values:
                ep = set(entry.get("platforms", []))
                if ep and not (ep & platform_values):
                    score *= 0.4

            # Direct technique-ID mention in the query is a very strong signal
            if tid.lower() in query.lower():
                score += 5.0

            scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        top = scored[: self.max_techniques]

        hits = [
            AttackHit(
                technique_id=e["id"],
                technique_name=e.get("name", ""),
                doc_type="summary",
                score=float(s),
                tactics=e.get("tactics", []),
                platforms=e.get("platforms", []),
                text=e.get("summary", ""),
                url=e.get("url", ""),
            )
            for s, e in top
        ]
        return RagResult(hits=hits, technique_ids=[h.technique_id for h in hits])

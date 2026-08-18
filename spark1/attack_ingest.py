#!/usr/bin/env python3
"""
MITRE ATT&CK Enterprise STIX 2.1 -> Qdrant ingestion for SPARKSOC.

Design notes
------------
Retrieval quality for SOC triage is dominated by *what you index*, not by the
embedding model. A naive "one vector per technique description" index performs
badly because analyst-facing queries look like log lines and detection ideas,
not like encyclopedia prose. This script therefore emits several document types
per technique, each independently embedded:

    summary     name + description + tactic + platform context
    detection   x_mitre_detection prose (the closest thing ATT&CK has to a
                detection engineering hint — highest-value field for triage)
    datasource  data source / data component coverage
    procedure   real-world procedure examples from group/software relationships
    mitigation  associated course-of-action text

All share a `technique_id` payload field so results collapse back to techniques
at query time, and carry `doc_type` so the harness can weight or filter.

Also emits a keyword fallback index used by the harness when Qdrant is
unavailable (see docs/00-ARCHITECTURE.md section 7).

Airgapped: reads a local STIX file, talks only to the local embedding server
and the local Qdrant. No network egress.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

import httpx
from qdrant_client import QdrantClient
from qdrant_client.http import models as qm

LOG = logging.getLogger("attack_ingest")

# Deterministic namespace so re-ingestion updates points in place instead of
# duplicating them.
NAMESPACE = uuid.UUID("6f4a1f2e-9c3d-4b7a-8e51-2d0c7a9b4e13")

MITRE_SOURCES = {"mitre-attack", "mitre-ics-attack", "mitre-mobile-attack"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class AttackDoc:
    """One embeddable chunk."""
    technique_id: str
    technique_name: str
    doc_type: str
    text: str
    tactics: list[str] = field(default_factory=list)
    platforms: list[str] = field(default_factory=list)
    data_sources: list[str] = field(default_factory=list)
    is_subtechnique: bool = False
    parent_id: str | None = None
    url: str = ""
    chunk_index: int = 0

    def point_id(self) -> str:
        key = f"{self.technique_id}|{self.doc_type}|{self.chunk_index}"
        return str(uuid.uuid5(NAMESPACE, key))

    def payload(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "doc_type": self.doc_type,
            "text": self.text,
            "tactics": self.tactics,
            "platforms": self.platforms,
            "data_sources": self.data_sources,
            "is_subtechnique": self.is_subtechnique,
            "parent_id": self.parent_id,
            "url": self.url,
            "chunk_index": self.chunk_index,
        }


# ---------------------------------------------------------------------------
# STIX parsing
# ---------------------------------------------------------------------------

def load_bundle(path: Path) -> list[dict[str, Any]]:
    LOG.info("Loading STIX bundle: %s", path)
    with path.open("r", encoding="utf-8") as fh:
        bundle = json.load(fh)
    if bundle.get("type") != "bundle":
        raise ValueError(f"{path} is not a STIX bundle (type={bundle.get('type')!r})")
    objects = bundle.get("objects", [])
    LOG.info("Bundle contains %d objects", len(objects))
    return objects


def mitre_id(obj: dict[str, Any]) -> str | None:
    """Extract the ATT&CK external ID (Txxxx, Gxxxx, Sxxxx, Mxxxx)."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in MITRE_SOURCES and ref.get("external_id"):
            return ref["external_id"]
    return None


def mitre_url(obj: dict[str, Any]) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in MITRE_SOURCES:
            return ref.get("url", "")
    return ""


def clean(text: str | None) -> str:
    """Strip STIX markdown citation noise that pollutes embeddings."""
    if not text:
        return ""
    # (Citation: Foo Bar 2021) appears thousands of times and carries no signal
    text = re.sub(r"\(Citation:[^)]*\)", "", text)
    # [Display text](https://...) -> Display text
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<code>(.*?)</code>", r"`\1`", text, flags=re.S)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def chunk_text(text: str, max_chars: int = 1400, overlap: int = 160) -> list[str]:
    """Paragraph-aware chunking. ATT&CK prose is short; most fields yield one chunk."""
    text = text.strip()
    if len(text) <= max_chars:
        return [text] if text else []

    paras = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks: list[str] = []
    buf = ""
    for p in paras:
        if len(buf) + len(p) + 2 <= max_chars:
            buf = f"{buf}\n\n{p}" if buf else p
        else:
            if buf:
                chunks.append(buf)
            if len(p) <= max_chars:
                buf = p
            else:
                # Hard split an oversized paragraph on sentence boundaries
                sentences = re.split(r"(?<=[.!?])\s+", p)
                buf = ""
                for s in sentences:
                    if len(buf) + len(s) + 1 <= max_chars:
                        buf = f"{buf} {s}".strip()
                    else:
                        if buf:
                            chunks.append(buf)
                        buf = s[:max_chars]
    if buf:
        chunks.append(buf)

    if overlap > 0 and len(chunks) > 1:
        overlapped = [chunks[0]]
        for prev, cur in zip(chunks, chunks[1:]):
            overlapped.append((prev[-overlap:] + " " + cur).strip())
        chunks = overlapped
    return chunks


class AttackGraph:
    """Indexes a STIX bundle for relationship traversal."""

    def __init__(self, objects: list[dict[str, Any]]):
        self.by_stix_id: dict[str, dict[str, Any]] = {}
        self.techniques: list[dict[str, Any]] = []
        self.tactics_by_shortname: dict[str, str] = {}
        self.relationships: list[dict[str, Any]] = []

        for obj in objects:
            oid = obj.get("id")
            if oid:
                self.by_stix_id[oid] = obj
            otype = obj.get("type")
            if otype == "attack-pattern":
                self.techniques.append(obj)
            elif otype == "x-mitre-tactic":
                sn = obj.get("x_mitre_shortname")
                if sn:
                    self.tactics_by_shortname[sn] = obj.get("name", sn)
            elif otype == "relationship":
                self.relationships.append(obj)

        # target_ref -> [(relationship_type, source_object)]
        self.incoming: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
        for rel in self.relationships:
            src = self.by_stix_id.get(rel.get("source_ref", ""))
            if src is None:
                continue
            self.incoming[rel.get("target_ref", "")].append(
                (rel.get("relationship_type", ""), rel)
            )

    def tactic_names(self, technique: dict[str, Any]) -> list[str]:
        names = []
        for phase in technique.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") == "mitre-attack":
                sn = phase.get("phase_name", "")
                names.append(self.tactics_by_shortname.get(sn, sn.replace("-", " ").title()))
        return names

    def related(self, technique: dict[str, Any], rel_type: str) -> list[tuple[dict[str, Any], str]]:
        """Return (source_object, relationship_description) for incoming relationships."""
        out = []
        for rtype, rel in self.incoming.get(technique.get("id", ""), []):
            if rtype != rel_type:
                continue
            src = self.by_stix_id.get(rel.get("source_ref", ""))
            if src is None or src.get("revoked") or src.get("x_mitre_deprecated"):
                continue
            out.append((src, clean(rel.get("description"))))
        return out


# ---------------------------------------------------------------------------
# Document construction
# ---------------------------------------------------------------------------

def build_documents(graph: AttackGraph, include_deprecated: bool = False) -> list[AttackDoc]:
    docs: list[AttackDoc] = []
    skipped = 0

    for tech in graph.techniques:
        if not include_deprecated and (tech.get("revoked") or tech.get("x_mitre_deprecated")):
            skipped += 1
            continue

        tid = mitre_id(tech)
        if not tid:
            skipped += 1
            continue

        name = tech.get("name", "")
        tactics = graph.tactic_names(tech)
        platforms = tech.get("x_mitre_platforms", []) or []
        data_sources = tech.get("x_mitre_data_sources", []) or []
        is_sub = bool(tech.get("x_mitre_is_subtechnique"))
        parent = tid.split(".")[0] if is_sub and "." in tid else None
        url = mitre_url(tech)

        def mk(doc_type: str, text: str, idx: int = 0) -> AttackDoc:
            return AttackDoc(
                technique_id=tid, technique_name=name, doc_type=doc_type, text=text,
                tactics=tactics, platforms=platforms, data_sources=data_sources,
                is_subtechnique=is_sub, parent_id=parent, url=url, chunk_index=idx,
            )

        # --- summary ------------------------------------------------------
        # The header line is repeated into every chunk. This is deliberate: it
        # keeps each vector self-identifying, which materially improves recall
        # when a query names a tactic or platform rather than the technique.
        header = (
            f"MITRE ATT&CK {tid}: {name}\n"
            f"Tactics: {', '.join(tactics) or 'unspecified'}\n"
            f"Platforms: {', '.join(platforms) or 'unspecified'}\n"
        )
        description = clean(tech.get("description"))
        for i, chunk in enumerate(chunk_text(header + "\n" + description)):
            docs.append(mk("summary", chunk, i))

        # --- detection ----------------------------------------------------
        detection = clean(tech.get("x_mitre_detection"))
        if detection:
            body = f"{header}\nDetection guidance:\n{detection}"
            for i, chunk in enumerate(chunk_text(body)):
                docs.append(mk("detection", chunk, i))

        # --- data sources -------------------------------------------------
        if data_sources:
            body = (
                f"{header}\nData sources and components that observe {tid} ({name}):\n"
                + "\n".join(f"- {ds}" for ds in data_sources)
            )
            docs.append(mk("datasource", body))

        # --- procedure examples (groups and software that use it) ----------
        procedures: list[str] = []
        for src, desc in graph.related(tech, "uses"):
            src_id = mitre_id(src) or ""
            src_name = src.get("name", "")
            kind = {"intrusion-set": "Group", "malware": "Malware",
                    "tool": "Tool", "campaign": "Campaign"}.get(src.get("type", ""), "Entity")
            if desc:
                procedures.append(f"{kind} {src_name} ({src_id}): {desc}")
            else:
                procedures.append(f"{kind} {src_name} ({src_id}) uses this technique.")
        if procedures:
            body = f"{header}\nObserved real-world procedures for {tid}:\n" + "\n".join(procedures)
            for i, chunk in enumerate(chunk_text(body, max_chars=1600)):
                docs.append(mk("procedure", chunk, i))

        # --- mitigations ---------------------------------------------------
        mitigations: list[str] = []
        for src, desc in graph.related(tech, "mitigates"):
            if src.get("type") != "course-of-action":
                continue
            mid = mitre_id(src) or ""
            mitigations.append(f"{src.get('name','')} ({mid}): {desc or clean(src.get('description'))}")
        if mitigations:
            body = f"{header}\nMitigations for {tid}:\n" + "\n".join(mitigations)
            for i, chunk in enumerate(chunk_text(body, max_chars=1600)):
                docs.append(mk("mitigation", chunk, i))

        # --- detection relationships (x-mitre-data-component detects) -------
        detects: list[str] = []
        for src, desc in graph.related(tech, "detects"):
            if src.get("type") != "x-mitre-data-component":
                continue
            detects.append(f"{src.get('name','')}: {desc}")
        if detects:
            body = f"{header}\nData components that detect {tid}:\n" + "\n".join(detects)
            for i, chunk in enumerate(chunk_text(body, max_chars=1600)):
                docs.append(mk("detects", chunk, i))

    LOG.info("Built %d documents from %d techniques (%d skipped as deprecated/revoked/unidentified)",
             len(docs), len(graph.techniques) - skipped, skipped)

    counts: dict[str, int] = defaultdict(int)
    for d in docs:
        counts[d.doc_type] += 1
    for k in sorted(counts):
        LOG.info("  %-12s %d", k, counts[k])
    return docs


# ---------------------------------------------------------------------------
# Embeddings
# ---------------------------------------------------------------------------

class EmbeddingClient:
    def __init__(self, base_url: str, model: str, api_key: str | None,
                 batch_size: int = 32, timeout: float = 300.0):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.batch_size = batch_size
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self.client = httpx.Client(timeout=timeout, headers=headers)

    def close(self) -> None:
        self.client.close()

    def probe_dim(self) -> int:
        vec = self._embed_once(["dimension probe"])[0]
        return len(vec)

    def _embed_once(self, texts: list[str]) -> list[list[float]]:
        resp = self.client.post(
            f"{self.base_url}/embeddings",
            json={"model": self.model, "input": texts},
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        # The server may return out of order; sort by index defensively.
        data.sort(key=lambda d: d.get("index", 0))
        return [d["embedding"] for d in data]

    def embed(self, texts: list[str]) -> list[list[float]]:
        """Batch with retry and adaptive batch shrinking on failure."""
        out: list[list[float]] = []
        i = 0
        batch = self.batch_size
        while i < len(texts):
            window = texts[i:i + batch]
            for attempt in range(1, 5):
                try:
                    out.extend(self._embed_once(window))
                    i += len(window)
                    break
                except httpx.HTTPStatusError as exc:
                    # 400 usually means the batch exceeded max_model_len budget
                    if exc.response.status_code == 400 and batch > 1:
                        batch = max(1, batch // 2)
                        LOG.warning("Embedding 400 — shrinking batch to %d", batch)
                        break
                    if attempt == 4:
                        raise
                    wait = 2 ** attempt
                    LOG.warning("Embedding HTTP %s, retry %d in %ss",
                                exc.response.status_code, attempt, wait)
                    time.sleep(wait)
                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    if attempt == 4:
                        raise
                    wait = 2 ** attempt
                    LOG.warning("Embedding transport error (%s), retry %d in %ss", exc, attempt, wait)
                    time.sleep(wait)
        return out


# ---------------------------------------------------------------------------
# Qdrant
# ---------------------------------------------------------------------------

def ensure_collection(client: QdrantClient, name: str, dim: int, recreate: bool) -> None:
    exists = client.collection_exists(name)

    if exists and recreate:
        LOG.warning("Deleting existing collection %r", name)
        client.delete_collection(name)
        exists = False

    if exists:
        info = client.get_collection(name)
        current = info.config.params.vectors.size
        if current != dim:
            raise SystemExit(
                f"Collection {name!r} has vector dim {current}, embedding server returns {dim}.\n"
                f"These must match. Re-run with --recreate to rebuild, which discards the index."
            )
        LOG.info("Reusing collection %r (%d points)", name, info.points_count or 0)
        return

    LOG.info("Creating collection %r (dim=%d, cosine)", name, dim)
    client.create_collection(
        collection_name=name,
        vectors_config=qm.VectorParams(
            size=dim,
            distance=qm.Distance.COSINE,
            # ATT&CK is ~15k vectors. Full HNSW is cheap and recall matters more
            # than index build time here.
            hnsw_config=qm.HnswConfigDiff(m=32, ef_construct=256),
        ),
        optimizers_config=qm.OptimizersConfigDiff(default_segment_number=2),
    )

    # Payload indexes so the harness can filter by platform/tactic cheaply.
    for field_name, schema in [
        ("technique_id", qm.PayloadSchemaType.KEYWORD),
        ("doc_type", qm.PayloadSchemaType.KEYWORD),
        ("tactics", qm.PayloadSchemaType.KEYWORD),
        ("platforms", qm.PayloadSchemaType.KEYWORD),
        ("is_subtechnique", qm.PayloadSchemaType.BOOL),
    ]:
        client.create_payload_index(collection_name=name, field_name=field_name, field_schema=schema)
    LOG.info("Payload indexes created")


def upsert(client: QdrantClient, collection: str, docs: list[AttackDoc],
           vectors: list[list[float]], batch: int = 256) -> None:
    total = len(docs)
    for start in range(0, total, batch):
        window = list(zip(docs[start:start + batch], vectors[start:start + batch]))
        points = [
            qm.PointStruct(id=d.point_id(), vector=v, payload=d.payload())
            for d, v in window
        ]
        client.upsert(collection_name=collection, points=points, wait=True)
        done = min(start + batch, total)
        LOG.info("  upserted %d/%d (%.0f%%)", done, total, 100 * done / total)


# ---------------------------------------------------------------------------
# Keyword fallback index (used when Qdrant is unavailable)
# ---------------------------------------------------------------------------

def write_keyword_index(graph: AttackGraph, docs: list[AttackDoc], path: Path) -> None:
    """
    Minimal inverted index over technique names, IDs and detection prose.
    The harness falls back to this so a Qdrant outage degrades retrieval
    quality rather than taking the pipeline down.
    """
    index: dict[str, dict[str, Any]] = {}
    for d in docs:
        entry = index.setdefault(d.technique_id, {
            "id": d.technique_id,
            "name": d.technique_name,
            "tactics": d.tactics,
            "platforms": d.platforms,
            "url": d.url,
            "is_subtechnique": d.is_subtechnique,
            "parent_id": d.parent_id,
            "terms": set(),
            "summary": "",
        })
        if d.doc_type == "summary" and d.chunk_index == 0 and not entry["summary"]:
            entry["summary"] = d.text[:600]
        for tok in re.findall(r"[A-Za-z][A-Za-z0-9_.\-]{3,}", d.text.lower()):
            entry["terms"].add(tok)

    serialisable = {}
    for tid, e in index.items():
        # Cap term sets; the long tail contributes noise, not recall.
        e["terms"] = sorted(e["terms"])[:400]
        serialisable[tid] = e

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(serialisable, indent=0), encoding="utf-8")
    LOG.info("Keyword fallback index written: %s (%d techniques)", path, len(serialisable))


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

VERIFY_QUERIES = [
    ("powershell -nop -w hidden -enc base64 encoded command", "T1059.001"),
    ("scheduled task created via schtasks for persistence", "T1053.005"),
    ("lsass.exe memory dumped with procdump", "T1003.001"),
    ("wmic process call create remote execution", "T1047"),
    ("net user /add administrator local account created", "T1136.001"),
    ("rundll32 executing exported function from dll", "T1218.011"),
    ("suspicious outbound dns tunneling long subdomain queries", "T1071.004"),
    ("linux cron job added to /etc/cron.d for persistence", "T1053.003"),
]


def verify(client: QdrantClient, collection: str, embedder: EmbeddingClient) -> bool:
    LOG.info("--- retrieval verification ---")
    passed = 0
    for query, expected in VERIFY_QUERIES:
        vec = embedder.embed([query])[0]
        hits = client.query_points(
            collection_name=collection, query=vec, limit=5, with_payload=True
        ).points
        found = [h.payload["technique_id"] for h in hits]
        hit = expected in found
        passed += hit
        LOG.info("  %s  %-58s -> %s",
                 "PASS" if hit else "MISS", query[:58], ", ".join(found[:5]))
        if not hit:
            LOG.info("        expected %s in top-5", expected)
    rate = passed / len(VERIFY_QUERIES)
    LOG.info("--- top-5 recall on canned queries: %d/%d (%.0f%%) ---",
             passed, len(VERIFY_QUERIES), 100 * rate)
    if rate < 0.6:
        LOG.error("Recall below 60%%. Check the embedding model and that doc_type "
                  "'detection' documents were created.")
        return False
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Ingest MITRE ATT&CK STIX into Qdrant")
    ap.add_argument("--stix", default=os.getenv("ATTACK_STIX_PATH", "/opt/sparksoc/attack/enterprise-attack.json"))
    ap.add_argument("--qdrant-url", default=os.getenv("QDRANT_URL", "http://127.0.0.1:6333"))
    ap.add_argument("--qdrant-api-key", default=os.getenv("QDRANT_API_KEY"))
    ap.add_argument("--collection", default=os.getenv("QDRANT_COLLECTION", "attack_enterprise"))
    ap.add_argument("--embed-url", default=os.getenv("EMBED_ENDPOINT", "http://127.0.0.1:8002/v1"))
    ap.add_argument("--embed-model", default=os.getenv("EMBED_MODEL_NAME", "soc-embed"))
    ap.add_argument("--embed-api-key", default=os.getenv("VLLM_API_KEY"))
    ap.add_argument("--batch-size", type=int, default=32)
    ap.add_argument("--keyword-index", default=os.getenv("ATTACK_KEYWORD_INDEX",
                                                         "/opt/sparksoc/attack/attack_keyword_index.json"))
    ap.add_argument("--include-deprecated", action="store_true")
    ap.add_argument("--recreate", action="store_true", help="drop and rebuild the collection")
    ap.add_argument("--dry-run", action="store_true", help="build documents, skip embedding and upsert")
    ap.add_argument("--skip-verify", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    stix_path = Path(args.stix)
    if not stix_path.exists():
        LOG.error("STIX bundle not found: %s", stix_path)
        return 1

    t0 = time.time()
    graph = AttackGraph(load_bundle(stix_path))
    LOG.info("Indexed %d techniques, %d tactics, %d relationships",
             len(graph.techniques), len(graph.tactics_by_shortname), len(graph.relationships))

    docs = build_documents(graph, include_deprecated=args.include_deprecated)
    if not docs:
        LOG.error("No documents built — bundle may be malformed.")
        return 1

    write_keyword_index(graph, docs, Path(args.keyword_index))

    if args.dry_run:
        LOG.info("Dry run: %d documents would be embedded. Sample:", len(docs))
        for d in docs[:3]:
            LOG.info("  [%s] %s\n%s\n", d.doc_type, d.technique_id, d.text[:400])
        return 0

    embedder = EmbeddingClient(args.embed_url, args.embed_model,
                               args.embed_api_key, batch_size=args.batch_size)
    try:
        dim = embedder.probe_dim()
        LOG.info("Embedding server reports dimension %d", dim)

        client = QdrantClient(url=args.qdrant_url, api_key=args.qdrant_api_key, timeout=120)
        ensure_collection(client, args.collection, dim, args.recreate)

        LOG.info("Embedding %d documents (batch=%d)...", len(docs), args.batch_size)
        te = time.time()
        vectors = embedder.embed([d.text for d in docs])
        LOG.info("Embedded in %.1fs (%.1f docs/s)", time.time() - te, len(docs) / max(time.time() - te, 1e-6))

        if len(vectors) != len(docs):
            LOG.error("Vector count %d != document count %d", len(vectors), len(docs))
            return 1

        LOG.info("Upserting into %r...", args.collection)
        upsert(client, args.collection, docs, vectors)

        info = client.get_collection(args.collection)
        LOG.info("Collection %r now holds %d points", args.collection, info.points_count)

        if not args.skip_verify:
            if not verify(client, args.collection, embedder):
                return 2
    finally:
        embedder.close()

    LOG.info("Ingestion complete in %.1fs", time.time() - t0)
    return 0


if __name__ == "__main__":
    sys.exit(main())

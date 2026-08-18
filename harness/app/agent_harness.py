#!/usr/bin/env python3
"""SPARKSOC agent harness — FastAPI service on the management VM.

Ingests Splunk Enterprise alerts, orchestrates triage on Spark 1 and deep
reasoning on Spark 2, and dispatches tiered response through Splunk SOAR.

Run:
    uvicorn app.agent_harness:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

from fastapi import Body, FastAPI, Path as PathParam, Query, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from .actions import ActionAllowlist
from .audit import AuditEvent, AuditLog
from .auth import NonceCache, verify_fallback_token, verify_signed_request
from .config import get_settings
from .llm import EmbeddingClient, SparkClient
from .models import CaseStatus, GroundTruthEvent, SplunkAlert
from .pipeline import CaseStore, Pipeline
from .rag import AttackRetriever
from .scoring import (
    ExerciseTracker, parse_atomic_red_team, parse_caldera,
    report_to_dict, report_to_html,
)
from .soar import SoarClient

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
S = get_settings()
logging.basicConfig(
    level=getattr(logging, S.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
    stream=sys.stdout,
)
LOG = logging.getLogger("sparksoc.harness")

# ---------------------------------------------------------------------------
# Component wiring
# ---------------------------------------------------------------------------
triage_client = SparkClient(S.triage_endpoint, "spark1-triage")
reason_client = SparkClient(S.reason_endpoint, "spark2-reason")
embedder = EmbeddingClient(S.embed_url, S.embed_model, S.spark1_api_key, S.embed_timeout)
retriever = AttackRetriever(S.qdrant_url, S.qdrant_api_key, S.qdrant_collection,
                            embedder, S.attack_keyword_index, S.rag_top_k, S.rag_techniques)
soar = SoarClient(S.soar_url, S.soar_token, verify=S.soar_verify, timeout=S.soar_timeout,
                  label=S.soar_label, retry_journal=S.state_dir / "soar_retry.jsonl",
                  poll_interval=S.soar_action_poll_interval,
                  poll_timeout=S.soar_action_poll_timeout)
allowlist = ActionAllowlist(S.allowlist_path, force_dry_run=S.force_dry_run)
audit = AuditLog(S.audit_path)
store = CaseStore(S.case_retention_hours)
tracker = ExerciseTracker(S.state_dir / "exercises")
pipeline = Pipeline(S, triage_client, reason_client, retriever, soar, allowlist, audit, store)

_redis = None
nonce_cache = NonceCache(None, S.nonce_ttl_seconds)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    global _redis, nonce_cache

    LOG.info("=" * 70)
    LOG.info("SPARKSOC agent harness starting (env=%s)", S.env)
    LOG.info("  triage  %s (%s)", S.triage_url, S.triage_model)
    LOG.info("  embed   %s (%s)", S.embed_url, S.embed_model)
    LOG.info("  reason  %s (%s)", S.reason_url, S.reason_model)
    LOG.info("  qdrant  %s/%s", S.qdrant_url, S.qdrant_collection)
    LOG.info("  soar    %s", S.soar_url)
    LOG.info("=" * 70)

    # ---- allowlist self-test: refuse to run with a broken security boundary --
    problems = allowlist.self_test()
    if problems:
        for p in problems:
            LOG.error("ALLOWLIST: %s", p)
        raise RuntimeError(
            f"Action allowlist has {len(problems)} consistency problem(s). "
            f"Refusing to start — the allowlist is the boundary between model output "
            f"and the range, and a malformed one is not a boundary."
        )
    LOG.info("Action allowlist v%s validated: %d COLLECT, %d CONTAIN, dry_run=%s",
             allowlist.version, len(allowlist.collect_action_ids()),
             sum(1 for a in allowlist.actions.values() if a.get("tier") == "CONTAIN"),
             allowlist.dry_run)
    if allowlist.dry_run:
        LOG.warning("DRY RUN MODE — no SOAR action will be dispatched. "
                    "Verdicts and audit records are still produced.")

    # ---- SOAR CA bundle sanity -------------------------------------------
    # A missing bind-mount source makes Docker create a DIRECTORY here, which
    # produces a baffling TLS error later. Say so plainly at startup instead.
    if isinstance(S.soar_verify, str) and S.soar_verify not in ("true", "false", "1", "0", ""):
        ca = Path(S.soar_verify)
        if ca.is_dir():
            LOG.error("SOAR_CA_BUNDLE %s is a DIRECTORY, not a file. Docker created it "
                      "because the bind-mount source was missing. See harness/certs/README.md.", ca)
        elif not ca.exists():
            LOG.warning("SOAR_CA_BUNDLE %s does not exist; falling back to system trust store.", ca)

    # ---- audit chain ----------------------------------------------------
    ok, msg = audit.verify_chain()
    (LOG.info if ok else LOG.error)("Audit chain: %s", msg)

    # ---- redis ----------------------------------------------------------
    try:
        import redis.asyncio as aioredis
        _redis = aioredis.from_url(S.redis_url, decode_responses=True)
        await _redis.ping()
        nonce_cache = NonceCache(_redis, S.nonce_ttl_seconds)
        LOG.info("Redis connected: %s", S.redis_url)
    except Exception as exc:
        LOG.warning("Redis unavailable (%s). Dedupe and replay protection are "
                    "in-process only for this instance.", exc)
        nonce_cache = NonceCache(None, S.nonce_ttl_seconds)

    # ---- dependency probes (warn, do not block startup) ------------------
    for name, coro in (("spark1-triage", triage_client.health()),
                       ("spark1-embed", embedder.health()),
                       ("spark2-reason", reason_client.health()),
                       ("qdrant", retriever.health()),
                       ("soar", soar.health())):
        try:
            healthy = await asyncio.wait_for(coro, timeout=15)
        except Exception:
            healthy = False
        (LOG.info if healthy else LOG.warning)("  dependency %-14s %s",
                                               name, "OK" if healthy else "UNREACHABLE")

    size = await retriever.collection_size()
    if size <= 0:
        LOG.error("Qdrant collection %r reports %d points. ATT&CK retrieval will be "
                  "degraded for every case. Run spark1/attack_ingest.py.",
                  S.qdrant_collection, size)
    else:
        LOG.info("  ATT&CK collection: %d points", size)

    await pipeline.start()
    await audit.write(AuditEvent.SERVICE_START,
                      detail={"env": S.env, "dry_run": allowlist.dry_run,
                              "allowlist_version": allowlist.version})

    yield

    await audit.write(AuditEvent.SERVICE_STOP, detail={})
    await pipeline.stop()
    for closer in (triage_client.aclose(), reason_client.aclose(),
                   embedder.aclose(), retriever.aclose(), soar.aclose()):
        with contextlib.suppress(Exception):
            await closer
    if _redis:
        with contextlib.suppress(Exception):
            await _redis.aclose()
    LOG.info("Harness stopped")


app = FastAPI(
    title="SPARKSOC Agent Harness",
    version="1.0.0",
    description="Airgapped dual-DGX-Spark AI SOC pipeline",
    lifespan=lifespan,
    docs_url="/docs" if S.env != "production" else None,
    redoc_url=None,
)


# ===========================================================================
# Ingestion
# ===========================================================================

async def _dedupe(fingerprint: str) -> bool:
    """True if this fingerprint was seen recently (i.e. should be suppressed)."""
    if _redis is None:
        return False
    try:
        fresh = await _redis.set(f"sparksoc:dedupe:{fingerprint}", "1",
                                 nx=True, ex=S.dedupe_ttl_seconds)
        return not bool(fresh)
    except Exception:
        return False


async def _ingest(alert: SplunkAlert, request: Request, method: str) -> JSONResponse:
    fingerprint = alert.fingerprint()

    if await _dedupe(fingerprint):
        pipeline.metrics["alerts_deduped"] += 1
        await audit.write(AuditEvent.ALERT_DEDUPED,
                          detail={"fingerprint": fingerprint,
                                  "search_name": alert.search_name,
                                  "ttl_seconds": S.dedupe_ttl_seconds})
        return JSONResponse(
            {"status": "deduplicated", "fingerprint": fingerprint,
             "detail": f"An identical alert was processed within the last "
                       f"{S.dedupe_ttl_seconds}s."},
            status_code=status.HTTP_200_OK,
        )

    active = tracker.active()
    case, reason = await pipeline.submit(alert, exercise_id=active.exercise_id if active else None)

    if case is None:
        return JSONResponse(
            {"status": "rejected", "reason": reason,
             "queue_depth": pipeline.fast_queue.qsize(),
             "detail": "The harness is saturated. Retry with backoff."},
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": "30"},
        )

    if active:
        tracker.attach_case(active.exercise_id, case.case_id)

    await audit.write(AuditEvent.ALERT_RECEIVED, case_id=case.case_id,
                      detail={"method": method, "search_name": alert.search_name,
                              "result_count": alert.result_count,
                              "source_ip": request.client.host if request.client else "unknown"})

    return JSONResponse(
        {"status": "accepted", "case_id": case.case_id,
         "fingerprint": fingerprint, "queue_depth": pipeline.fast_queue.qsize()},
        status_code=status.HTTP_202_ACCEPTED,
    )


@app.post("/v1/alert", status_code=status.HTTP_202_ACCEPTED)
async def receive_alert(request: Request):
    """Primary ingestion endpoint. Requires an HMAC-signed body from TA-soc-harness."""
    body = await request.body()

    auth = await verify_signed_request(
        request, body, S.hmac_secret, nonce_cache,
        S.hmac_window_seconds, S.allowed_source_ips,
    )
    if not auth.ok:
        pipeline.metrics["alerts_rejected"] += 1
        await audit.write(AuditEvent.ALERT_REJECTED, severity="warning",
                          detail={"reason": auth.reason,
                                  "source_ip": request.client.host if request.client else "unknown"})
        LOG.warning("Rejected alert: %s", auth.reason)
        return JSONResponse({"status": "unauthorized", "detail": auth.reason},
                            status_code=status.HTTP_401_UNAUTHORIZED)

    try:
        alert = SplunkAlert.model_validate_json(body)
    except Exception as exc:
        await audit.write(AuditEvent.ALERT_REJECTED, severity="warning",
                          detail={"reason": f"malformed payload: {exc}"})
        return JSONResponse({"status": "bad_request", "detail": str(exc)[:400]},
                            status_code=status.HTTP_400_BAD_REQUEST)

    return await _ingest(alert, request, "hmac")


@app.post("/v1/alert/webhook/{token}", status_code=status.HTTP_202_ACCEPTED)
async def receive_webhook(token: str, request: Request):
    """Fallback for Splunk's stock webhook alert action, which cannot sign.

    Weaker than /v1/alert: the token appears in the Splunk alert configuration
    and in any intermediate logs. Disabled unless WEBHOOK_FALLBACK_TOKEN is set.
    The stock webhook also delivers only the FIRST search result, so triage sees
    less than it would through TA-soc-harness.
    """
    auth = verify_fallback_token(request, token, S.webhook_fallback_token, S.allowed_source_ips)
    if not auth.ok:
        await audit.write(AuditEvent.ALERT_REJECTED, severity="warning",
                          detail={"reason": auth.reason, "endpoint": "webhook_fallback"})
        return JSONResponse({"status": "unauthorized", "detail": auth.reason},
                            status_code=status.HTTP_401_UNAUTHORIZED)

    raw = await request.json()

    # Stock webhook envelope: {sid, search_name, result: {...}, results_link, ...}
    single = raw.get("result") or {}
    alert = SplunkAlert(
        search_name=raw.get("search_name", "unknown"),
        sid=raw.get("sid"),
        owner=raw.get("owner"),
        app=raw.get("app"),
        server_host=raw.get("server_host"),
        results_link=raw.get("results_link"),
        result_count=1 if single else 0,
        trigger_time=int(time.time()),
        results=[single] if single else [],
        labels=["stock-webhook"],
    )
    return await _ingest(alert, request, "fallback_token")


# ===========================================================================
# Cases
# ===========================================================================

@app.get("/v1/case/{case_id}")
async def get_case(case_id: str = PathParam(...)):
    case = store.get(case_id)
    if not case:
        return JSONResponse({"detail": "case not found or evicted"},
                            status_code=status.HTTP_404_NOT_FOUND)
    return case.model_dump(mode="json")


@app.get("/v1/cases")
async def list_cases(
    limit: int = Query(50, ge=1, le=500),
    case_status: str | None = Query(None, alias="status"),
    exercise_id: str | None = Query(None),
):
    st = None
    if case_status:
        try:
            st = CaseStatus(case_status)
        except ValueError:
            return JSONResponse(
                {"detail": f"invalid status; expected one of "
                           f"{[s.value for s in CaseStatus]}"},
                status_code=status.HTTP_400_BAD_REQUEST)

    cases = store.list(limit=limit, status=st, exercise_id=exercise_id)
    return {
        "count": len(cases),
        "cases": [
            {
                "case_id": c.case_id,
                "status": c.status.value,
                "created_at": c.created_at,
                "search_name": c.alert.search_name if c.alert else None,
                "host": c.alert.primary_host() if c.alert else None,
                "disposition": (c.deep or c.triage).disposition if (c.deep or c.triage) else None,
                "severity": c.final_severity().value,
                "threat_score": (c.deep or c.triage).threat_score if (c.deep or c.triage) else None,
                "techniques": c.final_technique_ids(),
                "soar_container_id": c.soar_container_id,
                "is_likely_simulation": c.deep.is_likely_simulation if c.deep else None,
                "actions": len(c.actions),
                "errors": len(c.errors),
            }
            for c in cases
        ],
    }


@app.get("/v1/case/{case_id}/stream")
async def stream_case(case_id: str):
    """Server-sent events for a single case.

    This is how a console follows a case without polling: triage lands in
    seconds, the deep verdict arrives up to two minutes later on the same stream.
    """
    case = store.get(case_id)
    if not case:
        return JSONResponse({"detail": "case not found"}, status_code=404)

    async def gen():
        q = store.subscribe(case_id)
        try:
            yield f"event: snapshot\ndata: {json.dumps(case.model_dump(mode='json'), default=str)}\n\n"
            while True:
                try:
                    update = await asyncio.wait_for(q.get(), timeout=20.0)
                    yield f"event: update\ndata: {json.dumps(update, default=str)}\n\n"
                    if update.get("status") in {"complete", "failed"}:
                        yield "event: done\ndata: {}\n\n"
                        break
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            store.unsubscribe(case_id, q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/v1/case/{case_id}/audit")
async def case_audit(case_id: str, limit: int = Query(200, ge=1, le=2000)):
    return {"case_id": case_id, "entries": audit.tail(limit, case_id=case_id)}


# ===========================================================================
# Approvals
# ===========================================================================

class ApprovalDecision(BaseModel):
    decision: str = Field(..., pattern="^(approve|deny)$")
    approver: str = Field(..., min_length=1, max_length=100)
    note: str = ""


@app.get("/v1/approvals")
async def list_approvals():
    now = time.time()
    return {
        "count": len(pipeline.pending_approvals),
        "approvals": [
            {
                "approval_id": aid,
                "case_id": p["case_id"],
                "prompt": p["prompt"],
                "warning": p["warning"],
                "roles": p["roles"],
                "parameters": p["parameters"],
                "expires_in_seconds": max(0, int(p["expires_at"] - now)),
            }
            for aid, p in pipeline.pending_approvals.items()
        ],
    }


@app.post("/v1/approval/{approval_id}")
async def resolve_approval(approval_id: str, body: ApprovalDecision):
    result = await pipeline.resolve_approval(
        approval_id, body.decision, body.approver, body.note)
    code = status.HTTP_200_OK if result.get("ok") else status.HTTP_404_NOT_FOUND
    return JSONResponse(result, status_code=code)


# ===========================================================================
# Exercises
# ===========================================================================

class ExerciseStart(BaseModel):
    name: str
    exercise_id: str | None = None
    match_window_seconds: int = Field(900, ge=60, le=7200)


@app.post("/v1/exercise/start")
async def start_exercise(body: ExerciseStart):
    active = tracker.active()
    if active:
        return JSONResponse(
            {"detail": f"exercise {active.exercise_id} is already running; stop it first"},
            status_code=status.HTTP_409_CONFLICT)

    eid = body.exercise_id or f"EX-{time.strftime('%Y%m%d-%H%M%S')}"
    ex = tracker.start(eid, body.name, body.match_window_seconds)
    await audit.write(AuditEvent.EXERCISE_STARTED,
                      detail={"exercise_id": eid, "name": body.name,
                              "match_window_seconds": body.match_window_seconds})
    return {"exercise_id": ex.exercise_id, "name": ex.name, "started_at": ex.started_at}


@app.post("/v1/exercise/{exercise_id}/stop")
async def stop_exercise(exercise_id: str):
    ex = tracker.stop(exercise_id)
    if not ex:
        return JSONResponse({"detail": "unknown exercise"}, status_code=404)
    await audit.write(AuditEvent.EXERCISE_STOPPED,
                      detail={"exercise_id": exercise_id,
                              "cases": len(ex.case_ids),
                              "ground_truth_events": len(ex.ground_truth)})
    return {"exercise_id": exercise_id, "ended_at": ex.ended_at,
            "cases": len(ex.case_ids), "ground_truth_events": len(ex.ground_truth)}


@app.post("/v1/exercise/{exercise_id}/ground-truth")
async def add_ground_truth(
    exercise_id: str,
    payload: dict[str, Any] = Body(...),
):
    """Register the red team's executed steps.

    Accepts:
      {"format": "atomic",  "events": [...]}   Invoke-AtomicTest execution log
      {"format": "caldera", "events": [...]}   Caldera operation steps export
      {"format": "native",  "events": [...]}   GroundTruthEvent objects
    """
    fmt = (payload.get("format") or "native").lower()
    raw = payload.get("events", [])
    if not isinstance(raw, list):
        return JSONResponse({"detail": "events must be a list"}, status_code=400)

    try:
        if fmt == "atomic":
            events = parse_atomic_red_team(raw)
        elif fmt == "caldera":
            events = parse_caldera(raw)
        else:
            events = [GroundTruthEvent.model_validate(e) for e in raw]
    except Exception as exc:
        return JSONResponse({"detail": f"could not parse events: {exc}"}, status_code=400)

    if not events:
        return JSONResponse(
            {"detail": "no usable events parsed — check that each row carries a "
                       "technique id and a timestamp"},
            status_code=400)

    added = tracker.add_ground_truth(exercise_id, events)
    if added == 0:
        return JSONResponse({"detail": "unknown exercise"}, status_code=404)

    return {"exercise_id": exercise_id, "added": added, "format": fmt,
            "techniques": sorted({e.technique_id for e in events})}


@app.get("/v1/exercise/{exercise_id}/report")
async def exercise_report(exercise_id: str, fmt: str = Query("json", alias="format")):
    ex = tracker.exercises.get(exercise_id)
    if not ex:
        return JSONResponse({"detail": "unknown exercise"}, status_code=404)

    cases = [c for c in (store.get(cid) for cid in ex.case_ids) if c is not None]
    report = tracker.score(exercise_id, cases)
    if report is None:
        return JSONResponse({"detail": "could not score exercise"}, status_code=500)

    if fmt == "html":
        return HTMLResponse(report_to_html(report))
    return report_to_dict(report)


@app.get("/v1/exercises")
async def list_exercises():
    return {
        "exercises": [
            {"exercise_id": e.exercise_id, "name": e.name,
             "started_at": e.started_at, "ended_at": e.ended_at,
             "active": e.ended_at is None,
             "cases": len(e.case_ids), "ground_truth_events": len(e.ground_truth)}
            for e in sorted(tracker.exercises.values(), key=lambda x: -x.started_at)
        ]
    }


# ===========================================================================
# Operations
# ===========================================================================

@app.get("/health")
async def health():
    """Liveness. Deliberately cheap — does not touch dependencies."""
    return {"status": "ok", "env": S.env, "dry_run": allowlist.dry_run}


@app.get("/health/deep")
async def health_deep():
    checks = await asyncio.gather(
        triage_client.health(), embedder.health(), reason_client.health(),
        retriever.health(), soar.health(), return_exceptions=True,
    )
    names = ["spark1_triage", "spark1_embed", "spark2_reason", "qdrant", "soar"]
    results = {n: (c is True) for n, c in zip(names, checks)}

    chain_ok, chain_msg = audit.verify_chain()

    # Spark 1 and the audit chain are load-bearing; the rest degrade gracefully.
    critical_ok = results["spark1_triage"] and results["spark1_embed"] and chain_ok
    body = {
        "status": "ok" if critical_ok else "degraded",
        "dependencies": results,
        "audit_chain": {"ok": chain_ok, "detail": chain_msg},
        "queues": {
            "fast_depth": pipeline.fast_queue.qsize(),
            "fast_capacity": S.queue_max_size,
            "deep_depth": pipeline.deep_queue.qsize(),
            "deep_capacity": S.deep_queue_max_size,
        },
        "backends": {
            "triage": triage_client.stats,
            "reason": reason_client.stats,
        },
        "pending_approvals": len(pipeline.pending_approvals),
    }
    return JSONResponse(body, status_code=200 if critical_ok else 503)


@app.get("/metrics", response_class=PlainTextResponse)
async def metrics():
    """Prometheus text exposition. Scrape target for the enclave monitoring stack."""
    lines: list[str] = []

    def emit(name: str, value: Any, help_text: str, mtype: str = "gauge",
             labels: str = "") -> None:
        lines.append(f"# HELP sparksoc_{name} {help_text}")
        lines.append(f"# TYPE sparksoc_{name} {mtype}")
        lines.append(f"sparksoc_{name}{labels} {value}")

    for k, v in pipeline.metrics.items():
        emit(k, v, f"SPARKSOC {k.replace('_', ' ')}",
             "counter" if k.endswith(("received", "created", "completed",
                                      "dispatched", "rejected", "deduped")) else "gauge")

    emit("queue_depth", pipeline.fast_queue.qsize(), "Fast queue depth", labels='{queue="fast"}')
    emit("queue_depth", pipeline.deep_queue.qsize(), "Deep queue depth", labels='{queue="deep"}')
    emit("queue_capacity", S.queue_max_size, "Fast queue capacity", labels='{queue="fast"}')
    emit("queue_capacity", S.deep_queue_max_size, "Deep queue capacity", labels='{queue="deep"}')

    for name, client in (("triage", triage_client), ("reason", reason_client)):
        st = client.stats
        emit("backend_inflight", st["inflight"], "In-flight LLM requests",
             labels=f'{{backend="{name}"}}')
        emit("backend_errors", st["errors"], "LLM backend errors", "counter",
             labels=f'{{backend="{name}"}}')

    for k, v in pipeline.latency_percentiles().items():
        emit(f"latency_{k}", v, f"Pipeline latency {k}")

    emit("cases_in_store", len(store.list(limit=100000)), "Cases held in memory")
    emit("dry_run", int(allowlist.dry_run), "1 when no action will dispatch")
    emit("allowlist_version", allowlist.version, "Loaded action allowlist version")

    return "\n".join(lines) + "\n"


@app.get("/v1/audit/verify")
async def verify_audit():
    ok, msg = audit.verify_chain()
    return JSONResponse({"ok": ok, "detail": msg, "path": str(audit.path)},
                        status_code=200 if ok else 500)


@app.get("/v1/config")
async def show_config():
    """Non-secret effective configuration. Useful when a deployment misbehaves."""
    return {
        "env": S.env,
        "endpoints": {
            "triage": {"url": S.triage_url, "model": S.triage_model,
                       "concurrency": S.triage_concurrency},
            "embed": {"url": S.embed_url, "model": S.embed_model},
            "reason": {"url": S.reason_url, "model": S.reason_model,
                       "concurrency": S.reason_concurrency},
            "qdrant": {"url": S.qdrant_url, "collection": S.qdrant_collection},
            "soar": {"url": S.soar_url, "label": S.soar_label,
                     "tls_verify": S.soar_verify},
        },
        "pipeline": {
            "workers": S.workers, "deep_workers": S.deep_workers,
            "queue_max_size": S.queue_max_size,
            "deep_queue_max_size": S.deep_queue_max_size,
            "deep_threshold": S.deep_threshold,
            "deep_max_turns": S.deep_max_turns,
            "dedupe_ttl_seconds": S.dedupe_ttl_seconds,
        },
        "actions": {
            "allowlist_version": allowlist.version,
            "allowlist_path": str(S.allowlist_path),
            "dry_run": allowlist.dry_run,
            "collect_actions": allowlist.collect_action_ids(),
            "contain_actions": [k for k, v in allowlist.actions.items()
                                if v.get("tier") == "CONTAIN"],
            "range_cidrs": allowlist.scope.get("range_cidrs", []),
        },
    }


@app.post("/v1/soar/replay")
async def replay_soar():
    """Replay SOAR calls journalled during an outage."""
    count = await soar.replay_journal()
    return {"replayed": count, "soar_available": soar.available}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.agent_harness:app", host=S.bind_host, port=S.bind_port,
                log_level=S.log_level.lower())

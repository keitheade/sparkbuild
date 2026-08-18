"""Pipeline orchestration.

Two queues, two worker pools:

  fast queue  -> stage A (extract) -> stage B (RAG) -> stage C (triage)
                 -> SOAR container created immediately
                 -> enqueue to deep queue if warranted
  deep queue  -> stage D (multi-turn reasoning with evidence collection)
                 -> stage E (action tiering) -> SOAR update

The split exists because the deep path takes 30-120 seconds on a 120B model and
the fast path must not be blocked behind it. A burst of 60 alerts from an Atomic
Red Team chain drains through triage in seconds while the deep path works
through the escalations at its own rate.

Backpressure is explicit: both queues are bounded. When the fast queue is full
the API returns 429 and the Splunk alert action backs off, which is a better
failure than unbounded memory growth followed by an OOM kill mid-exercise.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import time
from typing import Any, Callable

from .actions import ActionAllowlist, ValidationResult
from .audit import AuditEvent, AuditLog
from .config import Settings
from .llm import EmptyContentError, LLMError, SparkClient
from .models import (
    ActionRecord, AlertFeatures, Case, CaseStatus, DeepTurn, DeepVerdict,
    ProposedAction, RagResult, Severity, SplunkAlert, TriageVerdict,
    deep_turn_schema, deep_verdict_schema, FEATURES_SCHEMA, triage_schema,
)
from .prompts import (
    build_deep_conclude_prompt, build_deep_initial_prompt, build_evidence_response,
    build_feature_prompt, build_rag_query, build_triage_prompt,
)
from .rag import AttackRetriever
from .soar import SoarClient, SoarError, SoarUnavailable

LOG = logging.getLogger("sparksoc.pipeline")


class CaseStore:
    """In-memory case store with TTL eviction.

    Deliberately not a database. Cases are ephemeral working state; the durable
    record is the SOAR container and the audit log. Keeping this simple means
    one less thing to restore in an enclave.
    """

    def __init__(self, retention_hours: int = 168):
        self._cases: dict[str, Case] = {}
        self._retention = retention_hours * 3600
        self._subscribers: dict[str, list[asyncio.Queue]] = {}

    def put(self, case: Case) -> None:
        case.touch()
        self._cases[case.case_id] = case
        self._notify(case)

    def get(self, case_id: str) -> Case | None:
        return self._cases.get(case_id)

    def list(self, limit: int = 100, status: CaseStatus | None = None,
             exercise_id: str | None = None) -> list[Case]:
        items = list(self._cases.values())
        if status:
            items = [c for c in items if c.status == status]
        if exercise_id:
            items = [c for c in items if c.exercise_id == exercise_id]
        items.sort(key=lambda c: c.created_at, reverse=True)
        return items[:limit]

    def evict(self) -> int:
        cutoff = time.time() - self._retention
        stale = [cid for cid, c in self._cases.items() if c.updated_at < cutoff]
        for cid in stale:
            self._cases.pop(cid, None)
            self._subscribers.pop(cid, None)
        return len(stale)

    # -- SSE fan-out ----------------------------------------------------
    def subscribe(self, case_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=32)
        self._subscribers.setdefault(case_id, []).append(q)
        return q

    def unsubscribe(self, case_id: str, q: asyncio.Queue) -> None:
        subs = self._subscribers.get(case_id, [])
        if q in subs:
            subs.remove(q)
        if not subs:
            self._subscribers.pop(case_id, None)

    def _notify(self, case: Case) -> None:
        for q in self._subscribers.get(case.case_id, []):
            with contextlib.suppress(asyncio.QueueFull):
                q.put_nowait(case.model_dump(mode="json"))


class Pipeline:
    def __init__(
        self,
        settings: Settings,
        triage_client: SparkClient,
        reason_client: SparkClient,
        retriever: AttackRetriever,
        soar: SoarClient,
        allowlist: ActionAllowlist,
        audit: AuditLog,
        store: CaseStore,
    ):
        self.s = settings
        self.triage_client = triage_client
        self.reason_client = reason_client
        self.retriever = retriever
        self.soar = soar
        self.allowlist = allowlist
        self.audit = audit
        self.store = store

        self.fast_queue: asyncio.Queue[Case] = asyncio.Queue(maxsize=settings.queue_max_size)
        self.deep_queue: asyncio.Queue[Case] = asyncio.Queue(maxsize=settings.deep_queue_max_size)
        self._tasks: list[asyncio.Task] = []
        self._running = False

        # Pending human approvals: approval_id -> (case_id, action_index, expiry)
        self.pending_approvals: dict[str, dict[str, Any]] = {}

        self.metrics: dict[str, float] = {
            "alerts_received": 0, "alerts_deduped": 0, "alerts_rejected": 0,
            "cases_created": 0, "triage_completed": 0, "deep_completed": 0,
            "actions_dispatched": 0, "actions_rejected": 0, "approvals_pending": 0,
            "errors": 0, "injection_suspected": 0, "scope_violations": 0,
        }
        self._latency: dict[str, list[float]] = {"fast": [], "deep": []}

    # ==================================================================
    # Lifecycle
    # ==================================================================
    async def start(self) -> None:
        self._running = True
        for i in range(self.s.workers):
            self._tasks.append(asyncio.create_task(self._fast_worker(i), name=f"fast-{i}"))
        for i in range(self.s.deep_workers):
            self._tasks.append(asyncio.create_task(self._deep_worker(i), name=f"deep-{i}"))
        self._tasks.append(asyncio.create_task(self._janitor(), name="janitor"))
        LOG.info("Pipeline started: %d fast workers, %d deep workers",
                 self.s.workers, self.s.deep_workers)

    async def stop(self) -> None:
        self._running = False
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        LOG.info("Pipeline stopped")

    async def _janitor(self) -> None:
        while self._running:
            try:
                await asyncio.sleep(300)
                evicted = self.store.evict()
                if evicted:
                    LOG.info("Evicted %d expired cases", evicted)
                await self._expire_approvals()
                if not self.soar.available:
                    await self.soar.replay_journal()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOG.error("Janitor error: %s", exc)

    # ==================================================================
    # Ingestion
    # ==================================================================
    async def submit(self, alert: SplunkAlert, exercise_id: str | None = None) -> tuple[Case | None, str]:
        """Enqueue an alert. Returns (case, reason). case is None when rejected."""
        self.metrics["alerts_received"] += 1

        case = Case(alert=alert, fingerprint=alert.fingerprint(), exercise_id=exercise_id)

        try:
            self.fast_queue.put_nowait(case)
        except asyncio.QueueFull:
            self.metrics["alerts_rejected"] += 1
            await self.audit.write(
                AuditEvent.ALERT_REJECTED,
                detail={"reason": "fast queue full", "depth": self.fast_queue.qsize(),
                        "search_name": alert.search_name},
                severity="warning",
            )
            return None, "queue_full"

        self.metrics["cases_created"] += 1
        self.store.put(case)
        await self.audit.write(
            AuditEvent.CASE_CREATED, case_id=case.case_id,
            detail={"search_name": alert.search_name, "fingerprint": case.fingerprint,
                    "result_count": alert.result_count, "host": alert.primary_host(),
                    "exercise_id": exercise_id},
        )
        return case, "queued"

    # ==================================================================
    # Fast path
    # ==================================================================
    async def _fast_worker(self, wid: int) -> None:
        while self._running:
            try:
                case = await self.fast_queue.get()
            except asyncio.CancelledError:
                raise
            try:
                await self._run_fast(case)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOG.exception("fast worker %d: unhandled error on %s", wid, case.case_id)
                await self._fail(case, f"fast path: {exc}")
            finally:
                self.fast_queue.task_done()

    async def _run_fast(self, case: Case) -> None:
        t0 = time.perf_counter()
        case.status = CaseStatus.TRIAGING
        self.store.put(case)

        # ---- Stage A: feature extraction ------------------------------
        ta = time.perf_counter()
        try:
            data, comp = await self.triage_client.complete_json(
                build_feature_prompt(case.alert.model_dump()),
                FEATURES_SCHEMA, schema_name="alert_features",
                max_tokens=1600, temperature=0.0,
            )
            case.features = AlertFeatures.model_validate(data)
        except EmptyContentError as exc:
            await self._fail(case, str(exc))
            return
        except (LLMError, ValueError) as exc:
            await self._fail(case, f"feature extraction failed: {exc}")
            return
        case.timings_ms["extract"] = int((time.perf_counter() - ta) * 1000)

        await self.audit.write(
            AuditEvent.FEATURES_EXTRACTED, case_id=case.case_id,
            detail={"summary": case.features.summary, "platform": case.features.platform,
                    "entities": len(case.features.entities),
                    "latency_ms": case.timings_ms["extract"],
                    "tokens": comp.completion_tokens},
        )

        if case.features.injection_suspected:
            self.metrics["injection_suspected"] += 1
            await self.audit.write(
                AuditEvent.INJECTION_SUSPECTED, case_id=case.case_id, severity="warning",
                detail={"evidence": case.features.injection_evidence[:1000],
                        "search_name": case.alert.search_name},
            )
            LOG.warning("Possible prompt injection in %s: %s",
                        case.case_id, case.features.injection_evidence[:200])

        self.store.put(case)

        # ---- Stage B: ATT&CK retrieval --------------------------------
        tb = time.perf_counter()
        case.rag = await self.retriever.retrieve(
            build_rag_query(case.features), platform=case.features.platform
        )
        case.timings_ms["rag"] = int((time.perf_counter() - tb) * 1000)

        await self.audit.write(
            AuditEvent.RAG_DEGRADED if case.rag.degraded else AuditEvent.RAG_RETRIEVED,
            case_id=case.case_id,
            severity="warning" if case.rag.degraded else "info",
            detail={"techniques": case.rag.technique_ids, "hits": len(case.rag.hits),
                    "degraded_reason": case.rag.degraded_reason,
                    "latency_ms": case.timings_ms["rag"]},
        )
        self.store.put(case)

        # ---- Stage C: triage verdict ----------------------------------
        tc = time.perf_counter()
        try:
            data, comp = await self.triage_client.complete_json(
                build_triage_prompt(case.features, case.rag, case.alert.search_name),
                triage_schema(case.rag.technique_ids),
                schema_name="triage_verdict", max_tokens=1400, temperature=0.1,
            )
            case.triage = TriageVerdict.model_validate(data)
        except EmptyContentError as exc:
            await self._fail(case, str(exc))
            return
        except (LLMError, ValueError) as exc:
            await self._fail(case, f"triage failed: {exc}")
            return
        case.timings_ms["triage"] = int((time.perf_counter() - tc) * 1000)

        # Drop any technique the retrieval stage did not actually return. The
        # schema enum should make this impossible; keep the check because a
        # guided-decoding regression should not become a hallucinated citation.
        allowed = set(case.rag.technique_ids)
        dropped = [t.technique_id for t in case.triage.techniques
                   if t.technique_id not in allowed and t.technique_id != "NONE"]
        if dropped:
            LOG.warning("%s: dropping ungrounded technique citations %s", case.case_id, dropped)
            case.triage.techniques = [t for t in case.triage.techniques
                                      if t.technique_id in allowed or t.technique_id == "NONE"]

        case.status = CaseStatus.TRIAGED
        self.metrics["triage_completed"] += 1
        case.timings_ms["fast_total"] = int((time.perf_counter() - t0) * 1000)
        self._latency["fast"].append(case.timings_ms["fast_total"])
        self._latency["fast"] = self._latency["fast"][-500:]

        await self.audit.write(
            AuditEvent.TRIAGE_VERDICT, case_id=case.case_id,
            severity="warning" if case.triage.threat_score >= 0.7 else "info",
            detail={"disposition": case.triage.disposition,
                    "severity": case.triage.severity.value,
                    "threat_score": case.triage.threat_score,
                    "confidence": case.triage.confidence,
                    "techniques": [t.technique_id for t in case.triage.techniques],
                    "escalate": case.triage.escalate,
                    "latency_ms": case.timings_ms["fast_total"]},
        )
        self.store.put(case)

        # ---- Stage E1: SOAR container, immediately ---------------------
        await self._create_soar_container(case)

        # ---- escalate? -------------------------------------------------
        should_deep = (
            case.triage.escalate
            or case.triage.threat_score >= self.s.deep_threshold
            or case.triage.disposition == "malicious"
            or case.features.injection_suspected
        )
        if not should_deep:
            case.status = CaseStatus.COMPLETE
            self.store.put(case)
            return

        try:
            self.deep_queue.put_nowait(case)
            case.status = CaseStatus.DEEP_QUEUED
        except asyncio.QueueFull:
            case.errors.append("deep queue full — deep analysis skipped")
            case.status = CaseStatus.COMPLETE
            await self.audit.write(
                AuditEvent.PIPELINE_ERROR, case_id=case.case_id, severity="warning",
                detail={"reason": "deep queue full", "depth": self.deep_queue.qsize()},
            )
            if case.soar_container_id:
                with contextlib.suppress(SoarError, SoarUnavailable):
                    await self.soar.add_note(
                        case.soar_container_id, "SPARKSOC — deep analysis skipped",
                        "The deep reasoning queue was saturated when this case was triaged. "
                        "Triage verdict stands. Re-run manually if needed.",
                    )
        self.store.put(case)

    # ==================================================================
    # Deep path
    # ==================================================================
    async def _deep_worker(self, wid: int) -> None:
        while self._running:
            try:
                case = await self.deep_queue.get()
            except asyncio.CancelledError:
                raise
            try:
                await self._run_deep(case)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOG.exception("deep worker %d: unhandled error on %s", wid, case.case_id)
                case.errors.append(f"deep path: {exc}")
                case.status = CaseStatus.COMPLETE
                self.store.put(case)
            finally:
                self.deep_queue.task_done()

    async def _run_deep(self, case: Case) -> None:
        t0 = time.perf_counter()
        case.status = CaseStatus.REASONING
        self.store.put(case)

        catalogue = self.allowlist.catalogue_text(tiers=("COLLECT",))
        collect_ids = self.allowlist.collect_action_ids()
        proposable_ids = self.allowlist.all_proposable_ids()
        allowed_techs = case.rag.technique_ids if case.rag else []
        target_host = self._resolve_target(case)

        await self.audit.write(
            AuditEvent.DEEP_STARTED, case_id=case.case_id,
            detail={"target_host": target_host, "max_turns": self.s.deep_max_turns},
        )

        history = build_deep_initial_prompt(case, catalogue)
        turn_schema = deep_turn_schema(collect_ids + ["NONE"], allowed_techs)

        collect_budget = int(
            ((self.allowlist.policy.get("tiers", {}) or {}).get("COLLECT", {}) or {}).get("max_per_case", 8)
        )
        collected = 0

        for turn in range(1, self.s.deep_max_turns + 1):
            try:
                data, comp = await self.reason_client.complete_json(
                    history, turn_schema, schema_name="deep_turn",
                    max_tokens=3000, temperature=0.2,
                )
                step = DeepTurn.model_validate(data)
            except EmptyContentError as exc:
                case.errors.append(str(exc))
                LOG.error("%s: deep path aborted — %s", case.case_id, exc)
                break
            except (LLMError, ValueError) as exc:
                case.errors.append(f"deep turn {turn}: {exc}")
                break

            await self.audit.write(
                AuditEvent.DEEP_TURN, case_id=case.case_id,
                detail={"turn": turn, "next_step": step.next_step,
                        "hypotheses": len(step.hypotheses),
                        "requests": [r.action_id for r in step.evidence_requests],
                        "latency_ms": comp.latency_ms,
                        "tokens": comp.completion_tokens},
            )

            history = history + [{"role": "assistant", "content": comp.content}]

            if step.next_step == "conclude" or not step.evidence_requests:
                break
            if collected >= collect_budget:
                history.append({"role": "user", "content":
                                f"The evidence collection budget for this case "
                                f"({collect_budget} actions) is exhausted. Conclude now."})
                break

            # ---- execute evidence requests ----------------------------
            results: list[dict[str, Any]] = []
            for req in step.evidence_requests:
                if collected >= collect_budget:
                    break
                record, outcome = await self._execute_action(case, req, target_host, auto=True)
                case.actions.append(record)
                collected += 1
                results.append(outcome)
            self.store.put(case)

            history.append({"role": "user", "content": build_evidence_response(results)})

        # ---- final verdict ---------------------------------------------
        verdict_schema = deep_verdict_schema(proposable_ids + ["NONE"], allowed_techs)
        try:
            data, comp = await self.reason_client.complete_json(
                build_deep_conclude_prompt(history), verdict_schema,
                schema_name="deep_verdict", max_tokens=4000, temperature=0.2,
            )
            case.deep = DeepVerdict.model_validate(data)
        except EmptyContentError as exc:
            case.errors.append(str(exc))
        except (LLMError, ValueError) as exc:
            case.errors.append(f"deep verdict failed: {exc}")

        case.timings_ms["deep_total"] = int((time.perf_counter() - t0) * 1000)
        self._latency["deep"].append(case.timings_ms["deep_total"])
        self._latency["deep"] = self._latency["deep"][-200:]

        if case.deep:
            self.metrics["deep_completed"] += 1
            await self.audit.write(
                AuditEvent.DEEP_VERDICT, case_id=case.case_id,
                severity="warning" if case.deep.threat_score >= 0.7 else "info",
                detail={"disposition": case.deep.disposition,
                        "severity": case.deep.severity.value,
                        "threat_score": case.deep.threat_score,
                        "confidence": case.deep.confidence,
                        "kill_chain_stage": case.deep.kill_chain_stage,
                        "techniques": [t.technique_id for t in case.deep.techniques],
                        "is_likely_simulation": case.deep.is_likely_simulation,
                        "latency_ms": case.timings_ms["deep_total"]},
            )
            await self._process_recommendations(case)

        await self._finalise_soar(case)
        case.status = CaseStatus.COMPLETE
        self.store.put(case)

    # ==================================================================
    # Actions
    # ==================================================================
    def _resolve_target(self, case: Case) -> str | None:
        """Target host comes from extracted entities, never from the model's
        free-text output. This is what makes the scope check meaningful."""
        if case.features:
            for e in case.features.entities:
                if e.kind == "host":
                    return e.value
        if case.alert:
            return case.alert.primary_host()
        return None

    async def _execute_action(
        self, case: Case, proposal: ProposedAction, target_host: str | None, *, auto: bool
    ) -> tuple[ActionRecord, dict[str, Any]]:

        record = ActionRecord(
            action_id=proposal.action_id,
            tier="",
            parameters=dict(proposal.parameters),
        )

        await self.audit.write(
            AuditEvent.ACTION_PROPOSED, case_id=case.case_id,
            detail={"action_id": proposal.action_id, "parameters": proposal.parameters,
                    "justification": proposal.justification, "confidence": proposal.confidence},
        )

        taken = sum(1 for a in case.actions if a.status in
                    {"dispatched", "succeeded", "dry_run", "pending_approval"})

        v: ValidationResult = self.allowlist.validate(
            proposal.action_id, proposal.parameters,
            target_host=target_host, confidence=proposal.confidence,
            actions_taken_this_case=taken,
        )
        record.tier = v.tier

        if not v.allowed:
            record.status = "rejected"
            record.reason = v.reason
            self.metrics["actions_rejected"] += 1
            is_scope = "out of scope" in v.reason
            if is_scope:
                self.metrics["scope_violations"] += 1
            await self.audit.write(
                AuditEvent.SCOPE_VIOLATION if is_scope else AuditEvent.ACTION_REJECTED,
                case_id=case.case_id, severity="warning",
                detail={"action_id": proposal.action_id, "reason": v.reason,
                        "parameters": proposal.parameters, "target_host": target_host},
            )
            return record, {"action_id": proposal.action_id, "status": "rejected",
                            "reason": v.reason, "output": ""}

        record.parameters = v.parameters

        # ---- dry run ---------------------------------------------------
        if self.allowlist.dry_run:
            record.status = "dry_run"
            record.reason = "dry_run mode: recorded, not dispatched"
            await self.audit.write(
                AuditEvent.ACTION_DRY_RUN, case_id=case.case_id,
                detail={"action_id": proposal.action_id, "soar_action": v.soar_action,
                        "asset": v.soar_asset, "parameters": v.parameters},
            )
            return record, {"action_id": proposal.action_id, "status": "dry_run",
                            "reason": "dry-run mode — no evidence was actually collected",
                            "output": ""}

        # ---- approval gate ---------------------------------------------
        if v.requires_approval:
            approval_id = f"APR-{case.case_id[-8:]}-{len(case.actions):02d}"
            record.status = "pending_approval"
            record.approval_id = approval_id
            record.reason = v.approval_prompt

            timeout_min = float(
                ((self.allowlist.policy.get("tiers", {}) or {}).get(v.tier, {}) or {})
                .get("approval_timeout_minutes", 60)
            )
            self.pending_approvals[approval_id] = {
                "case_id": case.case_id,
                "action_index": len(case.actions),
                "expires_at": time.time() + timeout_min * 60,
                "prompt": v.approval_prompt,
                "warning": v.approval_warning,
                "roles": v.approval_roles,
                "soar_action": v.soar_action,
                "soar_asset": v.soar_asset,
                "parameters": v.parameters,
            }
            self.metrics["approvals_pending"] = len(self.pending_approvals)

            await self.audit.write(
                AuditEvent.APPROVAL_REQUESTED, case_id=case.case_id, severity="warning",
                detail={"approval_id": approval_id, "action_id": proposal.action_id,
                        "prompt": v.approval_prompt, "warning": v.approval_warning,
                        "roles": v.approval_roles, "expires_in_minutes": timeout_min},
            )

            if case.soar_container_id:
                with contextlib.suppress(SoarError, SoarUnavailable):
                    await self.soar.add_note(
                        case.soar_container_id,
                        f"APPROVAL REQUIRED — {proposal.action_id}",
                        f"**{v.approval_prompt}**\n\n"
                        f"> {v.approval_warning}\n\n"
                        f"- Approval id: `{approval_id}`\n"
                        f"- Parameters: `{json.dumps(v.parameters)}`\n"
                        f"- Model justification: {proposal.justification}\n"
                        f"- Model confidence: {proposal.confidence:.2f}\n"
                        f"- Authorised roles: {', '.join(v.approval_roles) or 'any'}\n"
                        f"- Expires in {timeout_min:.0f} minutes\n\n"
                        f"Approve: `POST /v1/approval/{approval_id}` "
                        f"body `{{\"decision\":\"approve\",\"approver\":\"<you>\"}}`",
                        note_type="task",
                    )

            return record, {"action_id": proposal.action_id, "status": "pending_approval",
                            "reason": "awaiting human approval — not executed",
                            "output": ""}

        # ---- dispatch ---------------------------------------------------
        return await self._dispatch(case, record, v)

    async def _dispatch(self, case: Case, record: ActionRecord,
                        v: ValidationResult) -> tuple[ActionRecord, dict[str, Any]]:
        if not case.soar_container_id:
            record.status = "failed"
            record.reason = "no SOAR container — cannot dispatch"
            return record, {"action_id": record.action_id, "status": "failed",
                            "reason": record.reason, "output": ""}
        try:
            run_id = await self.soar.run_action(
                case.soar_container_id, v.soar_action, v.soar_asset, v.parameters,
                name=f"SPARKSOC {record.action_id}",
            )
            record.soar_action_run_id = str(run_id)
            record.status = "dispatched"
            self.metrics["actions_dispatched"] += 1

            await self.audit.write(
                AuditEvent.ACTION_DISPATCHED, case_id=case.case_id,
                detail={"action_id": record.action_id, "soar_action": v.soar_action,
                        "asset": v.soar_asset, "parameters": v.parameters,
                        "action_run_id": run_id},
            )

            outcome = await self.soar.wait_for_action(run_id)
            record.status = "succeeded" if outcome["status"] == "succeeded" else "failed"
            record.reason = outcome.get("reason", "")
            record.result_summary = str(outcome.get("output", ""))[:4000]
            record.completed_at = time.time()

            await self.audit.write(
                AuditEvent.ACTION_RESULT, case_id=case.case_id,
                detail={"action_id": record.action_id, "status": record.status,
                        "action_run_id": run_id, "reason": record.reason,
                        "output_chars": len(str(outcome.get("output", "")))},
            )
            outcome["action_id"] = record.action_id
            outcome["parameters"] = v.parameters
            return record, outcome

        except (SoarError, SoarUnavailable) as exc:
            record.status = "failed"
            record.reason = str(exc)
            record.completed_at = time.time()
            await self.audit.write(
                AuditEvent.ACTION_RESULT, case_id=case.case_id, severity="warning",
                detail={"action_id": record.action_id, "status": "failed", "reason": str(exc)},
            )
            return record, {"action_id": record.action_id, "status": "failed",
                            "reason": str(exc), "output": ""}

    async def _process_recommendations(self, case: Case) -> None:
        """Run the deep verdict's recommended actions through the tier gate."""
        if not case.deep:
            return
        target = self._resolve_target(case)
        for rec in case.deep.recommended_actions:
            if rec.action_id == "NONE":
                continue
            record, _ = await self._execute_action(case, rec, target, auto=False)
            case.actions.append(record)
        self.store.put(case)

    # ==================================================================
    # Approvals
    # ==================================================================
    async def resolve_approval(self, approval_id: str, decision: str,
                               approver: str, note: str = "") -> dict[str, Any]:
        pending = self.pending_approvals.get(approval_id)
        if not pending:
            return {"ok": False, "reason": "unknown or already-resolved approval id"}
        if time.time() > pending["expires_at"]:
            self.pending_approvals.pop(approval_id, None)
            return {"ok": False, "reason": "approval expired"}

        case = self.store.get(pending["case_id"])
        if not case:
            self.pending_approvals.pop(approval_id, None)
            return {"ok": False, "reason": "case no longer in store"}

        idx = pending["action_index"]
        if idx >= len(case.actions):
            return {"ok": False, "reason": "action record missing"}
        record = case.actions[idx]

        if decision != "approve":
            record.status = "rejected"
            record.reason = f"denied by {approver}: {note}"
            self.pending_approvals.pop(approval_id, None)
            self.metrics["approvals_pending"] = len(self.pending_approvals)
            await self.audit.write(
                AuditEvent.APPROVAL_DENIED, case_id=case.case_id, actor=approver,
                detail={"approval_id": approval_id, "action_id": record.action_id, "note": note},
            )
            self.store.put(case)
            return {"ok": True, "status": "denied"}

        await self.audit.write(
            AuditEvent.APPROVAL_GRANTED, case_id=case.case_id, actor=approver, severity="warning",
            detail={"approval_id": approval_id, "action_id": record.action_id,
                    "parameters": pending["parameters"], "note": note},
        )
        record.status = "approved"

        v = ValidationResult(
            allowed=True, tier=record.tier,
            soar_action=pending["soar_action"], soar_asset=pending["soar_asset"],
            parameters=pending["parameters"],
        )
        record, outcome = await self._dispatch(case, record, v)
        case.actions[idx] = record
        self.pending_approvals.pop(approval_id, None)
        self.metrics["approvals_pending"] = len(self.pending_approvals)
        self.store.put(case)
        return {"ok": True, "status": record.status, "result": outcome.get("reason", "")}

    async def _expire_approvals(self) -> None:
        now = time.time()
        for aid in [a for a, p in self.pending_approvals.items() if now > p["expires_at"]]:
            pending = self.pending_approvals.pop(aid)
            case = self.store.get(pending["case_id"])
            if case and pending["action_index"] < len(case.actions):
                case.actions[pending["action_index"]].status = "expired"
                case.actions[pending["action_index"]].reason = "approval window elapsed"
                self.store.put(case)
            await self.audit.write(
                AuditEvent.APPROVAL_EXPIRED, case_id=pending["case_id"],
                detail={"approval_id": aid}, severity="warning",
            )
        self.metrics["approvals_pending"] = len(self.pending_approvals)

    # ==================================================================
    # SOAR
    # ==================================================================
    def _soar_severity(self, sev: Severity) -> str:
        return self.s.severity_map().get(sev.value, "medium")

    async def _create_soar_container(self, case: Case) -> None:
        if not case.triage or not case.alert:
            return
        try:
            host = case.alert.primary_host() or "unknown-host"
            name = (f"[{case.triage.disposition.upper()}] {case.alert.search_name} — {host}")
            techs = ", ".join(t.technique_id for t in case.triage.techniques) or "none identified"

            description = (
                f"SPARKSOC automated triage\n\n"
                f"Case: {case.case_id}\n"
                f"Threat score: {case.triage.threat_score:.2f} "
                f"(confidence {case.triage.confidence:.2f})\n"
                f"ATT&CK: {techs}\n\n"
                f"{case.features.summary if case.features else ''}\n\n"
                f"{case.triage.reasoning}"
            )

            tags = ["sparksoc", f"disposition:{case.triage.disposition}"]
            tags += [t.technique_id.lower() for t in case.triage.techniques]
            if case.exercise_id:
                tags.append(f"exercise:{case.exercise_id}")
            if case.rag and case.rag.degraded:
                tags.append("rag-degraded")
            if case.features and case.features.injection_suspected:
                tags.append("injection-suspected")

            cid = await self.soar.create_container(
                name=name,
                description=description,
                severity=self._soar_severity(case.triage.severity),
                source_data_identifier=f"sparksoc:{case.fingerprint}",
                tags=tags,
                custom_fields={
                    "sparksoc_case_id": case.case_id,
                    "sparksoc_threat_score": case.triage.threat_score,
                    "sparksoc_stage": "triage",
                },
            )
            case.soar_container_id = cid

            await self.audit.write(
                AuditEvent.SOAR_CONTAINER, case_id=case.case_id,
                detail={"container_id": cid, "name": name, "tags": tags},
            )
            await self._add_artifacts(case, cid)

        except (SoarError, SoarUnavailable) as exc:
            case.errors.append(f"SOAR container creation failed: {exc}")
            LOG.error("%s: SOAR container creation failed: %s", case.case_id, exc)
        self.store.put(case)

    async def _add_artifacts(self, case: Case, container_id: int) -> None:
        if not case.features:
            return
        cef_key = {
            "host": "destinationHostName", "ip": "destinationAddress",
            "user": "destinationUserName", "process": "destinationProcessName",
            "file": "fileName", "hash": "fileHash", "domain": "destinationDnsDomain",
            "registry_key": "registryKey", "service": "serviceName",
            "scheduled_task": "taskName", "account": "destinationUserName", "port": "destinationPort",
        }
        artifacts = []
        seen: set[tuple[str, str]] = set()
        for e in case.features.entities[:30]:
            key = (e.kind, e.value)
            if key in seen:
                continue
            seen.add(key)
            artifacts.append({
                "name": f"{e.kind}: {e.value[:80]}",
                "cef": {cef_key.get(e.kind, "message"): e.value, "sparksocEntityRole": e.role},
                "label": "observable",
                "artifact_type": "host" if e.kind in {"host", "ip"} else "generic",
                "severity": self._soar_severity(case.triage.severity) if case.triage else "medium",
                "source_data_identifier": f"sparksoc:{case.fingerprint}:{e.kind}:{e.value}"[:250],
            })
        with contextlib.suppress(SoarError, SoarUnavailable):
            await self.soar.add_artifacts_bulk(container_id, artifacts)

    async def _finalise_soar(self, case: Case) -> None:
        if not case.soar_container_id:
            return
        try:
            if case.deep:
                techs = "\n".join(
                    f"- **{t.technique_id}** (confidence {t.confidence:.2f}) — {t.rationale}"
                    for t in case.deep.techniques if t.technique_id != "NONE"
                ) or "- none identified"

                hyps = "\n".join(
                    f"- [{h.status}] {h.statement} (confidence {h.confidence:.2f})"
                    for h in case.deep.hypotheses
                ) or "- none recorded"

                acts = "\n".join(
                    f"- `{a.action_id}` [{a.tier}] — **{a.status}**"
                    + (f" ({a.reason})" if a.reason else "")
                    for a in case.actions
                ) or "- none"

                sim = ""
                if case.deep.is_likely_simulation:
                    ind = "\n".join(f"  - {i}" for i in case.deep.simulation_indicators)
                    sim = (f"\n### Simulation assessment\n"
                           f"This activity is assessed as **likely authorised purple-team "
                           f"simulation**. Severity has not been reduced on that basis.\n{ind}\n")

                content = (
                    f"## Deep analysis verdict\n\n"
                    f"**{case.deep.disposition.upper()}** — severity {case.deep.severity.value}, "
                    f"threat score {case.deep.threat_score:.2f}, "
                    f"confidence {case.deep.confidence:.2f}\n\n"
                    f"Kill chain stage: `{case.deep.kill_chain_stage}`\n\n"
                    f"### Attack narrative\n{case.deep.attack_narrative}\n\n"
                    f"### ATT&CK techniques\n{techs}\n\n"
                    f"### Hypotheses\n{hyps}\n{sim}\n"
                    f"### Actions\n{acts}\n\n"
                    f"---\n"
                    f"Case `{case.case_id}` · deep analysis "
                    f"{case.timings_ms.get('deep_total', 0) / 1000:.1f}s · "
                    f"triage {case.timings_ms.get('fast_total', 0) / 1000:.1f}s"
                )
                await self.soar.add_note(case.soar_container_id,
                                         "SPARKSOC — deep analysis complete", content)

                await self.soar.update_container(
                    case.soar_container_id,
                    severity=self._soar_severity(case.deep.severity),
                    custom_fields={
                        "sparksoc_case_id": case.case_id,
                        "sparksoc_threat_score": case.deep.threat_score,
                        "sparksoc_stage": "deep",
                        "sparksoc_is_simulation": case.deep.is_likely_simulation,
                    },
                )
            elif case.errors:
                await self.soar.add_note(
                    case.soar_container_id, "SPARKSOC — deep analysis unavailable",
                    "Deep reasoning did not complete. Triage verdict stands.\n\n"
                    + "\n".join(f"- {e}" for e in case.errors),
                )
        except (SoarError, SoarUnavailable) as exc:
            LOG.error("%s: SOAR finalisation failed: %s", case.case_id, exc)
            case.errors.append(f"SOAR finalisation failed: {exc}")

    # ==================================================================
    async def _fail(self, case: Case, reason: str) -> None:
        case.status = CaseStatus.FAILED
        case.errors.append(reason)
        self.metrics["errors"] += 1
        LOG.error("%s FAILED: %s", case.case_id, reason)
        await self.audit.write(
            AuditEvent.PIPELINE_ERROR, case_id=case.case_id, severity="error",
            detail={"reason": reason},
        )
        self.store.put(case)

    def latency_percentiles(self) -> dict[str, float]:
        out: dict[str, float] = {}
        for name, vals in self._latency.items():
            if not vals:
                continue
            s = sorted(vals)
            out[f"{name}_p50_ms"] = s[len(s) // 2]
            out[f"{name}_p95_ms"] = s[min(len(s) - 1, int(len(s) * 0.95))]
            out[f"{name}_max_ms"] = s[-1]
        return out

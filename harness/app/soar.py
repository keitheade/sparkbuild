"""Splunk SOAR REST client.

Endpoints used (SOAR 6.x):
    POST /rest/container              create a case container
    POST /rest/container/{id}         update severity / status / tags
    POST /rest/artifact               attach observables
    POST /rest/note                   attach analyst-readable narrative
    POST /rest/action_run             dispatch an app action against an asset
    GET  /rest/action_run/{id}        poll dispatch status
    GET  /rest/app_run?_filter_...    retrieve per-asset action output

Auth is the `ph-auth-token` header. TLS verification uses a pinned CA bundle by
default; set SOAR_CA_BUNDLE=false only in a lab, and know that you are doing it.

Availability: when SOAR is unreachable the client persists the intended call to
a retry journal on disk and returns a degraded result. Verdicts continue to be
produced and audited. A SOAR outage must not take the analysis pipeline down.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from pathlib import Path
from typing import Any

import httpx

LOG = logging.getLogger("sparksoc.soar")

SEVERITY_VALUES = {"low", "medium", "high"}


class SoarError(RuntimeError):
    pass


class SoarUnavailable(SoarError):
    """Transport-level failure. The caller should degrade, not fail the case."""


class SoarClient:
    def __init__(
        self,
        base_url: str,
        auth_token: str,
        *,
        verify: str | bool = True,
        timeout: float = 60.0,
        label: str = "events",
        retry_journal: Path = Path("/var/lib/sparksoc/state/soar_retry.jsonl"),
        poll_interval: float = 3.0,
        poll_timeout: float = 300.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.label = label
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout
        self.retry_journal = retry_journal
        self.retry_journal.parent.mkdir(parents=True, exist_ok=True)

        # "false"/"true" strings arrive from env; normalise.
        if isinstance(verify, str):
            if verify.lower() in {"false", "0", "no"}:
                LOG.warning("SOAR TLS verification is DISABLED. Do not run this way in production.")
                verify = False
            elif verify.lower() in {"true", "1", "yes"}:
                verify = True

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            verify=verify,
            timeout=httpx.Timeout(timeout, connect=15.0),
            headers={"ph-auth-token": auth_token, "Content-Type": "application/json"},
        )
        self._available = True

    async def aclose(self) -> None:
        await self._client.aclose()

    @property
    def available(self) -> bool:
        return self._available

    # ------------------------------------------------------------------
    async def health(self) -> bool:
        try:
            r = await self._client.get("/rest/version", timeout=10.0)
            self._available = r.status_code == 200
            return self._available
        except Exception as exc:
            LOG.warning("SOAR health check failed: %s", exc)
            self._available = False
            return False

    def _journal(self, kind: str, payload: dict[str, Any]) -> None:
        record = {"ts": time.time(), "kind": kind, "payload": payload}
        try:
            with self.retry_journal.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, default=str) + "\n")
        except Exception as exc:
            LOG.error("Could not write SOAR retry journal: %s", exc)

    async def _post(self, path: str, payload: dict[str, Any], *, journal_kind: str | None = None) -> dict[str, Any]:
        try:
            r = await self._client.post(path, json=payload)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            self._available = False
            if journal_kind:
                self._journal(journal_kind, {"path": path, "body": payload})
            raise SoarUnavailable(f"POST {path}: {exc}") from exc

        self._available = True
        if r.status_code >= 400:
            raise SoarError(f"POST {path} -> {r.status_code}: {r.text[:400]}")
        try:
            return r.json()
        except json.JSONDecodeError:
            return {"raw": r.text}

    async def _get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            r = await self._client.get(path, params=params)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            self._available = False
            raise SoarUnavailable(f"GET {path}: {exc}") from exc
        self._available = True
        if r.status_code >= 400:
            raise SoarError(f"GET {path} -> {r.status_code}: {r.text[:400]}")
        return r.json()

    # ------------------------------------------------------------------
    # Containers
    # ------------------------------------------------------------------
    async def create_container(
        self,
        name: str,
        description: str,
        severity: str = "medium",
        *,
        source_data_identifier: str,
        tags: list[str] | None = None,
        custom_fields: dict[str, Any] | None = None,
        sensitivity: str = "amber",
        status: str = "new",
    ) -> int:
        if severity not in SEVERITY_VALUES:
            severity = "medium"

        payload = {
            "name": name[:250],
            "description": description[:5000],
            "label": self.label,
            "severity": severity,
            "sensitivity": sensitivity,
            "status": status,
            # SOAR dedupes on this. Reusing the case fingerprint means a
            # re-fired Splunk correlation updates the existing container
            # instead of spawning a duplicate.
            "source_data_identifier": source_data_identifier,
            "tags": tags or [],
            "run_automation": False,   # we orchestrate; do not double-fire playbooks
        }
        if custom_fields:
            payload["custom_fields"] = custom_fields

        resp = await self._post("/rest/container", payload, journal_kind="container")

        cid = resp.get("id")
        if cid is None and resp.get("existing_container_id"):
            cid = resp["existing_container_id"]
            LOG.info("SOAR container already existed for sdi=%s -> %s", source_data_identifier, cid)
        if cid is None:
            raise SoarError(f"container creation returned no id: {resp}")
        return int(cid)

    async def update_container(self, container_id: int, **fields: Any) -> None:
        await self._post(f"/rest/container/{container_id}", fields, journal_kind="container_update")

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------
    async def add_artifact(
        self,
        container_id: int,
        name: str,
        cef: dict[str, Any],
        *,
        label: str = "observable",
        severity: str = "medium",
        artifact_type: str = "network",
        source_data_identifier: str | None = None,
    ) -> int | None:
        payload = {
            "container_id": container_id,
            "name": name[:250],
            "label": label,
            "severity": severity if severity in SEVERITY_VALUES else "medium",
            "type": artifact_type,
            "cef": {k: v for k, v in cef.items() if v not in (None, "", [])},
            "run_automation": False,
        }
        if source_data_identifier:
            payload["source_data_identifier"] = source_data_identifier
        try:
            resp = await self._post("/rest/artifact", payload, journal_kind="artifact")
            return resp.get("id")
        except SoarError as exc:
            # A duplicate artifact is not worth failing a case over.
            LOG.warning("artifact creation failed (continuing): %s", exc)
            return None

    async def add_artifacts_bulk(self, container_id: int,
                                 artifacts: list[dict[str, Any]]) -> int:
        created = 0
        for a in artifacts:
            aid = await self.add_artifact(container_id, **a)
            created += 1 if aid else 0
        return created

    # ------------------------------------------------------------------
    # Notes
    # ------------------------------------------------------------------
    async def add_note(self, container_id: int, title: str, content: str,
                       note_type: str = "general") -> int | None:
        payload = {
            "container_id": container_id,
            "title": title[:250],
            "content": content[:100_000],
            "note_type": note_type,
            "note_format": "markdown",
        }
        try:
            resp = await self._post("/rest/note", payload, journal_kind="note")
            return resp.get("id")
        except SoarError as exc:
            LOG.warning("note creation failed (continuing): %s", exc)
            return None

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    async def run_action(
        self,
        container_id: int,
        action: str,
        asset: str,
        parameters: dict[str, Any],
        *,
        name: str = "SPARKSOC automated collection",
        app_id: int | None = None,
    ) -> int:
        target: dict[str, Any] = {
            "assets": [asset],
            "parameters": [parameters],
        }
        if app_id is not None:
            target["app_id"] = app_id

        payload = {
            "action": action,
            "container_id": container_id,
            "name": name[:100],
            "targets": [target],
            "type": "investigate",
        }
        resp = await self._post("/rest/action_run", payload, journal_kind="action_run")
        run_id = resp.get("action_run_id") or resp.get("id")
        if run_id is None:
            raise SoarError(f"action_run returned no id: {resp}")
        return int(run_id)

    async def wait_for_action(self, action_run_id: int,
                              timeout: float | None = None) -> dict[str, Any]:
        """Poll an action run to completion and return its normalised result."""
        deadline = time.monotonic() + (timeout or self.poll_timeout)
        status = "unknown"
        message = ""

        while time.monotonic() < deadline:
            try:
                doc = await self._get(f"/rest/action_run/{action_run_id}")
            except SoarUnavailable as exc:
                return {"status": "failed", "reason": f"soar unavailable during poll: {exc}", "output": ""}

            status = str(doc.get("status", "")).lower()
            message = doc.get("message", "") or ""

            if status in {"success", "successful", "failed", "cancelled"}:
                break
            await asyncio.sleep(self.poll_interval)
        else:
            return {"status": "failed",
                    "reason": f"action_run {action_run_id} did not complete within "
                              f"{timeout or self.poll_timeout:.0f}s",
                    "output": ""}

        output = await self._collect_app_run_output(action_run_id)
        normalised = "succeeded" if status in {"success", "successful"} else "failed"
        return {
            "status": normalised,
            "reason": message,
            "output": output,
            "action_run_id": action_run_id,
        }

    async def _collect_app_run_output(self, action_run_id: int) -> str:
        """Flatten app_run result data into readable text for the reasoning model."""
        try:
            doc = await self._get("/rest/app_run", params={
                "_filter_action_run": action_run_id,
                "page_size": 20,
            })
        except (SoarError, SoarUnavailable) as exc:
            return f"(could not retrieve action output: {exc})"

        chunks: list[str] = []
        for run in doc.get("data", []):
            result_data = run.get("result_data") or []
            summary = run.get("result_summary") or {}
            if summary:
                chunks.append(f"summary: {json.dumps(summary, default=str)}")
            for rd in result_data:
                if rd.get("message"):
                    chunks.append(f"message: {rd['message']}")
                data = rd.get("data") or []
                if data:
                    chunks.append(json.dumps(data, indent=1, default=str)[:20000])
                params = rd.get("parameter") or {}
                if params:
                    chunks.append(f"parameter: {json.dumps(params, default=str)}")
        return "\n".join(chunks) if chunks else "(action produced no result data)"

    # ------------------------------------------------------------------
    async def replay_journal(self) -> int:
        """Re-send journalled calls after a SOAR outage. Returns count replayed."""
        if not self.retry_journal.exists():
            return 0
        if not await self.health():
            return 0

        lines = self.retry_journal.read_text(encoding="utf-8").splitlines()
        if not lines:
            return 0

        remaining: list[str] = []
        replayed = 0
        for line in lines:
            try:
                rec = json.loads(line)
                await self._post(rec["payload"]["path"], rec["payload"]["body"])
                replayed += 1
            except SoarUnavailable:
                remaining.append(line)   # still down; keep for next time
            except Exception as exc:
                LOG.warning("Dropping unreplayable journal entry: %s", exc)

        self.retry_journal.write_text("\n".join(remaining) + ("\n" if remaining else ""), encoding="utf-8")
        if replayed:
            LOG.info("Replayed %d journalled SOAR calls (%d remaining)", replayed, len(remaining))
        return replayed

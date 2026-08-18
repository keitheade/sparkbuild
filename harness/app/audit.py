"""Tamper-evident audit log.

Every decision the pipeline makes is appended as a JSON line whose `prev_hash`
field chains to the previous entry. Altering or removing any historical record
breaks the chain from that point forward, and `verify_chain()` reports exactly
where.

This is tamper-EVIDENT, not tamper-PROOF: someone with write access can rewrite
the whole file and recompute the chain. Making it tamper-proof means shipping
each entry off-host as it is written — in this enclave, forwarding to Splunk via
a monitored input, which docs/05-SPLUNK-INTEGRATION.md covers.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import time
from enum import Enum
from pathlib import Path
from typing import Any

LOG = logging.getLogger("sparksoc.audit")

GENESIS = "0" * 64


class AuditEvent(str, Enum):
    ALERT_RECEIVED = "alert.received"
    ALERT_REJECTED = "alert.rejected"
    ALERT_DEDUPED = "alert.deduped"
    CASE_CREATED = "case.created"
    FEATURES_EXTRACTED = "features.extracted"
    RAG_RETRIEVED = "rag.retrieved"
    RAG_DEGRADED = "rag.degraded"
    TRIAGE_VERDICT = "triage.verdict"
    DEEP_STARTED = "deep.started"
    DEEP_TURN = "deep.turn"
    DEEP_VERDICT = "deep.verdict"
    ACTION_PROPOSED = "action.proposed"
    ACTION_REJECTED = "action.rejected"
    ACTION_DRY_RUN = "action.dry_run"
    ACTION_DISPATCHED = "action.dispatched"
    ACTION_RESULT = "action.result"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    APPROVAL_DENIED = "approval.denied"
    APPROVAL_EXPIRED = "approval.expired"
    SOAR_CONTAINER = "soar.container"
    INJECTION_SUSPECTED = "security.injection_suspected"
    SCOPE_VIOLATION = "security.scope_violation"
    PIPELINE_ERROR = "pipeline.error"
    EXERCISE_STARTED = "exercise.started"
    EXERCISE_STOPPED = "exercise.stopped"
    SERVICE_START = "service.start"
    SERVICE_STOP = "service.stop"


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = asyncio.Lock()
        self._last_hash = self._read_last_hash()
        self._seq = self._read_last_seq()

    # ------------------------------------------------------------------
    def _read_last_hash(self) -> str:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return GENESIS
        try:
            last = _read_last_line(self.path)
            return json.loads(last).get("entry_hash", GENESIS) if last else GENESIS
        except Exception as exc:
            LOG.error("Could not read last audit hash (%s); starting a new chain segment", exc)
            return GENESIS

    def _read_last_seq(self) -> int:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0
        try:
            last = _read_last_line(self.path)
            return int(json.loads(last).get("seq", 0)) if last else 0
        except Exception:
            return 0

    @staticmethod
    def _hash_entry(entry: dict[str, Any]) -> str:
        # sort_keys makes the hash reproducible for verification.
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()

    # ------------------------------------------------------------------
    async def write(
        self,
        event: AuditEvent,
        *,
        case_id: str | None = None,
        actor: str = "sparksoc",
        detail: dict[str, Any] | None = None,
        severity: str = "info",
    ) -> str:
        async with self._lock:
            self._seq += 1
            entry: dict[str, Any] = {
                "seq": self._seq,
                "ts": time.time(),
                "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "event": event.value,
                "severity": severity,
                "case_id": case_id,
                "actor": actor,
                "detail": detail or {},
                "prev_hash": self._last_hash,
            }
            entry["entry_hash"] = self._hash_entry(entry)

            line = json.dumps(entry, default=str, ensure_ascii=False)
            try:
                # Append + fsync: an audit record that is lost in the page cache
                # during a crash is not an audit record.
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
                    fh.flush()
                    os.fsync(fh.fileno())
            except Exception as exc:
                LOG.error("AUDIT WRITE FAILED (%s): %s", exc, line[:400])
                raise

            self._last_hash = entry["entry_hash"]
            return entry["entry_hash"]

    # ------------------------------------------------------------------
    def verify_chain(self) -> tuple[bool, str]:
        """Recompute the chain. Returns (ok, message)."""
        if not self.path.exists():
            return True, "audit log does not exist yet"

        prev = GENESIS
        count = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    return False, f"line {lineno}: not valid JSON"

                if entry.get("prev_hash") != prev:
                    return False, (
                        f"line {lineno} (seq {entry.get('seq')}): prev_hash mismatch — "
                        f"expected {prev[:16]}..., found {str(entry.get('prev_hash'))[:16]}... "
                        f"Records at or before this point were altered or removed."
                    )

                claimed = entry.pop("entry_hash", "")
                recomputed = self._hash_entry(entry)
                if claimed != recomputed:
                    return False, (
                        f"line {lineno} (seq {entry.get('seq')}): entry_hash mismatch — "
                        f"this record's contents were modified after it was written."
                    )

                prev = claimed
                count += 1

        return True, f"chain intact across {count} entries"

    def tail(self, n: int = 100, case_id: str | None = None) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        out: list[dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if case_id and entry.get("case_id") != case_id:
                    continue
                out.append(entry)
        return out[-n:]


def _read_last_line(path: Path, chunk: int = 8192) -> str:
    """Read the final non-empty line without loading the whole file."""
    with path.open("rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        buf = b""
        pos = size
        while pos > 0:
            step = min(chunk, pos)
            pos -= step
            fh.seek(pos)
            buf = fh.read(step) + buf
            lines = [ln for ln in buf.split(b"\n") if ln.strip()]
            if len(lines) >= 1 and (pos == 0 or len(lines) >= 2):
                return lines[-1].decode("utf-8", errors="replace")
        return buf.decode("utf-8", errors="replace").strip()

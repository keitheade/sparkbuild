"""Pydantic models and JSON schemas for the SPARKSOC pipeline.

Every model call in this pipeline is constrained by one of the schemas defined
here. That is a security control, not a convenience: a model whose output is
restricted to an enum of action ids cannot be talked into inventing an action,
no matter what a log field says.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Inbound
# ---------------------------------------------------------------------------

class SplunkResult(BaseModel):
    """One row from a Splunk search result set. Schema is deliberately open —
    saved searches emit arbitrary fields."""
    model_config = {"extra": "allow"}

    _raw: str | None = None
    _time: str | None = None
    host: str | None = None
    source: str | None = None
    sourcetype: str | None = None
    index: str | None = None


class SplunkAlert(BaseModel):
    """Payload delivered by TA-soc-harness (or the stock webhook fallback)."""
    model_config = {"extra": "allow"}

    search_name: str = Field(..., description="Saved search / correlation rule name")
    sid: str | None = None
    owner: str | None = None
    app: str | None = None
    server_host: str | None = None
    server_uri: str | None = None
    results_link: str | None = None
    result_count: int = 0
    trigger_time: int | None = None
    # Full result set from the custom alert action; stock webhooks send one row.
    results: list[dict[str, Any]] = Field(default_factory=list)
    # Optional metadata the alert action can set
    severity: str | None = None
    urgency: str | None = None
    labels: list[str] = Field(default_factory=list)

    def fingerprint(self) -> str:
        """Stable identity for dedupe.

        Keyed on rule + the entity tuple of the first result, NOT on the whole
        payload: Splunk re-fires the same correlation for the same host every
        interval and we do not want a new case each time.
        """
        first = self.results[0] if self.results else {}
        parts = [
            self.search_name,
            str(first.get("host") or first.get("dest") or first.get("ComputerName") or ""),
            str(first.get("user") or first.get("User") or first.get("src_user") or ""),
            str(first.get("process_name") or first.get("Image") or ""),
            str(first.get("signature") or first.get("EventCode") or ""),
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]

    def primary_host(self) -> str | None:
        for r in self.results:
            for key in ("host", "dest", "ComputerName", "dest_nt_host", "Computer"):
                v = r.get(key)
                if v:
                    return str(v)
        return None


# ---------------------------------------------------------------------------
# Stage A — feature extraction (Spark 1)
# ---------------------------------------------------------------------------

class ExtractedEntity(BaseModel):
    kind: Literal["host", "user", "process", "file", "ip", "domain", "hash",
                  "registry_key", "service", "scheduled_task", "account", "port"]
    value: str
    role: Literal["source", "target", "actor", "artifact", "unknown"] = "unknown"


class AlertFeatures(BaseModel):
    """Normalised, entity-extracted view of a raw alert."""
    summary: str = Field(..., description="One-sentence factual restatement, no interpretation")
    entities: list[ExtractedEntity] = Field(default_factory=list)
    observed_behaviours: list[str] = Field(
        default_factory=list,
        description="Atomic behavioural statements, e.g. 'powershell.exe launched by wmiprvse.exe'",
    )
    platform: Literal["windows", "linux", "network", "cloud", "unknown"] = "unknown"
    data_sources: list[str] = Field(default_factory=list)
    suspicious_indicators: list[str] = Field(default_factory=list)
    benign_explanations: list[str] = Field(
        default_factory=list,
        description="Plausible non-malicious explanations. Required — forces the model to consider them.",
    )
    # Set by the model when alert content contains text that reads as an
    # instruction rather than data. See prompts.py.
    injection_suspected: bool = False
    injection_evidence: str = ""


FEATURES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "maxLength": 500},
        "entities": {
            "type": "array", "maxItems": 40,
            "items": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": ["host", "user", "process", "file", "ip", "domain",
                                                         "hash", "registry_key", "service", "scheduled_task",
                                                         "account", "port"]},
                    "value": {"type": "string", "maxLength": 300},
                    "role": {"type": "string", "enum": ["source", "target", "actor", "artifact", "unknown"]},
                },
                "required": ["kind", "value", "role"], "additionalProperties": False,
            },
        },
        "observed_behaviours": {"type": "array", "maxItems": 20, "items": {"type": "string", "maxLength": 300}},
        "platform": {"type": "string", "enum": ["windows", "linux", "network", "cloud", "unknown"]},
        "data_sources": {"type": "array", "maxItems": 12, "items": {"type": "string", "maxLength": 100}},
        "suspicious_indicators": {"type": "array", "maxItems": 20, "items": {"type": "string", "maxLength": 300}},
        "benign_explanations": {"type": "array", "maxItems": 10, "items": {"type": "string", "maxLength": 300}},
        "injection_suspected": {"type": "boolean"},
        "injection_evidence": {"type": "string", "maxLength": 500},
    },
    "required": ["summary", "entities", "observed_behaviours", "platform", "data_sources",
                 "suspicious_indicators", "benign_explanations", "injection_suspected", "injection_evidence"],
    "additionalProperties": False,
}


# ---------------------------------------------------------------------------
# Stage B — ATT&CK retrieval
# ---------------------------------------------------------------------------

class AttackHit(BaseModel):
    technique_id: str
    technique_name: str
    doc_type: str
    score: float
    tactics: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    text: str = ""
    url: str = ""


class RagResult(BaseModel):
    hits: list[AttackHit] = Field(default_factory=list)
    technique_ids: list[str] = Field(default_factory=list)
    degraded: bool = False
    degraded_reason: str = ""
    latency_ms: int = 0


# ---------------------------------------------------------------------------
# Stage C — triage verdict (Spark 1)
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TechniqueAssessment(BaseModel):
    technique_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str


class TriageVerdict(BaseModel):
    disposition: Literal["benign", "suspicious", "malicious", "insufficient_data"]
    severity: Severity
    # 0..1 — probability this represents genuine adversary activity
    threat_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    techniques: list[TechniqueAssessment] = Field(default_factory=list)
    reasoning: str
    escalate: bool = Field(description="Whether deep validation is warranted")
    evidence_gaps: list[str] = Field(default_factory=list)


def triage_schema(allowed_technique_ids: list[str]) -> dict[str, Any]:
    """Build the triage schema with technique IDs constrained to what retrieval returned.

    This is the anti-hallucination control: the model physically cannot cite a
    technique that was not retrieved. `NONE` is included so it can decline.
    """
    enum_ids = allowed_technique_ids[:64] or ["NONE"]
    if "NONE" not in enum_ids:
        enum_ids = enum_ids + ["NONE"]
    return {
        "type": "object",
        "properties": {
            "disposition": {"type": "string", "enum": ["benign", "suspicious", "malicious", "insufficient_data"]},
            "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]},
            "threat_score": {"type": "number", "minimum": 0, "maximum": 1},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "techniques": {
                "type": "array", "maxItems": 8,
                "items": {
                    "type": "object",
                    "properties": {
                        "technique_id": {"type": "string", "enum": enum_ids},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "rationale": {"type": "string", "maxLength": 400},
                    },
                    "required": ["technique_id", "confidence", "rationale"],
                    "additionalProperties": False,
                },
            },
            "reasoning": {"type": "string", "maxLength": 1500},
            "escalate": {"type": "boolean"},
            "evidence_gaps": {"type": "array", "maxItems": 8, "items": {"type": "string", "maxLength": 300}},
        },
        "required": ["disposition", "severity", "threat_score", "confidence",
                     "techniques", "reasoning", "escalate", "evidence_gaps"],
        "additionalProperties": False,
    }


# ---------------------------------------------------------------------------
# Stage D — deep reasoning (Spark 2)
# ---------------------------------------------------------------------------

class ProposedAction(BaseModel):
    action_id: str
    parameters: dict[str, str] = Field(default_factory=dict)
    justification: str
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class Hypothesis(BaseModel):
    statement: str
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    status: Literal["proposed", "supported", "refuted", "unresolved"] = "proposed"
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)


class DeepTurn(BaseModel):
    """One turn of the reasoning loop."""
    thinking: str = Field(description="Analysis of evidence so far")
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    next_step: Literal["collect_evidence", "conclude"]
    evidence_requests: list[ProposedAction] = Field(default_factory=list)


class DeepVerdict(BaseModel):
    disposition: Literal["benign", "suspicious", "malicious", "insufficient_data"]
    severity: Severity
    threat_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    attack_narrative: str = Field(description="What the adversary did, in order")
    kill_chain_stage: Literal["reconnaissance", "resource_development", "initial_access",
                              "execution", "persistence", "privilege_escalation",
                              "defense_evasion", "credential_access", "discovery",
                              "lateral_movement", "collection", "command_and_control",
                              "exfiltration", "impact", "unknown"]
    techniques: list[TechniqueAssessment] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    recommended_actions: list[ProposedAction] = Field(default_factory=list)
    is_likely_simulation: bool = Field(
        default=False,
        description="Whether this looks like authorised purple-team activity rather than a real intrusion",
    )
    simulation_indicators: list[str] = Field(default_factory=list)


def deep_turn_schema(action_ids: list[str], allowed_technique_ids: list[str]) -> dict[str, Any]:
    enum_actions = action_ids or ["NONE"]
    enum_techs = (allowed_technique_ids[:64] or []) + ["NONE"]
    return {
        "type": "object",
        "properties": {
            "thinking": {"type": "string", "maxLength": 3000},
            "hypotheses": {
                "type": "array", "maxItems": 6,
                "items": {
                    "type": "object",
                    "properties": {
                        "statement": {"type": "string", "maxLength": 400},
                        "supporting_evidence": {"type": "array", "maxItems": 10, "items": {"type": "string", "maxLength": 300}},
                        "contradicting_evidence": {"type": "array", "maxItems": 10, "items": {"type": "string", "maxLength": 300}},
                        "status": {"type": "string", "enum": ["proposed", "supported", "refuted", "unresolved"]},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    },
                    "required": ["statement", "supporting_evidence", "contradicting_evidence", "status", "confidence"],
                    "additionalProperties": False,
                },
            },
            "next_step": {"type": "string", "enum": ["collect_evidence", "conclude"]},
            "evidence_requests": {
                "type": "array", "maxItems": 3,
                "items": {
                    "type": "object",
                    "properties": {
                        # The security control: an enum, not a free string.
                        "action_id": {"type": "string", "enum": enum_actions},
                        "parameters": {"type": "object", "additionalProperties": {"type": "string"}},
                        "justification": {"type": "string", "maxLength": 400},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    },
                    "required": ["action_id", "parameters", "justification", "confidence"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["thinking", "hypotheses", "next_step", "evidence_requests"],
        "additionalProperties": False,
    }


def deep_verdict_schema(action_ids: list[str], allowed_technique_ids: list[str]) -> dict[str, Any]:
    enum_actions = action_ids or ["NONE"]
    enum_techs = (allowed_technique_ids[:64] or []) + ["NONE"]
    return {
        "type": "object",
        "properties": {
            "disposition": {"type": "string", "enum": ["benign", "suspicious", "malicious", "insufficient_data"]},
            "severity": {"type": "string", "enum": ["informational", "low", "medium", "high", "critical"]},
            "threat_score": {"type": "number", "minimum": 0, "maximum": 1},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "attack_narrative": {"type": "string", "maxLength": 3000},
            "kill_chain_stage": {"type": "string", "enum": [
                "reconnaissance", "resource_development", "initial_access", "execution",
                "persistence", "privilege_escalation", "defense_evasion", "credential_access",
                "discovery", "lateral_movement", "collection", "command_and_control",
                "exfiltration", "impact", "unknown"]},
            "techniques": {
                "type": "array", "maxItems": 12,
                "items": {
                    "type": "object",
                    "properties": {
                        "technique_id": {"type": "string", "enum": enum_techs},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "rationale": {"type": "string", "maxLength": 400},
                    },
                    "required": ["technique_id", "confidence", "rationale"],
                    "additionalProperties": False,
                },
            },
            "hypotheses": {
                "type": "array", "maxItems": 6,
                "items": {
                    "type": "object",
                    "properties": {
                        "statement": {"type": "string", "maxLength": 400},
                        "supporting_evidence": {"type": "array", "maxItems": 10, "items": {"type": "string", "maxLength": 300}},
                        "contradicting_evidence": {"type": "array", "maxItems": 10, "items": {"type": "string", "maxLength": 300}},
                        "status": {"type": "string", "enum": ["proposed", "supported", "refuted", "unresolved"]},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    },
                    "required": ["statement", "supporting_evidence", "contradicting_evidence", "status", "confidence"],
                    "additionalProperties": False,
                },
            },
            "recommended_actions": {
                "type": "array", "maxItems": 6,
                "items": {
                    "type": "object",
                    "properties": {
                        "action_id": {"type": "string", "enum": enum_actions},
                        "parameters": {"type": "object", "additionalProperties": {"type": "string"}},
                        "justification": {"type": "string", "maxLength": 400},
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                    },
                    "required": ["action_id", "parameters", "justification", "confidence"],
                    "additionalProperties": False,
                },
            },
            "is_likely_simulation": {"type": "boolean"},
            "simulation_indicators": {"type": "array", "maxItems": 8, "items": {"type": "string", "maxLength": 300}},
        },
        "required": ["disposition", "severity", "threat_score", "confidence", "attack_narrative",
                     "kill_chain_stage", "techniques", "hypotheses", "recommended_actions",
                     "is_likely_simulation", "simulation_indicators"],
        "additionalProperties": False,
    }


# ---------------------------------------------------------------------------
# Case state
# ---------------------------------------------------------------------------

class ActionRecord(BaseModel):
    action_id: str
    tier: str
    parameters: dict[str, str] = Field(default_factory=dict)
    status: Literal["proposed", "rejected", "dry_run", "pending_approval",
                    "approved", "dispatched", "succeeded", "failed", "expired"] = "proposed"
    reason: str = ""
    soar_action_run_id: str | None = None
    result_summary: str = ""
    requested_at: float = Field(default_factory=time.time)
    completed_at: float | None = None
    approval_id: str | None = None


class CaseStatus(str, Enum):
    QUEUED = "queued"
    TRIAGING = "triaging"
    TRIAGED = "triaged"
    DEEP_QUEUED = "deep_queued"
    REASONING = "reasoning"
    COMPLETE = "complete"
    FAILED = "failed"
    SUPPRESSED = "suppressed"


class Case(BaseModel):
    case_id: str = Field(default_factory=lambda: f"SPARKSOC-{uuid.uuid4().hex[:12].upper()}")
    fingerprint: str = ""
    status: CaseStatus = CaseStatus.QUEUED
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)

    alert: SplunkAlert | None = None
    features: AlertFeatures | None = None
    rag: RagResult | None = None
    triage: TriageVerdict | None = None
    deep: DeepVerdict | None = None

    actions: list[ActionRecord] = Field(default_factory=list)
    soar_container_id: int | None = None
    exercise_id: str | None = None

    errors: list[str] = Field(default_factory=list)
    timings_ms: dict[str, int] = Field(default_factory=dict)

    def touch(self) -> None:
        self.updated_at = time.time()

    def final_severity(self) -> Severity:
        if self.deep:
            return self.deep.severity
        if self.triage:
            return self.triage.severity
        return Severity.INFORMATIONAL

    def final_technique_ids(self) -> list[str]:
        src = self.deep.techniques if self.deep else (self.triage.techniques if self.triage else [])
        return [t.technique_id for t in src if t.technique_id != "NONE"]


# ---------------------------------------------------------------------------
# Exercise scoring
# ---------------------------------------------------------------------------

class GroundTruthEvent(BaseModel):
    """One executed step from the purple team's plan."""
    technique_id: str
    name: str = ""
    executed_at: float
    target_host: str = ""
    target_user: str = ""
    tool: str = ""            # atomic-red-team, caldera, manual, ...
    expected_detection: bool = True
    notes: str = ""


class Exercise(BaseModel):
    exercise_id: str
    name: str
    started_at: float = Field(default_factory=time.time)
    ended_at: float | None = None
    ground_truth: list[GroundTruthEvent] = Field(default_factory=list)
    case_ids: list[str] = Field(default_factory=list)
    # Seconds either side of an executed step in which a case counts as a match
    match_window_seconds: int = 900

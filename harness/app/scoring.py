"""Purple-team exercise scoring.

This is the module that makes the difference between "an alert triage assistant"
and "a system that catches and reports on purple-team simulations". It takes the
red team's executed technique list as ground truth and scores what the pipeline
actually produced against it.

Matching model
--------------
A ground-truth event is DETECTED when at least one case satisfies all of:
  - the case's final technique set contains the executed technique id, OR the
    parent technique when the executed step was a sub-technique (T1059.001
    detected as T1059 is a partial, not a miss — it is scored separately)
  - the case's alert timestamp is within +/- match_window_seconds of execution
  - the case's target host matches, when both are known

Metrics reported
----------------
  detection rate      fraction of executed steps detected at all
  exact rate          fraction detected at sub-technique precision
  MTTD                median seconds from execution to triage verdict
  MTTD-deep           median seconds to deep verdict
  precision           fraction of escalated cases that map to a real step
                      (an escalated case with no ground-truth match inside the
                      window is a false positive for this exercise)
  coverage by tactic  where the pipeline is blind
  simulation recall   how often the deep verdict correctly flagged simulation

Interpretation caveat, stated in the report: precision computed this way treats
any escalation without a matching executed step as a false positive. In a live
range there is genuine background activity, so this is a lower bound on
precision, not a true measurement.
"""

from __future__ import annotations

import html
import json
import logging
import statistics
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import Case, Exercise, GroundTruthEvent

LOG = logging.getLogger("sparksoc.scoring")


@dataclass
class Detection:
    event: GroundTruthEvent
    case_id: str | None = None
    matched_technique: str = ""
    match_kind: str = "miss"          # exact | parent | miss
    detection_latency_s: float | None = None
    deep_latency_s: float | None = None
    threat_score: float = 0.0
    disposition: str = ""
    flagged_simulation: bool = False


@dataclass
class ExerciseReport:
    exercise_id: str
    name: str
    started_at: float
    ended_at: float | None
    duration_s: float

    total_steps: int = 0
    detected: int = 0
    exact: int = 0
    parent_only: int = 0
    missed: int = 0

    detection_rate: float = 0.0
    exact_rate: float = 0.0

    mttd_seconds: float | None = None
    mttd_p95_seconds: float | None = None
    mttd_deep_seconds: float | None = None

    total_cases: int = 0
    escalated_cases: int = 0
    matched_cases: int = 0
    unmatched_escalations: int = 0
    precision_lower_bound: float = 0.0

    simulation_flagged: int = 0
    simulation_recall: float = 0.0

    tactic_coverage: dict[str, dict[str, int]] = field(default_factory=dict)
    platform_coverage: dict[str, dict[str, int]] = field(default_factory=dict)
    detections: list[Detection] = field(default_factory=list)
    actions_summary: dict[str, int] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)


class ExerciseTracker:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.exercises: dict[str, Exercise] = {}
        self._load()

    # ------------------------------------------------------------------
    def _path(self, exercise_id: str) -> Path:
        return self.state_dir / f"exercise-{exercise_id}.json"

    def _load(self) -> None:
        for p in self.state_dir.glob("exercise-*.json"):
            try:
                self.exercises[json.loads(p.read_text())["exercise_id"]] = \
                    Exercise.model_validate_json(p.read_text())
            except Exception as exc:
                LOG.warning("Could not load %s: %s", p, exc)
        if self.exercises:
            LOG.info("Loaded %d exercise(s) from disk", len(self.exercises))

    def _save(self, ex: Exercise) -> None:
        self._path(ex.exercise_id).write_text(ex.model_dump_json(indent=2), encoding="utf-8")

    # ------------------------------------------------------------------
    def start(self, exercise_id: str, name: str, match_window_seconds: int = 900) -> Exercise:
        ex = Exercise(exercise_id=exercise_id, name=name,
                      match_window_seconds=match_window_seconds)
        self.exercises[exercise_id] = ex
        self._save(ex)
        LOG.info("Exercise %s (%s) started", exercise_id, name)
        return ex

    def stop(self, exercise_id: str) -> Exercise | None:
        ex = self.exercises.get(exercise_id)
        if ex:
            ex.ended_at = time.time()
            self._save(ex)
            LOG.info("Exercise %s stopped after %.0f minutes",
                     exercise_id, (ex.ended_at - ex.started_at) / 60)
        return ex

    def active(self) -> Exercise | None:
        for ex in self.exercises.values():
            if ex.ended_at is None:
                return ex
        return None

    def add_ground_truth(self, exercise_id: str, events: list[GroundTruthEvent]) -> int:
        ex = self.exercises.get(exercise_id)
        if not ex:
            return 0
        ex.ground_truth.extend(events)
        ex.ground_truth.sort(key=lambda e: e.executed_at)
        self._save(ex)
        return len(events)

    def attach_case(self, exercise_id: str, case_id: str) -> None:
        ex = self.exercises.get(exercise_id)
        if ex and case_id not in ex.case_ids:
            ex.case_ids.append(case_id)
            self._save(ex)

    # ==================================================================
    # Scoring
    # ==================================================================
    def score(self, exercise_id: str, cases: list[Case]) -> ExerciseReport | None:
        ex = self.exercises.get(exercise_id)
        if not ex:
            return None

        ended = ex.ended_at or time.time()
        report = ExerciseReport(
            exercise_id=ex.exercise_id, name=ex.name,
            started_at=ex.started_at, ended_at=ex.ended_at,
            duration_s=ended - ex.started_at,
            total_steps=len(ex.ground_truth),
            total_cases=len(cases),
        )

        if not ex.ground_truth:
            report.notes.append(
                "No ground truth was supplied. Detection metrics cannot be computed. "
                "POST the executed technique list to /v1/exercise/{id}/ground-truth "
                "(Atomic Red Team and Caldera exports are both accepted)."
            )
            report.escalated_cases = sum(1 for c in cases if c.deep is not None)
            return report

        matched_case_ids: set[str] = set()

        for event in ex.ground_truth:
            det = self._match_event(event, cases, ex.match_window_seconds)
            report.detections.append(det)
            if det.case_id:
                matched_case_ids.add(det.case_id)

            tactic_bucket = report.tactic_coverage.setdefault(
                self._tactic_of(event, cases), {"executed": 0, "detected": 0})
            tactic_bucket["executed"] += 1

            plat = event.target_host[:5].upper() if event.target_host else "UNKNOWN"
            plat_bucket = report.platform_coverage.setdefault(
                plat, {"executed": 0, "detected": 0})
            plat_bucket["executed"] += 1

            if det.match_kind == "exact":
                report.exact += 1
                report.detected += 1
                tactic_bucket["detected"] += 1
                plat_bucket["detected"] += 1
            elif det.match_kind == "parent":
                report.parent_only += 1
                report.detected += 1
                tactic_bucket["detected"] += 1
                plat_bucket["detected"] += 1
            else:
                report.missed += 1

        report.detection_rate = report.detected / max(report.total_steps, 1)
        report.exact_rate = report.exact / max(report.total_steps, 1)

        latencies = [d.detection_latency_s for d in report.detections
                     if d.detection_latency_s is not None]
        if latencies:
            report.mttd_seconds = statistics.median(latencies)
            s = sorted(latencies)
            report.mttd_p95_seconds = s[min(len(s) - 1, int(len(s) * 0.95))]

        deep_latencies = [d.deep_latency_s for d in report.detections
                          if d.deep_latency_s is not None]
        if deep_latencies:
            report.mttd_deep_seconds = statistics.median(deep_latencies)

        escalated = [c for c in cases if c.deep is not None
                     or (c.triage and c.triage.threat_score >= 0.45)]
        report.escalated_cases = len(escalated)
        report.matched_cases = len(matched_case_ids)
        report.unmatched_escalations = sum(1 for c in escalated if c.case_id not in matched_case_ids)
        report.precision_lower_bound = (
            report.matched_cases / len(escalated) if escalated else 0.0
        )

        sim_flagged = [c for c in cases if c.deep and c.deep.is_likely_simulation]
        report.simulation_flagged = len(sim_flagged)
        deep_matched = [c for c in cases if c.deep and c.case_id in matched_case_ids]
        if deep_matched:
            report.simulation_recall = sum(
                1 for c in deep_matched if c.deep.is_likely_simulation) / len(deep_matched)

        action_counter: Counter[str] = Counter()
        for c in cases:
            for a in c.actions:
                action_counter[f"{a.action_id}:{a.status}"] += 1
        report.actions_summary = dict(action_counter)

        report.notes.append(
            "precision_lower_bound treats every escalated case without a matching "
            "executed step as a false positive. Genuine background activity on the "
            "range is therefore counted against precision, so the true value is higher."
        )
        if report.parent_only:
            report.notes.append(
                f"{report.parent_only} step(s) were detected only at parent-technique "
                f"precision. These are real detections, but an analyst reading the case "
                f"would not have known which sub-technique was used."
            )
        degraded = sum(1 for c in cases if c.rag and c.rag.degraded)
        if degraded:
            report.notes.append(
                f"{degraded} case(s) ran with DEGRADED ATT&CK retrieval (Qdrant unavailable). "
                f"Their technique attributions are less reliable and depress exact_rate."
            )
        failed = sum(1 for c in cases if c.status.value == "failed")
        if failed:
            report.notes.append(f"{failed} case(s) failed outright — check the audit log for "
                                f"pipeline.error entries before trusting these numbers.")

        return report

    # ------------------------------------------------------------------
    def _match_event(self, event: GroundTruthEvent, cases: list[Case],
                     window: int) -> Detection:
        det = Detection(event=event)
        parent = event.technique_id.split(".")[0]

        best: tuple[int, Case, str, str] | None = None   # (rank, case, tech, kind)

        for case in cases:
            case_time = case.alert.trigger_time if (case.alert and case.alert.trigger_time) else case.created_at
            delta = case_time - event.executed_at
            # Only look forward, plus a small grace for clock skew.
            if delta < -60 or delta > window:
                continue

            if event.target_host:
                case_host = case.alert.primary_host() if case.alert else None
                if case_host and case_host.upper() != event.target_host.upper():
                    continue

            techs = case.final_technique_ids()
            if event.technique_id in techs:
                rank, kind, tech = 0, "exact", event.technique_id
            elif parent in techs or any(t.split(".")[0] == parent for t in techs):
                rank, kind = 1, "parent"
                tech = next((t for t in techs if t.split(".")[0] == parent), parent)
            else:
                continue

            if best is None or rank < best[0] or (rank == best[0] and case_time < best[1].created_at):
                best = (rank, case, tech, kind)

        if best is None:
            return det

        _, case, tech, kind = best
        case_time = case.alert.trigger_time if (case.alert and case.alert.trigger_time) else case.created_at
        det.case_id = case.case_id
        det.matched_technique = tech
        det.match_kind = kind
        det.threat_score = (case.deep or case.triage).threat_score if (case.deep or case.triage) else 0.0
        det.disposition = (case.deep or case.triage).disposition if (case.deep or case.triage) else ""
        det.flagged_simulation = bool(case.deep and case.deep.is_likely_simulation)

        fast_ms = case.timings_ms.get("fast_total", 0)
        det.detection_latency_s = (case_time - event.executed_at) + fast_ms / 1000
        if case.deep:
            det.deep_latency_s = det.detection_latency_s + case.timings_ms.get("deep_total", 0) / 1000
        return det

    @staticmethod
    def _tactic_of(event: GroundTruthEvent, cases: list[Case]) -> str:
        for case in cases:
            if not case.rag:
                continue
            for hit in case.rag.hits:
                if hit.technique_id == event.technique_id and hit.tactics:
                    return hit.tactics[0]
        return "unmapped"


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def report_to_dict(r: ExerciseReport) -> dict[str, Any]:
    return {
        "exercise_id": r.exercise_id, "name": r.name,
        "started_at": r.started_at, "ended_at": r.ended_at,
        "duration_minutes": round(r.duration_s / 60, 1),
        "summary": {
            "total_steps": r.total_steps, "detected": r.detected,
            "exact": r.exact, "parent_only": r.parent_only, "missed": r.missed,
            "detection_rate": round(r.detection_rate, 4),
            "exact_rate": round(r.exact_rate, 4),
            "mttd_seconds": round(r.mttd_seconds, 1) if r.mttd_seconds else None,
            "mttd_p95_seconds": round(r.mttd_p95_seconds, 1) if r.mttd_p95_seconds else None,
            "mttd_deep_seconds": round(r.mttd_deep_seconds, 1) if r.mttd_deep_seconds else None,
            "total_cases": r.total_cases, "escalated_cases": r.escalated_cases,
            "unmatched_escalations": r.unmatched_escalations,
            "precision_lower_bound": round(r.precision_lower_bound, 4),
            "simulation_flagged": r.simulation_flagged,
            "simulation_recall": round(r.simulation_recall, 4),
        },
        "tactic_coverage": r.tactic_coverage,
        "platform_coverage": r.platform_coverage,
        "actions": r.actions_summary,
        "detections": [
            {
                "technique_id": d.event.technique_id,
                "name": d.event.name,
                "executed_at": d.event.executed_at,
                "target_host": d.event.target_host,
                "tool": d.event.tool,
                "match": d.match_kind,
                "matched_technique": d.matched_technique,
                "case_id": d.case_id,
                "detection_latency_s": round(d.detection_latency_s, 1) if d.detection_latency_s else None,
                "deep_latency_s": round(d.deep_latency_s, 1) if d.deep_latency_s else None,
                "threat_score": d.threat_score,
                "disposition": d.disposition,
                "flagged_simulation": d.flagged_simulation,
            }
            for d in r.detections
        ],
        "notes": r.notes,
    }


def report_to_html(r: ExerciseReport) -> str:
    """Self-contained HTML report. No external assets — this runs in an airgap."""
    e = html.escape

    def pct(x: float) -> str:
        return f"{x * 100:.1f}%"

    rows = []
    for d in sorted(r.detections, key=lambda x: x.event.executed_at):
        colour = {"exact": "#1a7f4b", "parent": "#a8760b", "miss": "#a3242b"}[d.match_kind]
        label = {"exact": "DETECTED", "parent": "PARTIAL", "miss": "MISSED"}[d.match_kind]
        rows.append(f"""
      <tr>
        <td><code>{e(d.event.technique_id)}</code></td>
        <td>{e(d.event.name or '')}</td>
        <td>{e(d.event.target_host or '')}</td>
        <td>{time.strftime('%H:%M:%S', time.localtime(d.event.executed_at))}</td>
        <td><span class="pill" style="background:{colour}">{label}</span></td>
        <td>{e(d.matched_technique)}</td>
        <td>{f'{d.detection_latency_s:.0f}s' if d.detection_latency_s is not None else '—'}</td>
        <td>{d.threat_score:.2f}</td>
        <td>{e(d.case_id or '—')}</td>
      </tr>""")

    tactic_rows = "".join(
        f"<tr><td>{e(k)}</td><td>{v['executed']}</td><td>{v['detected']}</td>"
        f"<td>{pct(v['detected'] / max(v['executed'], 1))}</td></tr>"
        for k, v in sorted(r.tactic_coverage.items(),
                           key=lambda kv: kv[1]['detected'] / max(kv[1]['executed'], 1))
    )

    action_rows = "".join(
        f"<tr><td><code>{e(k)}</code></td><td>{v}</td></tr>"
        for k, v in sorted(r.actions_summary.items(), key=lambda kv: -kv[1])
    ) or "<tr><td colspan=2>No actions were taken.</td></tr>"

    notes = "".join(f"<li>{e(n)}</li>" for n in r.notes)

    def card(label: str, value: str, sub: str = "") -> str:
        return (f'<div class="card"><div class="label">{e(label)}</div>'
                f'<div class="value">{e(value)}</div>'
                f'<div class="sub">{e(sub)}</div></div>')

    cards = "".join([
        card("Detection rate", pct(r.detection_rate), f"{r.detected} of {r.total_steps} steps"),
        card("Exact precision", pct(r.exact_rate), f"{r.parent_only} parent-only"),
        card("MTTD (median)", f"{r.mttd_seconds:.0f}s" if r.mttd_seconds else "—",
             f"p95 {r.mttd_p95_seconds:.0f}s" if r.mttd_p95_seconds else ""),
        card("Deep verdict", f"{r.mttd_deep_seconds:.0f}s" if r.mttd_deep_seconds else "—", "median"),
        card("Precision (lower bound)", pct(r.precision_lower_bound),
             f"{r.unmatched_escalations} unmatched escalations"),
        card("Simulation recall", pct(r.simulation_recall), f"{r.simulation_flagged} flagged"),
    ])

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>SPARKSOC exercise report — {e(r.name)}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{ font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
         margin: 0; padding: 32px; background: #f6f7f9; color: #16181d; }}
  @media (prefers-color-scheme: dark) {{
    body {{ background: #14161a; color: #e7e9ee; }}
    .card, table, .panel {{ background: #1c1f25 !important; border-color: #2b2f38 !important; }}
    th {{ background: #23262e !important; }}
  }}
  h1 {{ font-size: 24px; margin: 0 0 4px; letter-spacing: -0.01em; }}
  .meta {{ color: #6b7280; font-size: 13px; margin-bottom: 24px; }}
  .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 12px; margin-bottom: 28px; }}
  .card {{ background: #fff; border: 1px solid #e3e6ea; border-radius: 10px; padding: 16px; }}
  .card .label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em; color: #6b7280; }}
  .card .value {{ font-size: 28px; font-weight: 600; margin: 6px 0 2px; font-variant-numeric: tabular-nums; }}
  .card .sub {{ font-size: 12px; color: #6b7280; }}
  h2 {{ font-size: 16px; margin: 28px 0 10px; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff;
           border: 1px solid #e3e6ea; border-radius: 10px; overflow: hidden; font-size: 13px; }}
  th, td {{ text-align: left; padding: 9px 12px; border-bottom: 1px solid #eceef1; }}
  th {{ background: #f2f4f6; font-weight: 600; font-size: 11px;
        text-transform: uppercase; letter-spacing: 0.05em; color: #4b5563; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{ font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }}
  .pill {{ display: inline-block; padding: 2px 9px; border-radius: 999px;
           color: #fff; font-size: 11px; font-weight: 600; letter-spacing: 0.03em; }}
  .panel {{ background: #fff; border: 1px solid #e3e6ea; border-radius: 10px;
            padding: 14px 18px; font-size: 13px; }}
  .panel li {{ margin-bottom: 6px; }}
</style></head>
<body>
  <h1>{e(r.name)}</h1>
  <div class="meta">
    Exercise <code>{e(r.exercise_id)}</code> ·
    {time.strftime('%Y-%m-%d %H:%M', time.localtime(r.started_at))} ·
    {r.duration_s / 60:.0f} minutes ·
    {r.total_cases} cases from {r.total_steps} executed steps
  </div>

  <div class="cards">{cards}</div>

  <h2>Executed steps</h2>
  <table>
    <thead><tr>
      <th>Technique</th><th>Name</th><th>Host</th><th>Executed</th>
      <th>Result</th><th>Matched as</th><th>MTTD</th><th>Score</th><th>Case</th>
    </tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>

  <h2>Coverage by tactic</h2>
  <table>
    <thead><tr><th>Tactic</th><th>Executed</th><th>Detected</th><th>Rate</th></tr></thead>
    <tbody>{tactic_rows or '<tr><td colspan=4>No tactic mapping available.</td></tr>'}</tbody>
  </table>

  <h2>Automated actions</h2>
  <table>
    <thead><tr><th>Action : status</th><th>Count</th></tr></thead>
    <tbody>{action_rows}</tbody>
  </table>

  <h2>Reading these numbers</h2>
  <div class="panel"><ul>{notes}</ul></div>
</body></html>"""


# ---------------------------------------------------------------------------
# Ground truth importers
# ---------------------------------------------------------------------------

def parse_atomic_red_team(data: list[dict[str, Any]]) -> list[GroundTruthEvent]:
    """Invoke-AtomicTest execution log (Get-AtomicLogEntries / -ExecutionLogPath CSV as JSON)."""
    out: list[GroundTruthEvent] = []
    for row in data:
        tid = (row.get("Technique") or row.get("technique") or
               row.get("TechniqueId") or row.get("attack_technique") or "")
        if not tid:
            continue
        ts = row.get("ExecutionTime") or row.get("Timestamp") or row.get("timestamp") or 0
        out.append(GroundTruthEvent(
            technique_id=str(tid).strip().upper(),
            name=str(row.get("TestName") or row.get("test_name") or row.get("Test") or ""),
            executed_at=_to_epoch(ts),
            target_host=str(row.get("Hostname") or row.get("hostname") or row.get("ExecutedOn") or ""),
            tool="atomic-red-team",
            notes=str(row.get("TestGuid") or ""),
        ))
    return out


def parse_caldera(data: list[dict[str, Any]]) -> list[GroundTruthEvent]:
    """Caldera operation report `steps` export."""
    out: list[GroundTruthEvent] = []
    for row in data:
        tid = row.get("attack_metadata", {}).get("technique_id") or row.get("technique_id") or ""
        if not tid:
            continue
        out.append(GroundTruthEvent(
            technique_id=str(tid).strip().upper(),
            name=str(row.get("name") or row.get("ability_name") or ""),
            executed_at=_to_epoch(row.get("run") or row.get("finish") or row.get("timestamp") or 0),
            target_host=str(row.get("host") or row.get("paw") or ""),
            tool="caldera",
            notes=str(row.get("status", "")),
        ))
    return out


def _to_epoch(value: Any) -> float:
    if isinstance(value, (int, float)):
        # Heuristic: values above ~1e11 are milliseconds
        return float(value) / 1000 if float(value) > 1e11 else float(value)
    if isinstance(value, str) and value.strip():
        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%d %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return time.mktime(time.strptime(value.strip(), fmt))
            except ValueError:
                continue
        LOG.warning("Unparseable ground-truth timestamp: %r", value)
    return time.time()

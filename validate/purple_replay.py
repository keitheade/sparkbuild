#!/usr/bin/env python3
"""
Purple-team exercise driver and replay harness.

Two modes:

  live      Start an exercise, register the red team's plan as ground truth,
            wait while they execute against the range (real Splunk alerts flow
            in through TA-soc-harness), then stop and fetch the report.
            This is the real workflow.

  replay    Start an exercise and inject a scripted chain of SYNTHETIC alerts
            on a timeline, registering matching ground truth automatically.
            No range required. Use this to validate the scoring pipeline itself
            and to rehearse before the actual exercise — it is the only way to
            know your detection-rate number means what you think it means.

    python3 purple_replay.py replay --config config.yaml --plan plans/apt-chain.yaml
    python3 purple_replay.py live   --config config.yaml --plan plans/exercise.yaml --duration 90
    python3 purple_replay.py report --config config.yaml --exercise EX-20260818-1400 --html out.html
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import yaml

GRN, RED, YEL, CYN, DIM, RST = (
    "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[2m", "\033[0m"
)


class Driver:
    def __init__(self, cfg: dict[str, Any]):
        self.url = cfg["harness"]["url"].rstrip("/")
        self.secret = cfg["harness"]["hmac_secret"]
        self.client = httpx.Client(timeout=60.0, verify=cfg.get("verify_tls", True))

    def _sign(self, ts: str, nonce: str, body: bytes) -> str:
        msg = ts.encode() + b"." + nonce.encode() + b"." + body
        return "sha256=" + hmac.new(self.secret.encode(), msg, hashlib.sha256).hexdigest()

    def submit_alert(self, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode()
        ts, nonce = str(int(time.time())), secrets.token_hex(16)
        r = self.client.post(f"{self.url}/v1/alert", content=body, headers={
            "Content-Type": "application/json", "X-SparkSOC-Timestamp": ts,
            "X-SparkSOC-Nonce": nonce, "X-SparkSOC-Signature": self._sign(ts, nonce, body)})
        r.raise_for_status()
        return r.json()

    def start(self, name: str, exercise_id: str | None, window: int) -> dict[str, Any]:
        r = self.client.post(f"{self.url}/v1/exercise/start", json={
            "name": name, "exercise_id": exercise_id, "match_window_seconds": window})
        if r.status_code == 409:
            raise SystemExit(f"{RED}An exercise is already running. Stop it first:{RST}\n"
                             f"  curl -XPOST {self.url}/v1/exercise/<id>/stop")
        r.raise_for_status()
        return r.json()

    def stop(self, exercise_id: str) -> dict[str, Any]:
        r = self.client.post(f"{self.url}/v1/exercise/{exercise_id}/stop")
        r.raise_for_status()
        return r.json()

    def ground_truth(self, exercise_id: str, events: list[dict[str, Any]],
                     fmt: str = "native") -> dict[str, Any]:
        r = self.client.post(f"{self.url}/v1/exercise/{exercise_id}/ground-truth",
                             json={"format": fmt, "events": events})
        r.raise_for_status()
        return r.json()

    def report(self, exercise_id: str, fmt: str = "json") -> Any:
        r = self.client.get(f"{self.url}/v1/exercise/{exercise_id}/report",
                            params={"format": fmt})
        r.raise_for_status()
        return r.text if fmt == "html" else r.json()

    def queue_depth(self) -> tuple[int, int]:
        try:
            d = self.client.get(f"{self.url}/health/deep").json()["queues"]
            return d["fast_depth"], d["deep_depth"]
        except Exception:
            return -1, -1


# ---------------------------------------------------------------------------
def load_plan(path: Path) -> dict[str, Any]:
    plan = yaml.safe_load(path.read_text())
    if "steps" not in plan:
        raise SystemExit(f"{RED}Plan {path} has no 'steps' list{RST}")
    return plan


def build_alert(step: dict[str, Any], seq: int) -> dict[str, Any]:
    """Turn a plan step into a synthetic Splunk alert payload."""
    return {
        "search_name": step.get("search_name", "SPARKSOC - Replay"),
        "sid": f"replay_{seq:04d}_{secrets.token_hex(3)}",
        "result_count": len(step.get("results", [])),
        "trigger_time": int(time.time()),
        "severity": step.get("severity"),
        "labels": ["replay", f"step:{seq}"],
        "results": step.get("results", []),
    }


def cmd_replay(driver: Driver, args) -> int:
    plan = load_plan(Path(args.plan))
    steps = plan["steps"]

    name = args.name or plan.get("name", "Replay exercise")
    eid = args.exercise_id or f"EX-{time.strftime('%Y%m%d-%H%M%S')}"
    ex = driver.start(name, eid, plan.get("match_window_seconds", 900))
    eid = ex["exercise_id"]
    print(f"{CYN}Exercise {eid} — {name}{RST}")
    print(f"{DIM}{len(steps)} steps, compressed timeline{RST}\n")

    ground_truth: list[dict[str, Any]] = []
    t_start = time.time()

    for i, step in enumerate(steps, 1):
        delay = float(step.get("delay_seconds", args.step_delay))
        if delay > 0:
            time.sleep(delay)

        executed_at = time.time()
        tid = step["technique_id"]
        host = step.get("target_host", "")

        ground_truth.append({
            "technique_id": tid,
            "name": step.get("name", ""),
            "executed_at": executed_at,
            "target_host": host,
            "tool": "replay",
            "expected_detection": step.get("expected_detection", True),
            "notes": step.get("notes", ""),
        })

        if step.get("stealth"):
            # A step with no telemetry: models a technique the range does not
            # instrument. It SHOULD be missed, and the report should say so.
            print(f"  {i:>3}. {tid:<12} {host:<18} {DIM}stealth — no alert emitted{RST}")
            continue

        try:
            resp = driver.submit_alert(build_alert(step, i))
            fast, deep = driver.queue_depth()
            status = resp.get("status")
            mark = f"{GRN}{status}{RST}" if status == "accepted" else f"{YEL}{status}{RST}"
            print(f"  {i:>3}. {tid:<12} {host:<18} {mark} "
                  f"{DIM}case={resp.get('case_id','-')} q={fast}/{deep}{RST}")
        except httpx.HTTPStatusError as exc:
            print(f"  {i:>3}. {tid:<12} {host:<18} {RED}HTTP {exc.response.status_code}{RST}")
        except Exception as exc:
            print(f"  {i:>3}. {tid:<12} {host:<18} {RED}{exc}{RST}")

    driver.ground_truth(eid, ground_truth)
    print(f"\n{DIM}Registered {len(ground_truth)} ground-truth events{RST}")

    # Let the deep path drain. Scoring before it finishes understates detection.
    print(f"{CYN}Draining pipeline (up to {args.drain}s)...{RST}")
    deadline = time.time() + args.drain
    while time.time() < deadline:
        fast, deep = driver.queue_depth()
        if fast == 0 and deep == 0:
            print(f"{GRN}  queues empty after {time.time() - t_start:.0f}s{RST}")
            break
        print(f"{DIM}  fast={fast} deep={deep}{RST}", end="\r")
        time.sleep(5)
    else:
        print(f"\n{YEL}  drain timeout — some deep verdicts may be missing from the report{RST}")

    driver.stop(eid)
    return emit_report(driver, eid, args)


def cmd_live(driver: Driver, args) -> int:
    plan = load_plan(Path(args.plan)) if args.plan else {"steps": []}
    name = args.name or plan.get("name", "Purple team exercise")
    eid = args.exercise_id or f"EX-{time.strftime('%Y%m%d-%H%M%S')}"

    ex = driver.start(name, eid, plan.get("match_window_seconds", 900))
    eid = ex["exercise_id"]

    print(f"{CYN}Exercise {eid} — {name}{RST}")
    print(f"{GRN}Started. Real Splunk alerts are now attributed to this exercise.{RST}\n")
    print("Register the red team's executed steps as they go, or in bulk at the end:")
    print(f"  curl -XPOST {driver.url}/v1/exercise/{eid}/ground-truth \\")
    print( "       -H 'Content-Type: application/json' \\")
    print( "       -d '{\"format\":\"atomic\",\"events\":[...]}'   # Invoke-AtomicTest log")
    print( "       -d '{\"format\":\"caldera\",\"events\":[...]}'  # Caldera steps export\n")

    if plan.get("steps"):
        gt = [{
            "technique_id": s["technique_id"], "name": s.get("name", ""),
            "executed_at": time.time(), "target_host": s.get("target_host", ""),
            "tool": "plan", "notes": s.get("notes", ""),
        } for s in plan["steps"]]
        print(f"{YEL}Note: the plan's steps were registered with the CURRENT time, "
              f"not their real execution times.{RST}")
        print(f"{YEL}For accurate MTTD, post the red team's real execution log instead.{RST}\n")
        driver.ground_truth(eid, gt)

    end = time.time() + args.duration * 60
    print(f"{CYN}Monitoring for {args.duration} minutes. Ctrl-C to stop early and report.{RST}\n")
    try:
        while time.time() < end:
            fast, deep = driver.queue_depth()
            cases = driver.client.get(f"{driver.url}/v1/cases",
                                      params={"exercise_id": eid, "limit": 500}).json()
            n = cases["count"]
            escalated = sum(1 for c in cases["cases"] if c.get("techniques"))
            remaining = (end - time.time()) / 60
            print(f"  {time.strftime('%H:%M:%S')}  cases={n:<4} with-techniques={escalated:<4} "
                  f"queues={fast}/{deep}  {remaining:.0f}m left    ", end="\r")
            time.sleep(10)
    except KeyboardInterrupt:
        print(f"\n{YEL}Stopped early by operator{RST}")

    print(f"\n{CYN}Draining...{RST}")
    deadline = time.time() + args.drain
    while time.time() < deadline:
        fast, deep = driver.queue_depth()
        if fast == 0 and deep == 0:
            break
        time.sleep(5)

    driver.stop(eid)
    return emit_report(driver, eid, args)


def cmd_report(driver: Driver, args) -> int:
    return emit_report(driver, args.exercise_id, args)


def emit_report(driver: Driver, eid: str, args) -> int:
    data = driver.report(eid, "json")
    s = data["summary"]

    print(f"\n{CYN}{'=' * 72}{RST}")
    print(f"  {data['name']}   ({eid})")
    print(f"  {data['duration_minutes']} minutes")
    print(f"{CYN}{'=' * 72}{RST}")

    def line(label: str, value: str, note: str = "") -> None:
        print(f"  {label:<26} {value:>10}   {DIM}{note}{RST}")

    rate = s["detection_rate"]
    colour = GRN if rate >= 0.8 else (YEL if rate >= 0.5 else RED)
    line("Detection rate", f"{colour}{rate * 100:.1f}%{RST}",
         f"{s['detected']}/{s['total_steps']} steps")
    line("Exact (sub-technique)", f"{s['exact_rate'] * 100:.1f}%",
         f"{s['parent_only']} parent-only, {s['missed']} missed")
    if s.get("mttd_seconds") is not None:
        line("MTTD median", f"{s['mttd_seconds']:.0f}s", f"p95 {s.get('mttd_p95_seconds', 0):.0f}s")
    if s.get("mttd_deep_seconds") is not None:
        line("MTTD deep verdict", f"{s['mttd_deep_seconds']:.0f}s", "median")
    line("Precision (lower bound)", f"{s['precision_lower_bound'] * 100:.1f}%",
         f"{s['unmatched_escalations']} unmatched escalations")
    line("Simulation recall", f"{s['simulation_recall'] * 100:.1f}%",
         f"{s['simulation_flagged']} flagged as simulation")
    line("Cases", str(s["total_cases"]), f"{s['escalated_cases']} escalated")

    missed = [d for d in data["detections"] if d["match"] == "miss"]
    if missed:
        print(f"\n{RED}  Missed steps:{RST}")
        for d in missed:
            print(f"    {d['technique_id']:<12} {d['name'][:40]:<42} {d['target_host']}")

    partial = [d for d in data["detections"] if d["match"] == "parent"]
    if partial:
        print(f"\n{YEL}  Detected only at parent-technique precision:{RST}")
        for d in partial:
            print(f"    {d['technique_id']:<12} matched as {d['matched_technique']:<12} "
                  f"{d['name'][:36]}")

    weak = sorted(data["tactic_coverage"].items(),
                  key=lambda kv: kv[1]["detected"] / max(kv[1]["executed"], 1))[:5]
    if weak:
        print(f"\n{CYN}  Weakest tactic coverage:{RST}")
        for tactic, v in weak:
            r = v["detected"] / max(v["executed"], 1)
            print(f"    {tactic:<28} {v['detected']}/{v['executed']}  {r * 100:.0f}%")

    if data.get("notes"):
        print(f"\n{DIM}  Reading these numbers:{RST}")
        for n in data["notes"]:
            print(f"{DIM}    · {n}{RST}")

    print(f"{CYN}{'=' * 72}{RST}")

    if args.json:
        Path(args.json).write_text(json.dumps(data, indent=2))
        print(f"  JSON report: {args.json}")
    if args.html:
        Path(args.html).write_text(driver.report(eid, "html"))
        print(f"  HTML report: {args.html}")

    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="SPARKSOC purple-team exercise driver")
    ap.add_argument("--config", default=str(Path(__file__).parent / "config.yaml"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    for name in ("replay", "live", "report"):
        p = sub.add_parser(name)
        p.add_argument("--exercise-id")
        p.add_argument("--json", help="write the JSON report here")
        p.add_argument("--html", help="write the HTML report here")
        p.add_argument("--drain", type=int, default=600,
                       help="seconds to wait for the deep queue to empty before scoring")
        if name != "report":
            p.add_argument("--plan", required=(name == "replay"))
            p.add_argument("--name")
        if name == "replay":
            p.add_argument("--step-delay", type=float, default=8.0,
                           help="default seconds between steps")
        if name == "live":
            p.add_argument("--duration", type=int, default=60, help="minutes to monitor")

    args = ap.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"{RED}Config not found: {cfg_path}{RST}")
        return 2
    driver = Driver(yaml.safe_load(cfg_path.read_text()))

    return {"replay": cmd_replay, "live": cmd_live, "report": cmd_report}[args.cmd](driver, args)


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
Throughput and latency baseline for the two Spark nodes.

Run after deployment and record the output. docs/08-RUNBOOK.md alerts against
these numbers; without a baseline "the pipeline feels slow" is unactionable.

    python3 bench.py --config config.yaml
    python3 bench.py --config config.yaml --node triage --concurrency 1,4,8,16
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import statistics
import sys
import time
from pathlib import Path

import httpx
import yaml

PROMPT = (
    "You are a SOC analyst. Summarise the following alert in two sentences and "
    "name the most likely MITRE ATT&CK technique.\n\n"
    "Process Create: Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
    "CommandLine=powershell -nop -w hidden -enc SQBFAFgA "
    "ParentImage=C:\\Windows\\System32\\wbem\\WmiPrvSE.exe User=CORP\\svc_backup "
    "Host=WIN11-RANGE-04"
)


def one_request(url: str, model: str, key: str, max_tokens: int) -> dict:
    t0 = time.perf_counter()
    with httpx.Client(timeout=600.0, headers={"Authorization": f"Bearer {key}"}) as c:
        r = c.post(f"{url.rstrip('/')}/chat/completions", json={
            "model": model, "messages": [{"role": "user", "content": PROMPT}],
            "max_tokens": max_tokens, "temperature": 0.1})
        r.raise_for_status()
        d = r.json()
    elapsed = time.perf_counter() - t0
    usage = d.get("usage", {})
    out = usage.get("completion_tokens", 0)
    return {"elapsed": elapsed, "out_tokens": out,
            "tok_s": out / elapsed if elapsed else 0,
            "empty": not (d["choices"][0]["message"].get("content") or "").strip()}


def bench(name: str, node: dict, levels: list[int], max_tokens: int) -> dict:
    print(f"\n=== {name}: {node['model']} @ {node['url']} ===")
    results = {}
    for n in levels:
        with cf.ThreadPoolExecutor(max_workers=n) as pool:
            t0 = time.perf_counter()
            futures = [pool.submit(one_request, node["url"], node["model"],
                                   node["api_key"], max_tokens) for _ in range(n)]
            rows = []
            for f in futures:
                try:
                    rows.append(f.result())
                except Exception as exc:
                    print(f"  concurrency {n}: request failed: {exc}")
            wall = time.perf_counter() - t0

        if not rows:
            continue
        empties = sum(1 for r in rows if r["empty"])
        per = [r["tok_s"] for r in rows]
        lat = [r["elapsed"] for r in rows]
        total_out = sum(r["out_tokens"] for r in rows)
        agg = total_out / wall if wall else 0

        results[n] = {
            "per_stream_tok_s": round(statistics.mean(per), 1),
            "aggregate_tok_s": round(agg, 1),
            "latency_p50_s": round(statistics.median(lat), 2),
            "latency_max_s": round(max(lat), 2),
            "empty_responses": empties,
        }
        flag = "  <-- EMPTY CONTENT (vLLM #37030)" if empties else ""
        print(f"  concurrency {n:>3}: "
              f"{results[n]['per_stream_tok_s']:>6.1f} tok/s per stream, "
              f"{results[n]['aggregate_tok_s']:>6.1f} tok/s aggregate, "
              f"p50 {results[n]['latency_p50_s']:>5.2f}s{flag}")
    return results


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(Path(__file__).parent / "config.yaml"))
    ap.add_argument("--node", default="all", choices=["all", "triage", "reason"])
    ap.add_argument("--concurrency", default="1,2,4,8")
    ap.add_argument("--max-tokens", type=int, default=256)
    ap.add_argument("--json", help="write results here")
    args = ap.parse_args()

    cfg = yaml.safe_load(Path(args.config).read_text())
    levels = [int(x) for x in args.concurrency.split(",")]
    out = {}

    for key in ("triage", "reason"):
        if args.node not in ("all", key):
            continue
        node = cfg.get("nodes", {}).get(key)
        if not node:
            print(f"(no nodes.{key} in config, skipping)")
            continue
        # Deep reasoning legitimately produces long outputs; bench it that way.
        mt = args.max_tokens if key == "triage" else max(args.max_tokens, 512)
        out[key] = bench(key, node, levels, mt)

    print("\nInterpretation:")
    print("  Per-stream tok/s should fall as concurrency rises — GB10 decode is")
    print("  bandwidth-bound. What matters is whether AGGREGATE throughput still")
    print("  climbs. The point where aggregate stops climbing is your real")
    print("  max-num-seqs ceiling, whatever the config says.")

    if args.json:
        Path(args.json).write_text(json.dumps(out, indent=2))
        print(f"\nWritten: {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

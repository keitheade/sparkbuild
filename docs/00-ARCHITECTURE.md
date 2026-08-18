# 00 — Architecture

## 1. Design constraints

| Constraint | Consequence |
|---|---|
| GB10 unified LPDDR5x, ~119 GB usable of 128 GB | Model weights, KV cache, Qdrant and page cache all draw from one pool. `--gpu-memory-utilization` fractions across co-resident vLLM processes must sum well below 1.0. |
| ~273 GB/s memory bandwidth, decode is bandwidth-bound | Throughput degrades past ~4 concurrent decode streams. `--max-num-seqs 128` is counterproductive. |
| 1 GbE interconnect only | No cross-node tensor parallelism (needs ConnectX-7). One model per node, communicating over HTTP. |
| sm_121 aarch64 is a young target | Kernel coverage is incomplete in official builds. Deployment must be gated on a smoke test, and must ship with documented fallback env toggles. |
| Airgapped | Everything — weights, images, wheels, ATT&CK data, CA certs — crosses on USB. No pip, no docker pull, no HF hub at runtime. |

## 2. Memory budget

### Spark 1 (~119 GB usable)

| Component | Allocation | Notes |
|---|---|---|
| vLLM triage — `Qwen3.5-35B-A3B` MXFP4 | `--gpu-memory-utilization 0.62` ≈ 74 GB | ~20 GB weights, remainder KV cache at 64K context |
| vLLM embed — `Qwen3-Embedding-0.6B` bf16 | `--gpu-memory-utilization 0.04` ≈ 5 GB | ~1.2 GB weights |
| Qdrant | ~6 GB host RAM | ATT&CK enterprise corpus is ~3.5 k vectors; trivial |
| OS, Docker, page cache, headroom | ~34 GB | Do not shrink below 25 GB — CUDA graph capture and fastsafetensors loading spike here |

**The two vLLM utilization fractions are independent reservations against the same pool.**
If you raise one, lower the other. `spark1/.env` enforces this with a preflight check in `init.sh`.

### Spark 2 (~119 GB usable)

| Component | Allocation | Notes |
|---|---|---|
| vLLM reason — `gpt-oss-120b` MXFP4 | `--gpu-memory-utilization 0.88` ≈ 105 GB | ~63 GB weights, remainder KV at 128K context with fp8 KV |
| OS, Docker, headroom | ~14 GB | Sole workload on this node |

## 3. Latency budget

Measured expectations on GB10. Treat as design targets, and re-baseline with
`validate/bench.py` after deployment.

| Stage | Backend | Budget | Notes |
|---|---|---|---|
| Ingest, validate, dedupe | Harness | < 50 ms | Pure Python |
| A — normalize + feature extraction | Spark 1 | 0.8–2.5 s | ~400 output tokens, JSON-schema constrained |
| B — ATT&CK retrieval | Spark 1 embed + Qdrant | 80–200 ms | Single embedding call + HNSW search |
| C — triage verdict | Spark 1 | 1.5–4 s | ~600 output tokens |
| **Fast-path total (returned to Splunk/SOAR)** | | **< 7 s p95** | This is the "real time" number |
| D — deep hypothesis validation | Spark 2 | 30–120 s | 3–6 turns, ~2–4 k output tokens total |
| D′ — evidence collection round trips | SOAR → range | 5–40 s per turn | Dominates D when evidence is requested |
| E — SOAR container + action dispatch | SOAR | 1–5 s | |

**Consequence:** the deep verdict is never awaited synchronously. The harness creates the
SOAR container immediately after stage C with the triage verdict, then amends it with a note
and updated severity when stage D completes. Consumers subscribe via
`GET /v1/case/{id}/stream` (SSE) or receive the SOAR note.

## 4. Data flow

```
Splunk saved search fires
        │
        │  TA-soc-harness custom alert action
        │  POST /v1/alert   (HMAC-SHA256, full result set, gzip)
        ▼
┌───────────────────────────────────────────────────────────────────┐
│ AGENT HARNESS (management VM)                                     │
│                                                                   │
│  auth.verify_hmac ──► models.SplunkAlert ──► dedupe fingerprint   │
│                              │                                    │
│                              ▼                                    │
│                   bounded asyncio.Queue (maxsize=512)             │
│                              │                                    │
│         ┌────────────────────┴────────────────────┐               │
│         │  N workers, per-backend semaphores      │               │
│         ▼                                          ▼              │
│   ┌───────────────────────────┐        ┌────────────────────────┐ │
│   │ STAGE A  extract features │───────►│ STAGE B  ATT&CK RAG    │ │
│   │ Spark1 :8001 json_schema  │        │ Spark1 :8002 + Qdrant  │ │
│   └───────────────────────────┘        └───────────┬────────────┘ │
│                                                     ▼             │
│                                        ┌────────────────────────┐ │
│                                        │ STAGE C  triage verdict│ │
│                                        │ Spark1 :8001           │ │
│                                        └───────────┬────────────┘ │
│                          score < threshold ────────┤              │
│                                    │                ▼             │
│                                    │   ┌────────────────────────┐ │
│                                    │   │ STAGE E1 SOAR container│ │
│                                    │   │ + artifacts (always)   │ │
│                                    │   └───────────┬────────────┘ │
│                                    │                ▼             │
│                                    │   ┌────────────────────────┐ │
│                                    │   │ STAGE D  deep reasoning│ │
│                                    │   │ Spark2 :8003, N turns  │ │
│                                    │   │   ▲                 │   │ │
│                                    │   │   │ evidence request│   │ │
│                                    │   │   └──── SOAR ◄──────┘   │ │
│                                    │   │   (COLLECT tier only)   │ │
│                                    │   └───────────┬────────────┘ │
│                                    │                ▼             │
│                                    │   ┌────────────────────────┐ │
│                                    │   │ STAGE E2 actions.py    │ │
│                                    │   │ allowlist + tier gate  │ │
│                                    │   └───────────┬────────────┘ │
│                                    │                ▼             │
│                                    │      COLLECT → dispatch      │
│                                    │      CONTAIN → approval task │
│                                    │      DENY    → audit only    │
│         ┌──────────────────────────┴───────────────┐              │
│         ▼                                          ▼              │
│   audit.py  (hash-chained JSONL)      scoring.py (exercise stats) │
└───────────────────────────────────────────────────────────────────┘
```

## 5. Why the fast path and deep path are split across nodes

The triage node must sustain burst ingestion. During a purple-team exercise, a single
Atomic Red Team chain can fire 20–60 Splunk alerts in under a minute. A 3B-active MoE at
`--max-num-seqs 16` absorbs that; a 120B dense-ish MoE at `--max-num-seqs 4` would queue for
minutes and the exercise would be over before the first verdict landed.

The reasoning node is deliberately starved of concurrency (`--max-num-seqs 4`) because on
bandwidth-bound unified memory, admitting more requests makes every request slower without
raising aggregate throughput. The harness enforces this with a semaphore of 2 so vLLM's queue
never becomes the bottleneck signal — backpressure surfaces in the harness where it can be
measured and alerted on.

## 6. Threat model

| Threat | Vector | Mitigation |
|---|---|---|
| **Prompt injection via log content** | An attacker (or purple team) writes attacker-controlled strings into a field that reaches the model — a process command line, a User-Agent, a filename — instructing it to return benign, or to request a containment action against a production host. | Primary novel risk. (a) All alert content is wrapped in delimited, explicitly-untrusted blocks with a standing instruction that content inside is data, never instruction. (b) Model output is JSON-schema constrained — it cannot emit free-form text that becomes an action. (c) Action names, assets, and targets are validated against a static allowlist and range CIDR list in `common/action_allowlist.yaml`; the model selects from an enum, it does not name things. (d) Containment requires human approval. See `harness/app/prompts.py`. |
| Model hallucinates a technique or verdict | Model error | Retrieval-grounded: stage C must cite ATT&CK IDs that appeared in stage B results; `triage.py` rejects and retries verdicts citing IDs not in the retrieved set. Exercise scoring quantifies the residual rate. |
| SOAR credential compromise from the harness | Token at rest in the harness container | Token is passed by Docker secret, never in the image; SOAR role is scoped to the range-only asset group; destructive actions are not in the allowlist at all, so a stolen token in this path still cannot isolate a production asset via the harness. |
| Replay of a captured Splunk alert POST | Network capture on the 1 GbE segment | HMAC covers a nonce and timestamp; harness rejects timestamps outside ±300 s and nonces seen in the last 24 h (Redis). |
| Model weights or images tampered on USB | Supply chain / transfer | `MANIFEST.json` carries SHA-256 for every artifact plus the resolved image digest; `verify-bundle.sh` refuses to load on mismatch. |
| Silent egress from an airgapped node | Misconfiguration | `validate/egress_check.sh` asserts no route off-enclave and that telemetry env vars are set in every running container. |

## 7. Failure modes and degradation

| Failure | Behaviour |
|---|---|
| Spark 2 unavailable | Fast path continues. Cases are marked `deep_verdict: unavailable`, SOAR container still created with triage verdict, deep queue drains to disk and replays on recovery. |
| Spark 1 unavailable | Hard stop for new alerts. Harness returns 503 to Splunk; the alert action retries with backoff (3 attempts) then writes to Splunk's own failure index so nothing is lost silently. |
| Qdrant unavailable | Stage B degrades to keyword ATT&CK lookup from the local STIX cache. Verdict is flagged `rag_degraded: true`. |
| Queue saturated (512) | Harness returns 429. Alert action backs off. Metrics expose `sparksoc_queue_depth` for alerting. |
| SOAR unavailable | Verdicts are still produced and audited; SOAR calls are queued to `state/soar_retry.jsonl` and replayed. |

## 8. Known platform risks carried into this deployment

1. **vLLM official image sm_121 aarch64 support** (vLLM #36821). Gated by
   `staging/Test-SparkSmoke.ps1`. If the gate fails, `docs/01-STAGING.md` §7 documents the
   fallback to a self-built sm_121a image.
2. **Marlin MoE shared-memory race on SM121 at TP=1 producing a null first Harmony token for
   gpt-oss** (vLLM #37030). The smoke gate asserts non-empty content on the first token.
   Mitigation toggles are in `spark2/.env.example` (`VLLM_USE_FLASHINFER_MOE_MXFP4_BF16`,
   attention/MoE backend overrides).
3. **JIT cold start ~25 s on first request.** Both `init.sh` scripts pre-warm with a
   synthetic request before marking the service healthy, so the first real alert does not
   pay it.

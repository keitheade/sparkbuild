# SPARKSOC — Airgapped Dual-DGX-Spark AI Security Operations Pipeline

Production deployment kit for a two-node NVIDIA DGX Spark (GB10 / Grace Blackwell / sm_121)
AI-assisted SOC pipeline that ingests Splunk Enterprise alerts in real time, triages them
against MITRE ATT&CK, validates attack hypotheses with a large reasoning model, and dispatches
evidence collection and containment through Splunk SOAR — entirely inside an airgapped enclave.

Purpose-built to **catch and score active purple-team simulations**, not just to summarise alerts.

---

## Topology

```
                          1 GbE management switch (airgapped enclave)
   ┌──────────────┬──────────────┬───────────────┬───────────────┬──────────────┐
   │              │              │               │               │              │
┌──┴───────┐ ┌────┴─────┐ ┌──────┴──────┐ ┌──────┴──────┐ ┌──────┴───────────┐
│ DGX      │ │ DGX      │ │  Splunk     │ │ Splunk SOAR │ │ ESXi range       │
│ Spark 1  │ │ Spark 2  │ │  Enterprise │ │             │ │ WS2022 / Win11   │
│ TRIAGE   │ │ REASON   │ │             │ │             │ │ RHEL targets     │
└──────────┘ └──────────┘ └─────────────┘ └─────────────┘ └──────────────────┘
                                  │
                          ┌───────┴────────┐
                          │ Management VM  │
                          │ agent harness  │
                          └────────────────┘
```

| Host          | Role                      | Services                                                       |
|---------------|---------------------------|----------------------------------------------------------------|
| DGX Spark 1   | Fast path                 | vLLM `Qwen3.5-35B-A3B` (MXFP4) :8001, vLLM `Qwen3-Embedding-0.6B` :8002, Qdrant :6333 |
| DGX Spark 2   | Deep path                 | vLLM `gpt-oss-120b` (MXFP4) :8003                              |
| Management VM | Orchestration             | `agent_harness` FastAPI :8080, Redis :6379, audit volume        |
| Splunk Ent.   | Detection source          | `TA-soc-harness` custom alert action                            |
| Splunk SOAR   | Response                  | WinRM + SSH assets, container/artifact/action_run API           |

Tensor parallelism across the two Sparks is **not** used — it requires a ConnectX-7 direct
link, and this enclave has only 1 GbE. Each node runs an independent model. See
[`docs/00-ARCHITECTURE.md`](docs/00-ARCHITECTURE.md).

---

## Repository layout

```
staging/          Windows 11 x86_64 staging host — download, verify, bundle for USB
spark1/           Airgapped deploy for the triage/RAG node
spark2/           Airgapped deploy for the reasoning node
harness/          FastAPI agent harness (management VM)
splunk/           TA-soc-harness custom alert action app
validate/         End-to-end validation + purple-team replay
docs/             Architecture, deployment, integration, runbook
common/           Shared schemas and the SOAR action allowlist
```

---

## Deployment order

| # | Step | Guide | Where |
|---|------|-------|-------|
| 0 | Read architecture, confirm memory/latency budgets | [`docs/00-ARCHITECTURE.md`](docs/00-ARCHITECTURE.md) | — |
| 1 | Stage models, images, ATT&CK data, wheels; **pass the smoke gate** | [`docs/01-STAGING.md`](docs/01-STAGING.md) | Windows 11 host |
| 2 | Deploy Spark 1, ingest ATT&CK into Qdrant | [`docs/02-SPARK1-DEPLOY.md`](docs/02-SPARK1-DEPLOY.md) | DGX Spark 1 |
| 3 | Deploy Spark 2, validate Harmony output | [`docs/03-SPARK2-DEPLOY.md`](docs/03-SPARK2-DEPLOY.md) | DGX Spark 2 |
| 4 | Deploy agent harness | [`docs/04-HARNESS-DEPLOY.md`](docs/04-HARNESS-DEPLOY.md) | Management VM |
| 5 | Wire Splunk Enterprise alerting | [`docs/05-SPLUNK-INTEGRATION.md`](docs/05-SPLUNK-INTEGRATION.md) | Splunk |
| 6 | Configure SOAR assets and allowlist | [`docs/06-SOAR-INTEGRATION.md`](docs/06-SOAR-INTEGRATION.md) | Splunk SOAR |
| 7 | Validate end-to-end, run purple-team exercise | [`docs/07-VALIDATION.md`](docs/07-VALIDATION.md) | Management VM |
| 8 | Operate | [`docs/08-RUNBOOK.md`](docs/08-RUNBOOK.md) | — |

---

## Decisions baked into this build

These were chosen deliberately; each has a documented alternative.

1. **vLLM image: `vllm/vllm-openai:cu130-nightly`, pinned by digest at staging time.**
   Official provenance. Risk: sm_121 aarch64 kernel support in official builds is not
   guaranteed (vLLM issue #36821), and nightly tags move. Mitigated by a mandatory
   staging smoke gate (`staging/Test-SparkSmoke.ps1`) that must pass before USB transfer,
   and by pinning the resolved digest into `MANIFEST.json`.

2. **Spark 1 runs `Qwen3.5-35B-A3B` (MoE, ~3B active) rather than a 27B dense.**
   ~70 tok/s measured on GB10 with far better batched throughput on short structured
   triage outputs. Proven on this silicon.

3. **Embeddings are served by a second vLLM instance, not TEI.**
   HF Text Embeddings Inference has no Blackwell support (issue #652) and no
   aarch64/sm_121 image. Reusing the already-validated vLLM container removes an entire
   class of deployment risk. `Qwen3-Embedding-0.6B`, ~2 GB.

4. **SOAR autonomy is tiered.** Read-only evidence collection dispatches automatically;
   anything that changes state on a range target requires human approval. Enforced in
   `common/action_allowlist.yaml`, not in a prompt.

5. **Deep reasoning is asynchronous.** A 120B model on a Spark produces a multi-turn
   verdict in 30–120 s. Triage returns in seconds; the deep verdict arrives by callback,
   SSE, or SOAR note. There is no synchronous path that blocks on Spark 2.

---

## Quick reference

```bash
# Spark 1
cd /opt/sparksoc/spark1 && docker compose up -d && ./init.sh

# Spark 2
cd /opt/sparksoc/spark2 && docker compose up -d && ./init.sh

# Management VM
cd /opt/sparksoc/harness && docker compose up -d

# End-to-end validation
python3 validate/e2e_test.py --config validate/config.yaml

# Purple-team exercise
curl -XPOST http://harness:8080/v1/exercise/start -d '{"name":"PT-2026-08"}'
#   ... run the simulation ...
curl -XPOST http://harness:8080/v1/exercise/PT-2026-08/stop
curl http://harness:8080/v1/exercise/PT-2026-08/report?format=html -o report.html
```

---

## Security posture

- No component initiates outbound connections beyond the enclave. Telemetry is disabled at
  the container level (`VLLM_NO_USAGE_STATS`, `DO_NOT_TRACK`, `HF_HUB_OFFLINE`).
- Splunk → harness traffic is HMAC-SHA256 signed with replay protection.
- Harness → SOAR uses `ph-auth-token` over TLS with a pinned CA bundle.
- Every model-proposed action is schema-validated against a static allowlist before dispatch.
  The model cannot invent an action name, an asset, or a target outside the range CIDRs.
- All decisions are written to a hash-chained audit log (`harness/app/audit.py`).

See [`docs/00-ARCHITECTURE.md`](docs/00-ARCHITECTURE.md#threat-model) for the threat model,
including prompt-injection-via-log-content, which is the primary novel risk in this design.

# 03 — DGX Spark 2 deployment (deep path)

`gpt-oss-120b` in MXFP4 as the sole workload on this node.

---

## 1. Before you start

Spark 1 must be healthy. The harness will not produce useful deep verdicts
without triage output to reason about, and `init.sh` here does not depend on
Spark 1 — but deploying in the other order means debugging two things at once.

Apply the same NTP configuration as Spark 1 ([`02-SPARK1-DEPLOY.md`](02-SPARK1-DEPLOY.md) §1).

```bash
nvidia-smi --query-gpu=name,compute_cap,memory.total --format=csv
awk '/MemAvailable/ {printf "%.0f GB available\n", $2/1048576}' /proc/meminfo
```

You want at least 100 GB available. This node runs one thing.

---

## 2. Load the bundle

```bash
sudo mkdir -p /opt/sparksoc && sudo chown -R "$USER" /opt/sparksoc
cd /media/usb/sparksoc
bash verify-bundle.sh
sudo /opt/sparksoc/code/spark2/load-bundle.sh /media/usb/sparksoc
```

The gpt-oss-120b extraction moves ~65 GB. Expect 10–20 minutes from USB 3.

---

## 3. Configure

```bash
cd /opt/sparksoc/code/spark2
cp .env.example .env && chmod 600 .env
$EDITOR .env
```

`VLLM_API_KEY` **must match Spark 1 and the harness.** The harness uses one key
per node but the deployment is simpler if they are identical; if you use
different keys, set `SPARK2_API_KEY` accordingly in the harness secrets.

| Variable | Default | Note |
|---|---|---|
| `GPU_UTIL_REASON` | `0.88` | ~105 GB of ~119 GB usable. Do not exceed 0.90 — CUDA graph capture spikes outside vLLM's reservation. |
| `REASON_MAX_SEQS` | `4` | Deliberate. The harness holds a semaphore of 2 on top so backpressure is visible in metrics rather than buried in the vLLM queue. |
| `REASON_MAX_LEN` | `131072` | Multi-turn reasoning with collected evidence gets long. |
| `REASON_PARSER_ARGS` | `--reasoning-parser openai_gptoss` | **Verify this name** — see §4. |

There is no BF16 fallback on this node. gpt-oss-120b in BF16 is ~240 GB; it does
not fit in 128 GB. If MXFP4 cannot work on this image, the options are to fix the
image ([`01-STAGING.md`](01-STAGING.md) §7) or to run without a deep path.

---

## 4. Confirm the reasoning parser name

gpt-oss emits the Harmony format with separate analysis and final channels. The
vLLM flag for it has changed across releases. A wrong name fails loudly at
startup, so this is a two-minute check that saves a confusing hour:

```bash
source .env
docker run --rm --entrypoint vllm "$VLLM_IMAGE" serve --help \
  | grep -A 25 -i 'reasoning-parser'
```

Set `REASON_PARSER_ARGS` to whichever of `openai_gptoss`, `gpt_oss`, or `openai`
appears. If none do, set `REASON_PARSER_ARGS=` and `REASON_TOOL_ARGS=` — the
harness parses JSON out of the content channel and does not require vLLM to
split the channels for it.

---

## 5. Start

```bash
docker compose up -d
docker compose logs -f vllm-reason
./init.sh
```

**A cold start of 15–25 minutes is normal.** 65 GB of weights plus JIT
compilation plus CUDA graph capture. `init.sh` waits up to 2400 s.

### What init.sh proves

| Step | Check |
|---|---|
| 1 | host preflight — GPU, memory, model shards present |
| 2 | vLLM becomes healthy |
| 3 | served model name is `soc-reason` |
| 4 | **five consecutive non-empty completions** |
| 5 | JSON-schema-constrained output parses |
| 6 | multi-turn coherence + a recorded tok/s baseline |
| 7 | pre-warm |

**Step 4 runs five times on purpose.** The SM121 Marlin MoE race (vLLM #37030) is
nondeterministic. One successful response does not clear it. If any of the five
returns empty content, `init.sh` fails with the mitigation list rather than
letting you deploy a node that silently produces nothing.

The tok/s baseline is written to `/opt/sparksoc/state/spark2-baseline.json`.
Keep it — [`08-RUNBOOK.md`](08-RUNBOOK.md) alerts against it.

Expected: 40–80 tok/s single-stream for MXFP4 gpt-oss-120b on one GB10. Below
15 tok/s, MXFP4 probably did not take effect:

```bash
docker compose logs vllm-reason | grep -i -E 'quant|mxfp4|marlin|awq'
```

---

## 6. Verify

```bash
export VLLM_API_KEY=$(grep ^VLLM_API_KEY .env | cut -d= -f2)

curl -s -H "Authorization: Bearer $VLLM_API_KEY" -H 'Content-Type: application/json' \
  http://127.0.0.1:8003/v1/chat/completions -d '{
    "model":"soc-reason",
    "messages":[{"role":"user","content":"A host ran encoded PowerShell spawned by WmiPrvSE. Which ATT&CK techniques apply and what evidence would confirm?"}],
    "max_tokens":500,"temperature":0.2}' \
  | python3 -c '
import sys,json
d=json.load(sys.stdin); m=d["choices"][0]["message"]; u=d["usage"]
print("content chars   :", len(m.get("content") or ""))
print("reasoning chars :", len(m.get("reasoning_content") or ""))
print("completion toks :", u["completion_tokens"])
print()
print((m.get("content") or "")[:800])'

bash /opt/sparksoc/code/validate/egress_check.sh
```

If `content chars` is 0 while `reasoning chars` is large, the model spent its
whole budget in the analysis channel — raise `max_tokens`. If both are 0, that
is the kernel fault, not a budget problem.

---

## 7. Install the service

```bash
sudo cp systemd/sparksoc-spark2.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sparksoc-spark2
```

`TimeoutStartSec=2700`. Do not shorten it — systemd killing a 20-minute model
load halfway through looks exactly like a crash loop.

---

## 8. Troubleshooting

| Symptom | Meaning | Action |
|---|---|---|
| `init.sh` step 4 fails on any of 5 | SM121 Marlin MoE race | in order: `VLLM_USE_FLASHINFER_MOE_MXFP4_BF16=1`, `VLLM_MARLIN_USE_ATOMIC_ADD=1`, `VLLM_ATTENTION_BACKEND=FLASH_ATTN`; then `01-STAGING.md` §7 |
| container killed during load | host OOM | lower `GPU_UTIL_REASON` to 0.85; stop other workloads |
| startup error naming the reasoning parser | wrong flag value | §4 |
| < 15 tok/s | MXFP4 not applied | check logs for the quantization line |
| verdicts truncate mid-JSON | reasoning channel consumed the budget | raise `max_tokens` for the deep verdict call (harness `pipeline.py`, `_run_deep`) |
| healthcheck flaps under load | 30 s interval vs. a busy scheduler | acceptable; the harness does not use the Docker healthcheck for routing |

---

## 9. Next

[`04-HARNESS-DEPLOY.md`](04-HARNESS-DEPLOY.md)

#!/usr/bin/env bash
# =============================================================================
# SPARKSOC — Spark 2 initialisation and validation
#
# The single most important thing this script does is prove that gpt-oss-120b
# actually EMITS TOKENS on sm_121. A broken Marlin MoE kernel (vLLM #37030)
# returns HTTP 200 with null content and finish_reason "stop". Every health
# check passes. The pipeline then silently produces no deep verdicts, and you
# find out during the purple-team exercise.
#
# Idempotent. Safe to re-run.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
log()  { printf '%s[%s]%s %s\n' "$CYN" "$(date +%H:%M:%S)" "$RST" "$*"; }
ok()   { printf '%s  OK  %s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s WARN %s %s\n' "$YLW" "$RST" "$*"; }
die()  { printf '%s FAIL %s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

[[ -f .env ]] || die ".env not found. cp .env.example .env and edit it."
set -a; . ./.env; set +a
[[ "$VLLM_API_KEY" == CHANGEME* ]] && die "VLLM_API_KEY is still the placeholder."

URL="http://127.0.0.1:8003"
AUTH=(-H "Authorization: Bearer ${VLLM_API_KEY}")
JSON=(-H 'Content-Type: application/json')

# =============================================================================
log "STEP 1 — host preflight"
# =============================================================================
if command -v nvidia-smi >/dev/null 2>&1; then
  nvidia-smi --query-gpu=name,compute_cap,memory.total,memory.used --format=csv
  cc=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | head -1 | tr -d ' ')
  [[ "$cc" == "12.1" ]] || warn "compute_cap ${cc}, expected 12.1 for GB10"
fi

avail_gb=$(awk '/MemAvailable/ {printf "%.0f", $2/1048576}' /proc/meminfo)
log "host MemAvailable: ${avail_gb} GB"
(( avail_gb > 70 )) || warn "Less than 70 GB available. Model load may thrash. Stop other workloads."

model_dir="${MODEL_ROOT}/${REASON_MODEL_DIR}"
[[ -f "${model_dir}/config.json" ]] || die "No config.json at ${model_dir}"
shards=$(find "$model_dir" -name '*.safetensors' | wc -l)
size=$(du -sh "$model_dir" | cut -f1)
ok "model present: ${shards} shards, ${size}"

# =============================================================================
log "STEP 2 — waiting for vLLM (cold start of 15-25 min is normal here)"
# =============================================================================
timeout=${STARTUP_TIMEOUT:-2400}
elapsed=0
while (( elapsed < timeout )); do
  if curl -sf -m 5 "${AUTH[@]}" "${URL}/health" >/dev/null 2>&1; then
    ok "health endpoint responding after ${elapsed}s"
    break
  fi
  if ! docker ps --format '{{.Names}}' | grep -q sparksoc-vllm-reason; then
    echo "--- container exited; last 80 log lines ---" >&2
    docker compose logs --tail 80 >&2
    die "vllm-reason container is not running"
  fi
  sleep 15; elapsed=$((elapsed+15))
  if (( elapsed % 120 == 0 )); then
    loaded=$(docker compose logs --tail 5 vllm-reason 2>/dev/null | tail -1 | cut -c1-110)
    log "  ... ${elapsed}s   ${loaded}"
  fi
done
(( elapsed < timeout )) || { docker compose logs --tail 80 >&2; die "vLLM did not become healthy in ${timeout}s"; }

# =============================================================================
log "STEP 3 — model identity"
# =============================================================================
models=$(curl -sf -m 15 "${AUTH[@]}" "${URL}/v1/models") || die "/v1/models failed"
served=$(printf '%s' "$models" | python3 -c 'import sys,json;print(",".join(m["id"] for m in json.load(sys.stdin)["data"]))')
log "served models: ${served}"
[[ "$served" == *"soc-reason"* ]] || die "expected served-model-name 'soc-reason', got '${served}'"
ok "model identity confirmed"

# =============================================================================
log "STEP 4 — NULL CONTENT CHECK (vLLM #37030)"
# =============================================================================
# Run this several times. The Marlin MoE race is nondeterministic: a single
# successful response does not clear it.

fail_count=0
for attempt in 1 2 3 4 5; do
  resp=$(curl -sf -m 240 "${AUTH[@]}" "${JSON[@]}" "${URL}/v1/chat/completions" -d '{
      "model": "soc-reason",
      "messages": [{"role":"user","content":"Reply with exactly one word: ALIVE"}],
      "max_tokens": 24, "temperature": 0
    }') || die "completion request failed on attempt ${attempt}"

  content=$(printf '%s' "$resp" | python3 -c '
import sys, json
d = json.load(sys.stdin)
m = d["choices"][0]["message"]
# Harmony puts chain-of-thought on reasoning_content and the answer on content.
print((m.get("content") or "").strip())
')
  reasoning=$(printf '%s' "$resp" | python3 -c '
import sys, json
d = json.load(sys.stdin)
print(len((d["choices"][0]["message"].get("reasoning_content") or "")))
')
  finish=$(printf '%s' "$resp" | python3 -c 'import sys,json;print(json.load(sys.stdin)["choices"][0]["finish_reason"])')

  if [[ -z "$content" ]]; then
    warn "attempt ${attempt}: EMPTY content (finish=${finish}, reasoning_chars=${reasoning})"
    fail_count=$((fail_count+1))
  else
    log "attempt ${attempt}: '${content}' (finish=${finish}, reasoning_chars=${reasoning})"
  fi
done

if (( fail_count > 0 )); then
  die "gpt-oss returned EMPTY content on ${fail_count}/5 attempts.

  This is vLLM #37030 — the SM121 Marlin MoE 256-thread shared-memory race.
  It is a kernel bug, not a prompt or configuration error.

  Edit .env, then: docker compose up -d --force-recreate && ./init.sh
    1. VLLM_USE_FLASHINFER_MOE_MXFP4_BF16=1
    2. VLLM_MARLIN_USE_ATOMIC_ADD=1
    3. VLLM_ATTENTION_BACKEND=FLASH_ATTN

  If all three fail, the image lacks a usable MXFP4 MoE path for sm_121.
  See docs/01-STAGING.md section 7 for the self-build fallback.

  DO NOT proceed to harness deployment with this unresolved. The deep path
  will silently return nothing and every case will fall back to triage only."
fi
ok "5/5 non-empty completions — MoE kernel path is sound"

# =============================================================================
log "STEP 5 — structured output (the harness requires JSON-schema decoding)"
# =============================================================================
resp=$(curl -sf -m 300 "${AUTH[@]}" "${JSON[@]}" "${URL}/v1/chat/completions" -d '{
    "model": "soc-reason",
    "messages": [{"role":"user","content":"A host ran: powershell -nop -w hidden -enc <base64>. Assess it."}],
    "max_tokens": 512, "temperature": 0,
    "response_format": {"type":"json_schema","json_schema":{"name":"verdict","strict":true,"schema":{
      "type":"object",
      "properties":{
        "verdict":{"type":"string","enum":["benign","suspicious","malicious"]},
        "confidence":{"type":"number"},
        "technique_ids":{"type":"array","items":{"type":"string"}}
      },
      "required":["verdict","confidence","technique_ids"],
      "additionalProperties":false}}}
  }') || die "structured output request failed"

parsed=$(printf '%s' "$resp" | python3 -c '
import sys, json
d = json.load(sys.stdin)
c = d["choices"][0]["message"].get("content") or ""
try:
    v = json.loads(c)
except Exception:
    print("PARSE_FAIL"); raise SystemExit
print(f"{v.get(\"verdict\")}|{v.get(\"confidence\")}|{\",\".join(v.get(\"technique_ids\", []))}")
')
[[ "$parsed" == "PARSE_FAIL" || -z "$parsed" ]] && die "structured output did not yield valid JSON.
  The harness constrains every deep-reasoning call with a JSON schema.
  Check that guided decoding (xgrammar) is available in this build."
ok "structured output: ${parsed}"

# =============================================================================
log "STEP 6 — multi-turn coherence and throughput baseline"
# =============================================================================
# The deep path is multi-turn. Prove the model holds context across turns and
# measure tok/s so docs/08-RUNBOOK.md has a real baseline to alert against.

start=$(date +%s%N)
resp=$(curl -sf -m 600 "${AUTH[@]}" "${JSON[@]}" "${URL}/v1/chat/completions" -d '{
    "model": "soc-reason",
    "messages": [
      {"role":"system","content":"You are a SOC analyst. Be concise and specific."},
      {"role":"user","content":"Host WIN11-RANGE-04: powershell.exe spawned by wbem/WmiPrvSE.exe with -enc. What ATT&CK techniques are implicated?"},
      {"role":"assistant","content":"T1047 (WMI) for the parent, T1059.001 (PowerShell) and T1027 (obfuscation) for the child."},
      {"role":"user","content":"Given that, name the single highest-value next evidence artifact to collect and say why in one sentence."}
    ],
    "max_tokens": 400, "temperature": 0.2
  }') || die "multi-turn request failed"
elapsed_ms=$(( ($(date +%s%N) - start) / 1000000 ))

out_tokens=$(printf '%s' "$resp" | python3 -c 'import sys,json;print(json.load(sys.stdin)["usage"]["completion_tokens"])')
text=$(printf '%s' "$resp" | python3 -c 'import sys,json;m=json.load(sys.stdin)["choices"][0]["message"];print((m.get("content") or "").strip()[:300])')
tps=$(awk -v t="$out_tokens" -v ms="$elapsed_ms" 'BEGIN{printf "%.1f", t/(ms/1000)}')

log "response: ${text}"
ok "multi-turn OK — ${out_tokens} tokens in ${elapsed_ms} ms (${tps} tok/s)"

if (( $(awk -v x="$tps" 'BEGIN{print (x<15)?1:0}') )); then
  warn "Throughput ${tps} tok/s is below the ~40-80 tok/s expected for MXFP4 on GB10."
  warn "Check that --quantization mxfp4 took effect: docker compose logs vllm-reason | grep -i quant"
fi

# =============================================================================
log "STEP 7 — pre-warm"
# =============================================================================
for i in 1 2; do
  curl -sf -m 600 "${AUTH[@]}" "${JSON[@]}" "${URL}/v1/chat/completions" -d '{
    "model":"soc-reason",
    "messages":[{"role":"user","content":"Summarise the Windows lateral movement kill chain in two sentences."}],
    "max_tokens":200,"temperature":0}' >/dev/null || warn "warmup ${i} failed"
  log "  warmup ${i} done"
done

# Record the baseline for the runbook
mkdir -p /opt/sparksoc/state
cat > /opt/sparksoc/state/spark2-baseline.json <<JSON
{
  "recorded_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "model": "soc-reason",
  "quantization": "${REASON_QUANT_ARGS}",
  "max_model_len": ${REASON_MAX_LEN},
  "max_num_seqs": ${REASON_MAX_SEQS},
  "single_stream_tok_per_sec": ${tps},
  "multiturn_latency_ms": ${elapsed_ms},
  "null_content_failures_of_5": ${fail_count}
}
JSON

ok "Spark 2 initialisation complete"
cat <<EOF

  reasoning   ${URL}/v1   model: soc-reason
  baseline    /opt/sparksoc/state/spark2-baseline.json  (${tps} tok/s)

  Next: docs/04-HARNESS-DEPLOY.md

EOF

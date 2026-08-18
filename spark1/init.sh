#!/usr/bin/env bash
# =============================================================================
# SPARKSOC — Spark 1 initialisation and validation
#
# Run AFTER `docker compose up -d`. This script:
#   1. validates the memory budget in .env before you discover it via OOM
#   2. waits for real generative readiness, not just /health
#   3. catches the SM121 empty-completion failure mode (vLLM #37030)
#   4. verifies the embedding dimension matches what Qdrant will be built for
#   5. pre-warms both models so the first real alert does not pay JIT cost
#   6. ingests MITRE ATT&CK into Qdrant if the collection is absent
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

: "${VLLM_API_KEY:?VLLM_API_KEY unset}"
[[ "$VLLM_API_KEY" == CHANGEME* ]] && die "VLLM_API_KEY is still the placeholder. Generate one: openssl rand -hex 32"
[[ "$QDRANT_API_KEY" == CHANGEME* ]] && die "QDRANT_API_KEY is still the placeholder."

TRIAGE_URL="http://127.0.0.1:8001"
EMBED_URL="http://127.0.0.1:8002"
QDRANT_URL="http://127.0.0.1:6333"
AUTH=(-H "Authorization: Bearer ${VLLM_API_KEY}")

# =============================================================================
log "STEP 1 — memory budget preflight"
# =============================================================================
sum=$(awk -v a="${GPU_UTIL_TRIAGE:-0.62}" -v b="${GPU_UTIL_EMBED:-0.04}" 'BEGIN{printf "%.3f", a+b}')
ceiling=0.80
if (( $(awk -v s="$sum" -v c="$ceiling" 'BEGIN{print (s>c)?1:0}') )); then
  die "GPU_UTIL_TRIAGE + GPU_UTIL_EMBED = ${sum} exceeds the ${ceiling} ceiling.
     Both reserve from the same 128 GB unified pool. Leave >=20% for the OS,
     Qdrant, page cache, and CUDA graph capture. See docs/00-ARCHITECTURE.md."
fi
ok "memory budget ${sum} / ${ceiling}"

if command -v nvidia-smi >/dev/null 2>&1; then
  cc=$(nvidia-smi --query-gpu=compute_cap --format=csv,noheader | head -1 | tr -d ' ')
  gpu=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)
  log "GPU: ${gpu} (compute capability ${cc})"
  [[ "$cc" == "12.1" ]] || warn "compute_cap is ${cc}, expected 12.1 for GB10."
fi

# =============================================================================
log "STEP 2 — waiting for services"
# =============================================================================
wait_health() {
  local name=$1 url=$2 timeout=${3:-900} elapsed=0
  log "waiting for ${name} (up to ${timeout}s; cold start includes JIT + weight load)"
  while (( elapsed < timeout )); do
    if curl -sf -m 5 "${AUTH[@]}" "${url}/health" >/dev/null 2>&1; then
      ok "${name} health endpoint responding after ${elapsed}s"; return 0
    fi
    if ! docker compose ps --status running --format '{{.Service}}' | grep -q .; then
      die "no containers running — check: docker compose logs"
    fi
    sleep 10; elapsed=$((elapsed+10))
    (( elapsed % 60 == 0 )) && log "  ... ${elapsed}s"
  done
  echo "--- last 60 log lines ---" >&2
  docker compose logs --tail 60 >&2
  die "${name} did not become healthy within ${timeout}s"
}

wait_health "vllm-triage" "$TRIAGE_URL" 900
wait_health "vllm-embed"  "$EMBED_URL"  300

until curl -sf -m 5 -H "api-key: ${QDRANT_API_KEY}" "${QDRANT_URL}/readyz" >/dev/null 2>&1; do
  sleep 3
done
ok "qdrant ready"

# =============================================================================
log "STEP 3 — generative validation (the check /health cannot do)"
# =============================================================================
# A vLLM instance with broken sm_121 MoE kernels returns HTTP 200 with EMPTY
# content. /health passes. Everything downstream silently produces nothing.
# This is vLLM #37030. Catch it here.

resp=$(curl -sf -m 180 "${AUTH[@]}" -H 'Content-Type: application/json' \
  "${TRIAGE_URL}/v1/chat/completions" -d '{
    "model": "soc-triage",
    "messages": [{"role":"user","content":"Reply with exactly: ALIVE"}],
    "max_tokens": 16, "temperature": 0
  }') || die "triage completion request failed — see: docker compose logs vllm-triage"

content=$(printf '%s' "$resp" | python3 -c 'import sys,json; print((json.load(sys.stdin)["choices"][0]["message"].get("content") or "").strip())')

if [[ -z "$content" ]]; then
  die "TRIAGE MODEL RETURNED EMPTY CONTENT.

  This is the sm_121 Marlin MoE shared-memory race (vLLM #37030), not a
  configuration error. HTTP 200 with null content is its signature.

  Try, in order, editing .env and restarting (docker compose up -d --force-recreate):
    1. VLLM_USE_FLASHINFER_MOE_MXFP4_BF16=1
    2. TRIAGE_QUANT_ARGS=          and  GPU_UTIL_TRIAGE=0.75   (serve BF16)
    3. VLLM_ATTENTION_BACKEND=FLASH_ATTN
  If none work, the image lacks usable sm_121 MoE kernels — see
  docs/01-STAGING.md section 7 for the self-build fallback."
fi
ok "triage generative check passed: '${content}'"

# ---- structured output check: the pipeline depends on JSON schema guidance --
resp=$(curl -sf -m 180 "${AUTH[@]}" -H 'Content-Type: application/json' \
  "${TRIAGE_URL}/v1/chat/completions" -d '{
    "model": "soc-triage",
    "messages": [{"role":"user","content":"Return the severity of a failed logon storm."}],
    "max_tokens": 128, "temperature": 0,
    "response_format": {"type":"json_schema","json_schema":{"name":"sev","strict":true,"schema":{
      "type":"object","properties":{"severity":{"type":"string","enum":["low","medium","high","critical"]}},
      "required":["severity"],"additionalProperties":false}}}
  }') || die "structured-output request failed. The harness requires JSON-schema constrained decoding."

sev=$(printf '%s' "$resp" | python3 -c 'import sys,json;d=json.load(sys.stdin);print(json.loads(d["choices"][0]["message"]["content"]).get("severity",""))' 2>/dev/null || true)
[[ -n "$sev" ]] || die "structured output did not return valid JSON matching the schema.
  The harness constrains every model call this way. Check that this vLLM build
  has guided decoding (xgrammar/outlines) available."
ok "structured output check passed: severity=${sev}"

# =============================================================================
log "STEP 4 — embedding dimension verification"
# =============================================================================
emb=$(curl -sf -m 60 "${AUTH[@]}" -H 'Content-Type: application/json' \
  "${EMBED_URL}/v1/embeddings" \
  -d '{"model":"soc-embed","input":["T1059.001 PowerShell command and scripting interpreter"]}') \
  || die "embedding request failed"

dim=$(printf '%s' "$emb" | python3 -c 'import sys,json; print(len(json.load(sys.stdin)["data"][0]["embedding"]))')
log "embedding dimension reported by the server: ${dim}"

if [[ "${EMBED_DIM:-}" != "$dim" ]]; then
  warn "EMBED_DIM in .env is '${EMBED_DIM:-unset}' but the server returns ${dim}."
  warn "Updating .env to match — Qdrant collection geometry must be exact."
  if grep -q '^EMBED_DIM=' .env; then
    sed -i "s/^EMBED_DIM=.*/EMBED_DIM=${dim}/" .env
  else
    echo "EMBED_DIM=${dim}" >> .env
  fi
  export EMBED_DIM="$dim"
fi
ok "embedding dimension ${dim}"

# =============================================================================
log "STEP 5 — pre-warm (absorb JIT so the first real alert does not)"
# =============================================================================
# First request after start triggers ~25 s of JIT compilation and CUDA graph
# capture. Do it now, deliberately, with a representative payload shape.
warm_payload=$(python3 - <<'PY'
import json
sample = ("Process Create: Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
          "CommandLine=powershell -nop -w hidden -enc SQBFAFgA ParentImage=C:\\Windows\\System32\\wbem\\WmiPrvSE.exe "
          "User=CORP\\svc_backup Host=WIN11-RANGE-04") * 12
print(json.dumps({
    "model": "soc-triage",
    "messages": [{"role": "user", "content": "Summarise in one sentence:\n" + sample}],
    "max_tokens": 256, "temperature": 0
}))
PY
)
for i in 1 2 3; do
  start=$(date +%s%N)
  curl -sf -m 300 "${AUTH[@]}" -H 'Content-Type: application/json' \
    "${TRIAGE_URL}/v1/chat/completions" -d "$warm_payload" >/dev/null || warn "warmup $i failed"
  ms=$(( ($(date +%s%N) - start) / 1000000 ))
  log "  triage warmup ${i}: ${ms} ms"
done
curl -sf -m 60 "${AUTH[@]}" -H 'Content-Type: application/json' "${EMBED_URL}/v1/embeddings" \
  -d '{"model":"soc-embed","input":["warmup"]}' >/dev/null
ok "pre-warm complete"

# =============================================================================
log "STEP 6 — MITRE ATT&CK ingestion"
# =============================================================================
collection="${QDRANT_COLLECTION:-attack_enterprise}"
exists=$(curl -sf -m 10 -H "api-key: ${QDRANT_API_KEY}" \
  "${QDRANT_URL}/collections/${collection}" -o /dev/null -w '%{http_code}' || echo 000)

if [[ "$exists" == "200" ]]; then
  count=$(curl -sf -H "api-key: ${QDRANT_API_KEY}" \
    "${QDRANT_URL}/collections/${collection}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["result"]["points_count"])')
  ok "collection '${collection}' already exists with ${count} points"
  log "  to rebuild: python3 attack_ingest.py --recreate"
else
  log "collection '${collection}' absent — ingesting ATT&CK STIX"
  [[ -f "${ATTACK_STIX_PATH:?}" ]] || die "ATT&CK bundle not found at ${ATTACK_STIX_PATH}"
  if [[ -d ./venv ]]; then . ./venv/bin/activate; fi
  python3 attack_ingest.py
fi

# =============================================================================
ok "Spark 1 initialisation complete"
# =============================================================================
cat <<EOF

  triage      ${TRIAGE_URL}/v1   model: soc-triage
  embeddings  ${EMBED_URL}/v1    model: soc-embed   dim: ${EMBED_DIM}
  qdrant      ${QDRANT_URL}      collection: ${collection}

  Next: docs/03-SPARK2-DEPLOY.md

EOF

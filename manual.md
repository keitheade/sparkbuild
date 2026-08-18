# Manual staging — no PowerShell orchestrator

Everything `Stage-SOCBundle.ps1` does, as commands you run yourself.

Works on any machine with Docker + Python: Windows (`pwsh`), Linux, or macOS.
Where the shells differ, both are shown. Total download ~150 GB.

---

## 0. Prerequisites

```bash
pip install -U "huggingface_hub[cli,hf_transfer]"
export HF_HUB_ENABLE_HF_TRANSFER=1          # much faster on large repos
export HF_TOKEN=hf_your_token_here
```

Windows PowerShell:

```powershell
pip install -U "huggingface_hub[cli,hf_transfer]"
$env:HF_HUB_ENABLE_HF_TRANSFER = "1"
$env:HF_TOKEN = "hf_your_token_here"
```

**Docker Desktop → Settings → General → "Use containerd for pulling and storing
images" must be ON.** You are pulling ARM images on an x86 machine. Without this
setting Docker can store the x86 variant instead and you find out on the Spark.

Accept the licences on each model page while logged in, or the downloads 401:
- https://huggingface.co/Qwen/Qwen3.5-35B-A3B
- https://huggingface.co/Qwen/Qwen3-Embedding-0.6B
- https://huggingface.co/openai/gpt-oss-120b

Pick a working directory with ~350 GB free. These instructions assume
`/data/staging` (Linux) or `D:\staging` (Windows).

---

## 1. Download the models

```bash
mkdir -p /data/staging/models && cd /data/staging/models

# Spark 1 — triage (~70 GB)
hf download Qwen/Qwen3.5-35B-A3B \
    --local-dir Qwen3.5-35B-A3B \
    --max-workers 8 \
    --exclude "*.pth" "*.msgpack" "*.h5" "original/*"

# Spark 1 — embeddings (~2 GB)
hf download Qwen/Qwen3-Embedding-0.6B \
    --local-dir Qwen3-Embedding-0.6B \
    --max-workers 8 \
    --exclude "*.pth" "*.msgpack" "*.h5" "onnx/*" "*.gguf"

# Spark 2 — deep reasoning (~65 GB)
hf download openai/gpt-oss-120b \
    --local-dir gpt-oss-120b \
    --max-workers 8 \
    --exclude "*.pth" "*.msgpack" "*.h5" "metal/*" "original/*"
```

`hf download` is resumable — if it dies, run the same command again.

`--local-dir` matters: it produces a plain directory tree. The default HF cache
uses symlinks, which do not survive tar and USB transfer.

### Verify each download

An incomplete shard set produces a model that loads and generates confident
nonsense, so check rather than assume:

```bash
cd /data/staging/models
for d in Qwen3.5-35B-A3B Qwen3-Embedding-0.6B gpt-oss-120b; do
  echo "=== $d ==="
  test -f "$d/config.json" || echo "  MISSING config.json"
  echo "  shards: $(find "$d" -name '*.safetensors' | wc -l)   size: $(du -sh "$d" | cut -f1)"
  python3 - "$d" <<'PY'
import json, os, sys
d = sys.argv[1]
idx = os.path.join(d, "model.safetensors.index.json")
if os.path.exists(idx):
    want = set(json.load(open(idx))["weight_map"].values())
    have = set(os.listdir(d))
    missing = want - have
    print(f"  index: {len(want)} shards expected, {len(missing)} missing"
          + (f" -> {sorted(missing)[:3]}" if missing else " (complete)"))
cfg = json.load(open(os.path.join(d, "config.json")))
q = cfg.get("quantization_config", {}).get("quant_method")
print(f"  quantization_config: {q or 'none (full precision)'}")
PY
done
```

If `quantization_config` shows a method, **do not** pass `--quantization` on the
vLLM command line for that model — vLLM reads it from the checkpoint, and the
flag forces a conflicting online-quantization path.

---

## 2. Download the container images

```bash
mkdir -p /data/staging/images && cd /data/staging/images

for ref in \
  "vllm/vllm-openai:cu130-nightly|vllm" \
  "qdrant/qdrant:v1.12.4|qdrant" \
  "python:3.11-slim|python" \
  "redis:7.4-alpine|redis"
do
  image="${ref%%|*}"; alias="${ref##*|}"
  echo "=== $alias : $image ==="

  # Confirm the tag actually publishes linux/arm64 before pulling
  docker buildx imagetools inspect "$image" --raw \
    | python3 -c 'import sys,json;d=json.load(sys.stdin);print("  platforms:", ", ".join(sorted({f"{m[\"platform\"][\"os\"]}/{m[\"platform\"][\"architecture\"]}" for m in d.get("manifests",[]) if m.get("platform",{}).get("os")!="unknown"})))' \
    2>/dev/null || echo "  (could not enumerate platforms)"

  docker pull --platform linux/arm64 "$image"

  # THE CHECK THAT MATTERS
  arch=$(docker image inspect "$image" --format '{{.Architecture}}')
  if [ "$arch" != "arm64" ]; then
    echo "  !! got $arch, expected arm64 — enable the containerd image store and re-pull"
    exit 1
  fi
  echo "  architecture confirmed: $arch"

  docker save -o "${alias}.tar" "$image"
  echo "  saved: ${alias}.tar ($(du -h "${alias}.tar" | cut -f1))"
done
```

Windows PowerShell equivalent:

```powershell
mkdir D:\staging\images -Force; cd D:\staging\images

$images = @(
  @{ Ref='vllm/vllm-openai:cu130-nightly'; Alias='vllm'   },
  @{ Ref='qdrant/qdrant:v1.12.4';          Alias='qdrant' },
  @{ Ref='python:3.11-slim';               Alias='python' },
  @{ Ref='redis:7.4-alpine';               Alias='redis'  }
)

foreach ($i in $images) {
    Write-Host "=== $($i.Alias) : $($i.Ref) ===" -ForegroundColor Cyan
    docker pull --platform linux/arm64 $i.Ref
    $arch = docker image inspect $i.Ref --format '{{.Architecture}}'
    if ($arch -ne 'arm64') {
        throw "Got $arch, expected arm64. Enable the containerd image store and re-pull."
    }
    Write-Host "  architecture confirmed: $arch" -ForegroundColor Green
    docker save -o "$($i.Alias).tar" $i.Ref
}
```

**Do not skip the architecture assertion.** It is the single most common way
this build fails, and it fails silently until you are inside the enclave.

---

## 3. Download the MITRE ATT&CK data

```bash
mkdir -p /data/staging/attack && cd /data/staging/attack

curl -fL -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-17.1.json

# Validate — a 404 downloads an HTML page that looks like a file
python3 - <<'PY'
import json
b = json.load(open("enterprise-attack.json"))
assert b.get("type") == "bundle", "not a STIX bundle"
techniques = sum(1 for o in b["objects"] if o["type"] == "attack-pattern")
print(f"objects: {len(b['objects'])}, techniques: {techniques}")
assert techniques > 500, "bundle looks truncated"
print("OK")
PY
```

Check the current filename at https://github.com/mitre-attack/attack-stix-data —
it changes with each ATT&CK release.

---

## 4. Build the aarch64 Python wheelhouse

The Sparks and the management VM install Python packages offline from here.

```bash
mkdir -p /data/staging/wheelhouse /data/staging/req
cat /path/to/sparkbuild/spark1/requirements.txt \
    /path/to/sparkbuild/harness/requirements.txt \
    /path/to/sparkbuild/validate/requirements.txt \
    > /data/staging/req/all-requirements.txt
printf '\npip\nsetuptools\nwheel\n' >> /data/staging/req/all-requirements.txt

docker run --rm --platform linux/arm64 \
  -v /data/staging/wheelhouse:/wheelhouse \
  -v /data/staging/req:/req \
  python:3.11-slim bash -c '
    set -e
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends build-essential python3-dev
    python -m pip install --upgrade pip wheel setuptools
    python -m pip wheel --wheel-dir /wheelhouse --requirement /req/all-requirements.txt
    echo "wheels: $(ls -1 /wheelhouse/*.whl | wc -l)"
  '
```

Runs under qemu emulation — 10–25 minutes, and it will look frozen. It isn't.

Needs `docker run --privileged --rm tonistiigi/binfmt --install arm64` first if
arm64 emulation isn't already registered.

**Why not `pip download --platform manylinux_2_28_aarch64`:** it silently skips
any dependency without a prebuilt aarch64 wheel, and you discover the gap in the
airgap. Building in-container compiles them for real and fails loudly here.

---

## 5. Package for transfer

```bash
cd /data/staging

# Model weights are already-compressed binary — gzip buys ~1% for 30 min of CPU
tar -cf sparksoc-models-spark1.tar models/Qwen3.5-35B-A3B models/Qwen3-Embedding-0.6B
tar -cf sparksoc-models-spark2.tar models/gpt-oss-120b

# These compress meaningfully
tar -czf sparksoc-images.tar.gz     images/
tar -czf sparksoc-attack.tar.gz     attack/
tar -czf sparksoc-wheelhouse.tar.gz wheelhouse/
tar -czf sparksoc-code.tar.gz -C /path/to sparkbuild

sha256sum sparksoc-*.tar* > SHA256SUMS
cat SHA256SUMS
```

If your USB is FAT32, reformat it as **exFAT** — FAT32 cannot hold files over
4 GB. Or split:

```bash
split -b 3800M sparksoc-models-spark1.tar sparksoc-models-spark1.tar.part
# rejoin on the target:  cat sparksoc-models-spark1.tar.part* > sparksoc-models-spark1.tar
```

Copy everything to the USB, then on each target host:

```bash
sha256sum -c SHA256SUMS      # verify BEFORE extracting anything
```

---

## 6. On each Spark

```bash
sudo mkdir -p /opt/sparksoc && sudo chown -R "$USER" /opt/sparksoc
cd /media/usb/sparksoc

sha256sum -c SHA256SUMS

tar -xzf sparksoc-code.tar.gz  -C /opt/sparksoc/
tar -xzf sparksoc-attack.tar.gz -C /opt/sparksoc/
tar -xzf sparksoc-wheelhouse.tar.gz -C /opt/sparksoc/

# Spark 1
tar -xf sparksoc-models-spark1.tar -C /opt/sparksoc/
# Spark 2
tar -xf sparksoc-models-spark2.tar -C /opt/sparksoc/

# Images
tar -xzf sparksoc-images.tar.gz -C /tmp/
for t in /tmp/images/*.tar; do docker load -i "$t"; done

# Verify they loaded as arm64
docker images --format '{{.Repository}}:{{.Tag}}' | while read -r i; do
  printf '%-45s %s\n' "$i" "$(docker image inspect "$i" --format '{{.Architecture}}')"
done
```

Anything not showing `arm64` will fail with `exec format error` at runtime.

---

## 7. Compose files

Both are in the repo at `spark1/docker-compose.yaml` and
`spark2/docker-compose.yaml`, reproduced below for reference. They read from a
`.env` file in the same directory — minimal versions are given after each.

Full annotated originals, including every tuning flag and its rationale, are in
the repo. Do not treat the minimal `.env` here as a substitute for reading
`spark1/.env.example` and `spark2/.env.example`, which explain what each value
does and what to change when something fails.

---

### `spark1/docker-compose.yaml`

```yaml
# =============================================================================
# SPARKSOC — DGX Spark 1 (FAST PATH: triage, feature extraction, ATT&CK RAG)
#
#   vllm-triage   :8001  Qwen3.5-35B-A3B   structured triage + feature extraction
#   vllm-embed    :8002  Qwen3-Embedding-0.6B   RAG embeddings (replaces TEI —
#                        HF TEI has no Blackwell support, issue #652)
#   qdrant        :6333  MITRE ATT&CK vector store
#
# Airgap notes:
#   - No image has a pull policy that would reach a registry. Images must be
#     `docker load`-ed by load-bundle.sh first.
#   - Telemetry is disabled at the container level. In an airgap these calls
#     do not leak, but they do add multi-second startup stalls on DNS timeout.
#
# Memory: the two vLLM services reserve independent fractions of the SAME
# unified 128 GB pool. GPU_UTIL_TRIAGE + GPU_UTIL_EMBED must stay <= 0.80.
# init.sh enforces this. See docs/00-ARCHITECTURE.md section 2.
# =============================================================================

x-vllm-common: &vllm-common
  image: ${VLLM_IMAGE:?set VLLM_IMAGE in .env}
  runtime: nvidia
  ipc: host
  restart: unless-stopped
  ulimits:
    memlock: -1
    stack: 67108864
  environment: &vllm-env
    NVIDIA_VISIBLE_DEVICES: all
    NVIDIA_DRIVER_CAPABILITIES: compute,utility
    # ---- airgap hygiene: never attempt egress ----
    HF_HUB_OFFLINE: "1"
    TRANSFORMERS_OFFLINE: "1"
    HF_DATASETS_OFFLINE: "1"
    VLLM_NO_USAGE_STATS: "1"
    DO_NOT_TRACK: "1"
    VLLM_DO_NOT_TRACK: "1"
    # ---- allocator behaviour on unified memory ----
    PYTORCH_CUDA_ALLOC_CONF: "expandable_segments:True"
    VLLM_LOGGING_LEVEL: ${VLLM_LOG_LEVEL:-INFO}
    # ---- sm_121 escape hatches (see .env.example) ----
    VLLM_USE_FLASHINFER_MOE_MXFP4_BF16: ${VLLM_USE_FLASHINFER_MOE_MXFP4_BF16:-0}
    VLLM_ATTENTION_BACKEND: ${VLLM_ATTENTION_BACKEND:-}
  deploy:
    resources:
      reservations:
        devices:
          - driver: nvidia
            count: all
            capabilities: [gpu]
  logging:
    driver: json-file
    options:
      max-size: "50m"
      max-file: "5"

services:

  # ---------------------------------------------------------------------------
  # Triage / feature extraction model
  # ---------------------------------------------------------------------------
  vllm-triage:
    <<: *vllm-common
    container_name: sparksoc-vllm-triage
    volumes:
      - ${MODEL_ROOT:?}/${TRIAGE_MODEL_DIR:?}:/model:ro
      - vllm-triage-cache:/root/.cache/vllm      # torch.compile / CUDA graph cache
    ports:
      - "${BIND_ADDR:-0.0.0.0}:8001:8000"
    command: >
      --model /model
      --served-model-name soc-triage
      --port 8000
      --host 0.0.0.0
      ${TRIAGE_QUANT_ARGS:---quantization mxfp4}
      --tensor-parallel-size 1
      --gpu-memory-utilization ${GPU_UTIL_TRIAGE:-0.62}
      --max-model-len ${TRIAGE_MAX_LEN:-32768}
      --max-num-seqs ${TRIAGE_MAX_SEQS:-16}
      --kv-cache-dtype ${TRIAGE_KV_DTYPE:-fp8}
      --enable-prefix-caching
      --enable-chunked-prefill
      --load-format ${TRIAGE_LOAD_FORMAT:-fastsafetensors}
      --disable-log-requests
      --api-key ${VLLM_API_KEY:?set VLLM_API_KEY in .env}
    healthcheck:
      # /health alone is not sufficient — it returns 200 before the model can
      # actually generate. init.sh does the generative check.
      test: ["CMD-SHELL", "curl -sf http://127.0.0.1:8000/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 900s        # cold start includes JIT + fastsafetensors load
    stop_grace_period: 60s

  # ---------------------------------------------------------------------------
  # Embedding model (TEI replacement)
  # ---------------------------------------------------------------------------
  vllm-embed:
    <<: *vllm-common
    container_name: sparksoc-vllm-embed
    volumes:
      - ${MODEL_ROOT:?}/${EMBED_MODEL_DIR:?}:/model:ro
      - vllm-embed-cache:/root/.cache/vllm
    ports:
      - "${BIND_ADDR:-0.0.0.0}:8002:8000"
    command: >
      --model /model
      --served-model-name soc-embed
      --port 8000
      --host 0.0.0.0
      --runner pooling
      --tensor-parallel-size 1
      --gpu-memory-utilization ${GPU_UTIL_EMBED:-0.04}
      --max-model-len ${EMBED_MAX_LEN:-8192}
      --max-num-seqs ${EMBED_MAX_SEQS:-32}
      --disable-log-requests
      --api-key ${VLLM_API_KEY:?}
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://127.0.0.1:8000/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 300s
    stop_grace_period: 30s
    depends_on:
      # Start after triage so the larger allocation lands first and we fail
      # fast on OOM rather than fragmenting the pool.
      vllm-triage:
        condition: service_healthy

  # ---------------------------------------------------------------------------
  # Vector store
  # ---------------------------------------------------------------------------
  qdrant:
    image: ${QDRANT_IMAGE:?set QDRANT_IMAGE in .env}
    container_name: sparksoc-qdrant
    restart: unless-stopped
    ports:
      - "${BIND_ADDR:-0.0.0.0}:6333:6333"
      - "${BIND_ADDR:-0.0.0.0}:6334:6334"
    volumes:
      - qdrant-storage:/qdrant/storage
      - ./qdrant-config.yaml:/qdrant/config/production.yaml:ro
    environment:
      QDRANT__SERVICE__API_KEY: ${QDRANT_API_KEY:?set QDRANT_API_KEY in .env}
      QDRANT__TELEMETRY_DISABLED: "true"
      QDRANT__LOG_LEVEL: INFO
    healthcheck:
      test: ["CMD-SHELL", "bash -c ':> /dev/tcp/127.0.0.1/6333' || exit 1"]
      interval: 15s
      timeout: 5s
      retries: 5
      start_period: 30s
    logging:
      driver: json-file
      options:
        max-size: "20m"
        max-file: "3"

volumes:
  qdrant-storage:
    driver: local
  vllm-triage-cache:
    driver: local
  vllm-embed-cache:
    driver: local

networks:
  default:
    name: sparksoc
```

#### Minimal `spark1/.env`

```bash
VLLM_IMAGE=vllm/vllm-openai:cu130-nightly
QDRANT_IMAGE=qdrant/qdrant:v1.12.4
MODEL_ROOT=/opt/sparksoc/models
TRIAGE_MODEL_DIR=Qwen3.5-35B-A3B
EMBED_MODEL_DIR=Qwen3-Embedding-0.6B

# openssl rand -hex 32
VLLM_API_KEY=REPLACE_ME
QDRANT_API_KEY=REPLACE_ME

BIND_ADDR=0.0.0.0

# Both fractions draw from ONE 128 GB unified pool. Sum must stay <= 0.80.
GPU_UTIL_TRIAGE=0.62
GPU_UTIL_EMBED=0.04

TRIAGE_QUANT_ARGS=--quantization mxfp4
TRIAGE_MAX_LEN=32768
TRIAGE_MAX_SEQS=16
TRIAGE_KV_DTYPE=fp8
TRIAGE_LOAD_FORMAT=fastsafetensors
EMBED_MAX_LEN=8192
EMBED_MAX_SEQS=32

VLLM_USE_FLASHINFER_MOE_MXFP4_BF16=0
VLLM_ATTENTION_BACKEND=
VLLM_LOG_LEVEL=INFO

ATTACK_STIX_PATH=/opt/sparksoc/attack/enterprise-attack.json
QDRANT_COLLECTION=attack_enterprise
EMBED_ENDPOINT=http://127.0.0.1:8002/v1
EMBED_MODEL_NAME=soc-embed
EMBED_DIM=1024
```

`spark1` also bind-mounts `./qdrant-config.yaml`, which is in the repo. Without
it Qdrant starts with defaults — workable, but it will use memmap and more
threads than you want on a box that is also running two vLLM instances.

Start it:

```bash
cd /opt/sparksoc/code/spark1
docker compose up -d
./init.sh          # waits for readiness, checks for empty completions, ingests ATT&CK
```

---

### `spark2/docker-compose.yaml`

```yaml
# =============================================================================
# SPARKSOC — DGX Spark 2 (DEEP PATH: attack hypothesis validation, reasoning)
#
#   vllm-reason  :8003  gpt-oss-120b (MXFP4 MoE)
#
# Sole workload on this node. ~63 GB of MXFP4 weights plus KV cache for a
# 128K context.
#
# CRITICAL — vLLM #37030
#   gpt-oss at TP=1 on SM121 has a documented shared-memory race in the Marlin
#   MoE 256-thread kernel that produces a NULL first Harmony token. The symptom
#   is HTTP 200 with empty `content`, which passes every naive health check.
#   init.sh asserts non-empty content. Mitigation toggles are in .env.example.
#
# Cross-node tensor parallelism is NOT configured. TP=2 across two Sparks
# requires a ConnectX-7 direct link; this enclave has 1 GbE only.
# =============================================================================

services:

  vllm-reason:
    image: ${VLLM_IMAGE:?set VLLM_IMAGE in .env}
    container_name: sparksoc-vllm-reason
    runtime: nvidia
    ipc: host
    restart: unless-stopped
    ulimits:
      memlock: -1
      stack: 67108864
    volumes:
      - ${MODEL_ROOT:?}/${REASON_MODEL_DIR:?}:/model:ro
      - vllm-reason-cache:/root/.cache/vllm
    ports:
      - "${BIND_ADDR:-0.0.0.0}:8003:8000"
    environment:
      NVIDIA_VISIBLE_DEVICES: all
      NVIDIA_DRIVER_CAPABILITIES: compute,utility

      # ---- airgap hygiene ----
      HF_HUB_OFFLINE: "1"
      TRANSFORMERS_OFFLINE: "1"
      HF_DATASETS_OFFLINE: "1"
      VLLM_NO_USAGE_STATS: "1"
      DO_NOT_TRACK: "1"
      VLLM_DO_NOT_TRACK: "1"

      # ---- allocator ----
      PYTORCH_CUDA_ALLOC_CONF: "expandable_segments:True"
      VLLM_LOGGING_LEVEL: ${VLLM_LOG_LEVEL:-INFO}

      # ---- sm_121 / MXFP4 MoE escape hatches (see .env.example) ----
      VLLM_USE_FLASHINFER_MOE_MXFP4_BF16: ${VLLM_USE_FLASHINFER_MOE_MXFP4_BF16:-0}
      VLLM_ATTENTION_BACKEND: ${VLLM_ATTENTION_BACKEND:-}
      VLLM_MARLIN_USE_ATOMIC_ADD: ${VLLM_MARLIN_USE_ATOMIC_ADD:-0}

    command: >
      --model /model
      --served-model-name soc-reason
      --port 8000
      --host 0.0.0.0
      ${REASON_QUANT_ARGS:---quantization mxfp4}
      --tensor-parallel-size 1
      --gpu-memory-utilization ${GPU_UTIL_REASON:-0.88}
      --max-model-len ${REASON_MAX_LEN:-131072}
      --max-num-seqs ${REASON_MAX_SEQS:-4}
      --kv-cache-dtype ${REASON_KV_DTYPE:-fp8}
      --enable-prefix-caching
      --enable-chunked-prefill
      --load-format ${REASON_LOAD_FORMAT:-fastsafetensors}
      ${REASON_PARSER_ARGS:---reasoning-parser openai_gptoss}
      ${REASON_TOOL_ARGS:---enable-auto-tool-choice --tool-call-parser openai}
      --disable-log-requests
      --api-key ${VLLM_API_KEY:?set VLLM_API_KEY in .env}

    deploy:
      resources:
        reservations:
          devices:
            - driver: nvidia
              count: all
              capabilities: [gpu]

    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://127.0.0.1:8000/health || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5
      # 63 GB of weights over fastsafetensors plus JIT. Do not shorten this.
      start_period: 1800s

    stop_grace_period: 120s

    logging:
      driver: json-file
      options:
        max-size: "100m"
        max-file: "5"

volumes:
  vllm-reason-cache:
    driver: local

networks:
  default:
    name: sparksoc
```

#### Minimal `spark2/.env`

```bash
VLLM_IMAGE=vllm/vllm-openai:cu130-nightly
MODEL_ROOT=/opt/sparksoc/models
REASON_MODEL_DIR=gpt-oss-120b

# MUST match spark1 and the harness
VLLM_API_KEY=REPLACE_ME

BIND_ADDR=0.0.0.0

# Sole workload on this node. Do not exceed 0.90 — CUDA graph capture
# spikes outside the pool vLLM reserves.
GPU_UTIL_REASON=0.88

REASON_QUANT_ARGS=--quantization mxfp4
REASON_MAX_LEN=131072
REASON_MAX_SEQS=4
REASON_KV_DTYPE=fp8
REASON_LOAD_FORMAT=fastsafetensors

# VERIFY THIS NAME before first start:
#   docker run --rm --entrypoint vllm $VLLM_IMAGE serve --help | grep -A20 reasoning-parser
# Candidates across vLLM releases: openai_gptoss, gpt_oss, openai
REASON_PARSER_ARGS=--reasoning-parser openai_gptoss
REASON_TOOL_ARGS=--enable-auto-tool-choice --tool-call-parser openai

# vLLM #37030 escape hatches. Try in this order if completions come back empty.
VLLM_USE_FLASHINFER_MOE_MXFP4_BF16=0
VLLM_MARLIN_USE_ATOMIC_ADD=0
VLLM_ATTENTION_BACKEND=
VLLM_LOG_LEVEL=INFO
```

Start it:

```bash
cd /opt/sparksoc/code/spark2
docker compose up -d
./init.sh          # cold start is 15-25 min; init.sh waits up to 2400s
```

`init.sh` runs the completion check **five times**, because the SM121 Marlin MoE
race is nondeterministic and one success does not clear it.

---

## Where this differs from the scripted path

The orchestrator additionally:

- **pins image digests** into `MANIFEST.json` so you can prove later exactly what
  you deployed
- **runs the hardware smoke gate** against a real Spark before packaging —
  including the check for vLLM #37030, where gpt-oss returns HTTP 200 with empty
  content on sm_121 and every naive health check passes
- **validates shard indexes** against `model.safetensors.index.json`
- **splits and checksums** bundles automatically with a reassembly script

Doing it manually is entirely reasonable. Just be aware that the smoke gate is
the thing standing between you and discovering a broken runtime after the media
is already inside the enclave. If you skip it, read `docs/01-STAGING.md` §7 first
so you know what the fallback looks like.

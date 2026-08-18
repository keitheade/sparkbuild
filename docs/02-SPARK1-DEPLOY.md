# 02 — DGX Spark 1 deployment (fast path)

Triage model, embedding model, Qdrant, and the MITRE ATT&CK index.

---

## 1. Host preparation

```bash
# Verify the hardware
nvidia-smi --query-gpu=name,compute_cap,memory.total --format=csv
# expect: NVIDIA GB10, 12.1, ~131072 MiB

uname -m                       # aarch64
docker --version
docker info | grep -i runtime  # nvidia must be present
```

If `nvidia` is not a listed runtime, the NVIDIA Container Toolkit is not
configured. Nothing below will work until it is.

### Time discipline

HMAC replay protection between Splunk and the harness rejects timestamps more
than 300 s out. In an airgap with no upstream NTP, drift is the single most
common cause of "everything was working yesterday".

```bash
# Point every enclave host at one internal source
sudo timedatectl set-ntp true
sudo sed -i 's/^#\?NTP=.*/NTP=10.90.1.1/' /etc/systemd/timesyncd.conf
sudo systemctl restart systemd-timesyncd
timedatectl status | grep -E 'synchronized|Time zone'
```

Use the same source on Spark 2, the management VM, Splunk, and SOAR.

---

## 2. Load the bundle

```bash
sudo mkdir -p /opt/sparksoc && sudo chown -R "$USER" /opt/sparksoc
cd /media/usb/sparksoc

bash verify-bundle.sh          # reassembles splits, checks every SHA-256
```

Do not continue if verification fails. A corrupted safetensors shard produces a
model that loads and generates confident nonsense.

```bash
sudo /media/usb/sparksoc/../code/spark1/load-bundle.sh /media/usb/sparksoc
# or, if code is already extracted:
sudo /opt/sparksoc/code/spark1/load-bundle.sh /media/usb/sparksoc
```

This extracts code, ATT&CK data, the wheelhouse and Spark 1's models, loads the
container images, asserts each is `arm64`, and builds an offline venv.

---

## 3. Configure

```bash
cd /opt/sparksoc/code/spark1
cp .env.example .env && chmod 600 .env

# Generate keys. Record these — Spark 2 and the harness must match.
openssl rand -hex 32   # -> VLLM_API_KEY
openssl rand -hex 32   # -> QDRANT_API_KEY

$EDITOR .env
```

The values worth understanding before you change them:

| Variable | Default | Why |
|---|---|---|
| `GPU_UTIL_TRIAGE` | `0.62` | ~74 GB of the 128 GB unified pool |
| `GPU_UTIL_EMBED` | `0.04` | ~5 GB; the two must sum ≤ 0.80 |
| `TRIAGE_QUANT_ARGS` | `--quantization mxfp4` | online MXFP4 of the BF16 MoE checkpoint |
| `TRIAGE_MAX_SEQS` | `16` | **not 128** — see below |
| `TRIAGE_MAX_LEN` | `32768` | ample for alerts; larger costs KV cache you need for concurrency |

`init.sh` refuses to start if the two utilization fractions exceed 0.80. They are
independent reservations against the same physical memory.

**On `--max-num-seqs`:** GB10 decode is LPDDR5x bandwidth-bound. Past roughly
four concurrent decode streams, the per-token bandwidth tax exceeds the batching
gain. 16 is a deliberate compromise for triage, where outputs are short and
prefill dominates. Setting 128 does not increase throughput; it inflates KV
allocation and TTFT variance. Measure with `validate/bench.py` before changing it.

---

## 4. Start

```bash
docker compose up -d
docker compose logs -f vllm-triage      # watch the load; Ctrl-C when serving
./init.sh
```

`init.sh` performs six steps and each can fail informatively:

1. **memory budget preflight** — arithmetic on the two fractions
2. **wait for readiness** — up to 900 s, cold start includes JIT
3. **generative validation** — a completion that must return non-empty content,
   plus a JSON-schema-constrained call, because the whole pipeline depends on
   guided decoding
4. **embedding dimension verification** — writes the observed dimension back
   into `.env` so the Qdrant collection geometry cannot drift
5. **pre-warm** — three representative requests so the first real alert does not
   pay ~25 s of JIT
6. **ATT&CK ingestion** — only if the collection is absent

Expected timing: 8–15 minutes cold, of which ATT&CK ingestion is 5–10 minutes.

---

## 5. ATT&CK ingestion

`init.sh` runs this automatically the first time. To rebuild:

```bash
source venv/bin/activate
python3 attack_ingest.py --recreate
```

Useful flags:

```bash
python3 attack_ingest.py --dry-run          # build documents, print samples, no embedding
python3 attack_ingest.py --skip-verify      # skip the canned retrieval checks
python3 attack_ingest.py -v                 # debug logging
```

The script emits several document types per technique — `summary`, `detection`,
`datasource`, `procedure`, `mitigation`, `detects` — because analyst queries look
like log lines, and ATT&CK's `x_mitre_detection` prose is the field that actually
matches them. A single-vector-per-technique index performs noticeably worse.

It finishes by running eight canned queries and reporting top-5 recall. Below
60% it exits non-zero. If that happens:

- confirm `detection` documents were created (`--dry-run` prints the mix)
- confirm the embedding model is the one you expect (`/v1/models` on :8002)
- confirm the collection dimension matches the server (`init.sh` step 4)

Expected: roughly 12,000–18,000 points for ATT&CK Enterprise v17.

---

## 6. Verify

```bash
export VLLM_API_KEY=$(grep ^VLLM_API_KEY .env | cut -d= -f2)
export QDRANT_API_KEY=$(grep ^QDRANT_API_KEY .env | cut -d= -f2)

# triage
curl -s -H "Authorization: Bearer $VLLM_API_KEY" \
  http://127.0.0.1:8001/v1/models | python3 -m json.tool

# embeddings
curl -s -H "Authorization: Bearer $VLLM_API_KEY" -H 'Content-Type: application/json' \
  http://127.0.0.1:8002/v1/embeddings \
  -d '{"model":"soc-embed","input":["lsass memory dump"]}' \
  | python3 -c 'import sys,json;print("dim",len(json.load(sys.stdin)["data"][0]["embedding"]))'

# qdrant
curl -s -H "api-key: $QDRANT_API_KEY" \
  http://127.0.0.1:6333/collections/attack_enterprise \
  | python3 -c 'import sys,json;r=json.load(sys.stdin)["result"];print(r["points_count"],"points, dim",r["config"]["params"]["vectors"]["size"])'

# airgap posture
bash /opt/sparksoc/code/validate/egress_check.sh
```

---

## 7. Install the service

```bash
sudo cp systemd/sparksoc-spark1.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sparksoc-spark1
systemctl status sparksoc-spark1
```

`TimeoutStartSec=1800` because a cold boot legitimately takes 15 minutes.

---

## 8. Troubleshooting

| Symptom | Meaning | Action |
|---|---|---|
| `init.sh` step 3: **empty content** | sm_121 Marlin MoE race (vLLM #37030) | `.env`: `VLLM_USE_FLASHINFER_MOE_MXFP4_BF16=1`, then BF16 fallback (`TRIAGE_QUANT_ARGS=` and `GPU_UTIL_TRIAGE=0.75`), then `VLLM_ATTENTION_BACKEND=FLASH_ATTN` |
| `CUDA out of memory` during load | fractions too high, or something else on the GPU | lower `GPU_UTIL_TRIAGE`; `nvidia-smi` for other processes |
| `no kernel image is available` | image lacks sm_121 kernels | `docs/01-STAGING.md` §7 |
| structured-output check fails | build lacks guided decoding | check for `xgrammar` in the image; try `--guided-decoding-backend outlines` |
| ingestion recall < 60% | wrong embedding model or missing doc types | `attack_ingest.py --dry-run -v` |
| embed service will not start | `--runner pooling` unsupported in this build | try `--task embed` in `docker-compose.yaml` |
| Qdrant `Wrong input: Vector dimension error` | collection built for a different model | `python3 attack_ingest.py --recreate` |
| slow first request after restart | JIT + CUDA graph capture | expected ~25 s; `init.sh` pre-warms |

---

## 9. Next

[`03-SPARK2-DEPLOY.md`](03-SPARK2-DEPLOY.md)

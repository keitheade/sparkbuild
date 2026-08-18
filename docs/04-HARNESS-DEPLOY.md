# 04 — Agent harness deployment (management VM)

The FastAPI orchestrator that connects Splunk, both Sparks, and SOAR.

---

## 1. Prerequisites

- Both Sparks deployed and `init.sh` passing on each
- Docker and Docker Compose on the management VM
- Same NTP source as everything else in the enclave
- The SOAR automation user's `ph-auth-token` ([`06-SOAR-INTEGRATION.md`](06-SOAR-INTEGRATION.md) §2)
- The SOAR CA certificate

---

## 2. Load the bundle and build the image

```bash
sudo mkdir -p /opt/sparksoc && sudo chown -R "$USER" /opt/sparksoc
cd /media/usb/sparksoc
bash verify-bundle.sh

tar -xzf sparksoc-code.tar.gz -C /tmp
rsync -a /tmp/stage-code/ /opt/sparksoc/code/
tar -xzf sparksoc-wheelhouse.tar.gz -C /opt/sparksoc/
tar -xzf sparksoc-attack.tar.gz -C /tmp
mkdir -p /opt/sparksoc/code/harness/attack
cp /tmp/attack/attack_keyword_index.json /opt/sparksoc/code/harness/attack/ 2>/dev/null || true

tar -xzf sparksoc-images.tar.gz -C /tmp
docker load -i /tmp/images/python.tar
docker load -i /tmp/images/redis.tar

cd /opt/sparksoc
docker build -t sparksoc/harness:1.0.0 -f code/harness/Dockerfile .
```

The build context is `/opt/sparksoc` so the Dockerfile can `COPY wheelhouse`.
Installation is `--no-index`; nothing reaches out.

### The keyword fallback index

`attack_keyword_index.json` is produced by `attack_ingest.py` on Spark 1. If it
was not in the ATT&CK bundle, copy it across now:

```bash
scp spark1:/opt/sparksoc/attack/attack_keyword_index.json \
    /opt/sparksoc/code/harness/attack/
```

Without it, a Qdrant outage means retrieval returns nothing at all rather than
degrading to keyword matching.

---

## 3. Secrets

Secrets are files mounted as Docker secrets, never environment values in a
compose file and never baked into the image.

```bash
cd /opt/sparksoc/code/harness
mkdir -p secrets certs && chmod 700 secrets

# Must match the corresponding values on the Sparks
printf '%s' 'SPARK1_VLLM_API_KEY_VALUE'  > secrets/spark1_api_key
printf '%s' 'SPARK2_VLLM_API_KEY_VALUE'  > secrets/spark2_api_key
printf '%s' 'SPARK1_QDRANT_API_KEY_VALUE' > secrets/qdrant_api_key

# From SOAR: Administration > User Management > Users > automation user > REST API key
printf '%s' 'PH_AUTH_TOKEN_VALUE' > secrets/soar_token

# New shared secret. The same value goes into the Splunk alert action.
openssl rand -hex 32 | tr -d '\n' > secrets/splunk_hmac_secret
cat secrets/splunk_hmac_secret; echo   # copy this for docs/05

chmod 400 secrets/*

# SOAR CA
openssl s_client -connect soar.range.local:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > certs/soar-ca.pem
```

`printf '%s'` rather than `echo` — a trailing newline in a secret file produces a
signature mismatch that is genuinely unpleasant to diagnose.

---

## 4. Configure

```bash
cp .env.example .env && chmod 600 .env
$EDITOR .env
```

Set the endpoint IPs, then consider three settings:

**`ALLOWED_SOURCE_IPS`** — the Splunk search head(s). Empty means any host that
can reach port 8080 may submit signed alerts. Set it.

**`DEEP_THRESHOLD`** (default `0.45`) — triage threat score at or above which the
deep path engages. Lower catches more and saturates Spark 2 sooner. During a
purple-team exercise, watch `sparksoc_queue_depth{queue="deep"}`; if it stays
pinned, raise the threshold rather than adding deep workers.

**`FORCE_DRY_RUN`** — see §6.

---

## 5. Start

```bash
docker compose up -d
docker compose logs -f harness
```

Startup is intentionally strict. **The harness refuses to start if
`common/action_allowlist.yaml` fails its self-test.** That file is the boundary
between model output and the range; a malformed one is not a boundary. Expect:

```
Action allowlist v3 validated: 11 COLLECT, 5 CONTAIN, dry_run=False
Audit chain: chain intact across N entries
Redis connected: redis://redis:6379/0
  dependency spark1-triage  OK
  dependency spark1-embed   OK
  dependency spark2-reason  OK
  dependency qdrant         OK
  dependency soar           OK
  ATT&CK collection: 14832 points
Pipeline started: 6 fast workers, 2 deep workers
```

Unreachable dependencies produce warnings, not a startup failure — Spark 2 or
SOAR being down should degrade the pipeline, not prevent it running.

### Why a single uvicorn worker

Case state, both queues, and pending approvals live in process. With multiple
workers, an approval POSTed to worker 2 would not find the case held by worker 1.
Scaling horizontally requires moving that state to Redis first.

---

## 6. Dry run first

Ship with `FORCE_DRY_RUN=true` for the first exercise. Every action is validated,
tiered, and audited as `dry_run` — nothing dispatches to the range. You get
verdict quality data with zero blast radius.

```bash
curl -s http://127.0.0.1:8080/v1/config | python3 -m json.tool | grep dry_run
```

Promote when all of these hold:

1. `e2e_test.py` passes with no failures
2. A replay exercise scores a detection rate you believe
3. Reviewing `action.dry_run` audit entries, the actions the model *would* have
   taken are ones you would have approved
4. `sparksoc_scope_violations` is 0, or every instance is explained

```bash
sed -i 's/^FORCE_DRY_RUN=.*/FORCE_DRY_RUN=false/' .env
docker compose up -d --force-recreate harness
```

---

## 7. Verify

```bash
curl -s http://127.0.0.1:8080/health | python3 -m json.tool
curl -s http://127.0.0.1:8080/health/deep | python3 -m json.tool
curl -s http://127.0.0.1:8080/v1/config  | python3 -m json.tool
curl -s http://127.0.0.1:8080/v1/audit/verify

# Signed submission end to end
cd /opt/sparksoc/code/validate
cp config.example.yaml config.yaml && $EDITOR config.yaml
python3 e2e_test.py --config config.yaml --only connectivity,security
```

---

## 8. Install the service

```bash
sudo cp systemd-sparksoc-harness.service /etc/systemd/system/sparksoc-harness.service
sudo systemctl daemon-reload
sudo systemctl enable --now sparksoc-harness
```

---

## 9. API reference

### Ingestion
| Method | Path | Notes |
|---|---|---|
| POST | `/v1/alert` | HMAC-signed. Primary path, used by TA-soc-harness. |
| POST | `/v1/alert/webhook/{token}` | Stock Splunk webhook fallback. Weaker; disabled unless `WEBHOOK_FALLBACK_TOKEN` is set. |

### Cases
| Method | Path | Notes |
|---|---|---|
| GET | `/v1/cases` | `?limit=&status=&exercise_id=` |
| GET | `/v1/case/{id}` | full case document |
| GET | `/v1/case/{id}/stream` | SSE — triage in seconds, deep verdict later on the same stream |
| GET | `/v1/case/{id}/audit` | audit entries for one case |

### Approvals
| Method | Path | Notes |
|---|---|---|
| GET | `/v1/approvals` | pending containment approvals |
| POST | `/v1/approval/{id}` | `{"decision":"approve\|deny","approver":"name","note":""}` |

### Exercises
| Method | Path | Notes |
|---|---|---|
| POST | `/v1/exercise/start` | one active exercise at a time |
| POST | `/v1/exercise/{id}/stop` | |
| POST | `/v1/exercise/{id}/ground-truth` | `format`: `atomic` \| `caldera` \| `native` |
| GET | `/v1/exercise/{id}/report` | `?format=json\|html` |
| GET | `/v1/exercises` | |

### Operations
| Method | Path | Notes |
|---|---|---|
| GET | `/health` | liveness, no dependency calls |
| GET | `/health/deep` | dependencies, queues, audit chain; 503 when critical deps are down |
| GET | `/metrics` | Prometheus text |
| GET | `/v1/config` | effective non-secret configuration |
| GET | `/v1/audit/verify` | recompute the hash chain |
| POST | `/v1/soar/replay` | replay SOAR calls journalled during an outage |

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| refuses to start, `ALLOWLIST:` errors | allowlist self-test failed | fix `common/action_allowlist.yaml`; the messages name the specific problem |
| 401 on every alert | secret mismatch or clock drift | compare `secrets/splunk_hmac_secret` with the Splunk alert action; check `timedatectl` on both |
| 401 mentioning drift | NTP | sync both hosts to the enclave source |
| 429 on alerts | fast queue full | check `/health/deep` queues; raise `WORKERS` only if Spark 1 has headroom |
| all cases `rag_degraded` | Qdrant unreachable | `curl` Qdrant from the harness container; check `QDRANT_API_KEY` |
| deep verdicts never appear | Spark 2 down, or deep queue saturated | `/health/deep`; consider raising `DEEP_THRESHOLD` |
| every action rejected "target out of scope" | `range_cidrs` do not match the range | fix `common/action_allowlist.yaml` and restart |
| audit chain verification fails | file edited or truncated | investigate as a security event; `docs/08-RUNBOOK.md` |
| Redis warnings on startup | Redis down | harness runs with in-process dedupe; fix Redis before running an exercise |

---

## 11. Next

[`05-SPLUNK-INTEGRATION.md`](05-SPLUNK-INTEGRATION.md)

# 08 — Operations runbook

---

## 1. Daily

```bash
# Health across the enclave
for h in spark1 spark2; do
  echo "=== $h ==="
  ssh $h 'cd /opt/sparksoc/code/'$h' && docker compose ps --format "table {{.Service}}\t{{.Status}}"'
done

curl -s http://harness:8080/health/deep | python3 -m json.tool

# Audit chain
curl -s http://harness:8080/v1/audit/verify

# Overnight volume and errors
curl -s http://harness:8080/metrics | grep -E 'alerts_received|errors|scope_violations|injection'

# Approvals that nobody actioned
curl -s http://harness:8080/v1/approvals | python3 -m json.tool
```

---

## 2. Alerting thresholds

Scrape `http://harness:8080/metrics`. Baselines come from
`validate/bench.py` and `/opt/sparksoc/state/spark2-baseline.json`.

| Metric | Warning | Critical | Meaning |
|---|---|---|---|
| `sparksoc_queue_depth{queue="fast"}` | > 100 | > 400 | triage falling behind; 429s imminent at 512 |
| `sparksoc_queue_depth{queue="deep"}` | > 50 | > 110 | Spark 2 saturated; raise `DEEP_THRESHOLD` |
| `sparksoc_errors` rate | > 1/hour | > 10/hour | check `pipeline.error` audit entries |
| `sparksoc_scope_violations` | any | > 5/hour | model targeting outside the range — investigate |
| `sparksoc_injection_suspected` | any | — | not necessarily bad; review the evidence |
| `sparksoc_latency_fast_p95_ms` | > 10000 | > 20000 | fast path missing its budget |
| `sparksoc_backend_errors{backend=...}` | > 5 | > 50 | node unhealthy |
| `sparksoc_approvals_pending` | > 3 | > 10 | approvals will expire unactioned |
| `sparksoc_dry_run` | — | unexpected value | someone changed autonomy posture |

Suggested Prometheus rules:

```yaml
groups:
  - name: sparksoc
    rules:
      - alert: SparkSOCQueueSaturated
        expr: sparksoc_queue_depth{queue="fast"} > 400
        for: 5m
        annotations:
          summary: "Fast queue near capacity; Splunk deliveries will be rejected with 429"

      - alert: SparkSOCScopeViolation
        expr: increase(sparksoc_scope_violations[1h]) > 0
        annotations:
          summary: "Model proposed an action targeting a host outside the range CIDRs"

      - alert: SparkSOCBackendDown
        expr: increase(sparksoc_backend_errors[10m]) > 20
        annotations:
          summary: "Repeated LLM backend errors on {{ $labels.backend }}"

      - alert: SparkSOCAuditChainBroken
        expr: sparksoc_audit_chain_ok == 0
        annotations:
          summary: "Audit hash chain verification failed — treat as a security event"
```

---

## 3. Common incidents

### Empty completions after a working period

**Symptom:** cases fail with `EmptyContentError`; `docker compose logs` shows no
errors on the vLLM side.

This is the SM121 Marlin MoE race (vLLM #37030) reappearing, usually after a
restart changed kernel selection. It is nondeterministic — it can lie dormant.

```bash
ssh spark2 'cd /opt/sparksoc/code/spark2 && ./init.sh'   # step 4 runs 5 attempts
```

If it fails, apply the escape hatches in order, restarting between each:

```bash
# spark2/.env
VLLM_USE_FLASHINFER_MOE_MXFP4_BF16=1
# then
VLLM_MARLIN_USE_ATOMIC_ADD=1
# then
VLLM_ATTENTION_BACKEND=FLASH_ATTN

docker compose up -d --force-recreate && ./init.sh
```

The fast path keeps working throughout — cases get triage verdicts and SOAR
containers, marked `deep_verdict: unavailable`. This is a degradation, not an
outage.

### Queue saturation during an exercise

```bash
curl -s http://harness:8080/metrics | grep -E 'queue_depth|backend_inflight'
```

**Fast queue saturated:** Spark 1 is the bottleneck. Do not raise `WORKERS` —
that just moves the queue. Either raise `TRIAGE_MAX_SEQS` (test with `bench.py`
first; past the aggregate-throughput plateau it makes things worse) or add
Splunk-side throttling.

**Deep queue saturated:** expected during a heavy chain. Raise `DEEP_THRESHOLD`
from 0.45 to 0.6 to escalate less. Adding deep workers does not help — Spark 2's
`--max-num-seqs 4` and the bandwidth ceiling are the real limit.

Mid-exercise, without a restart:

```bash
docker compose exec harness printenv DEEP_THRESHOLD   # confirm current
# DEEP_THRESHOLD is read at startup; to change it live, edit .env and:
docker compose up -d --force-recreate harness
# In-flight cases survive; queued cases do not. Prefer waiting for a lull.
```

### SOAR unavailable

Calls journal to `state/soar_retry.jsonl`. Verdicts and audit records continue.

```bash
curl -XPOST http://harness:8080/v1/soar/replay
docker compose exec harness wc -l /var/lib/sparksoc/state/soar_retry.jsonl
```

The janitor attempts replay every 5 minutes automatically when SOAR is marked
unavailable.

### Qdrant down

Retrieval degrades to the keyword index. Cases are tagged `rag-degraded` in SOAR
and the triage prompt tells the model to lower its confidence.

```bash
ssh spark1 'cd /opt/sparksoc/code/spark1 && docker compose restart qdrant && sleep 20'
curl -s -H "api-key: $QDRANT_API_KEY" http://spark1:6333/collections/attack_enterprise
```

If the collection is gone, rebuild:

```bash
ssh spark1 'cd /opt/sparksoc/code/spark1 && . venv/bin/activate && python3 attack_ingest.py --recreate'
```

### Audit chain verification fails

**Treat this as a security event.**

```bash
curl -s http://harness:8080/v1/audit/verify
# -> "line 4821 (seq 4820): prev_hash mismatch"
```

1. Do not restart the harness — that appends and complicates the picture.
2. Copy the file for forensics:
   ```bash
   docker compose exec harness cp /var/lib/sparksoc/audit/audit.jsonl \
     /var/lib/sparksoc/audit/audit.$(date +%s).evidence
   ```
3. If you forward the audit log to Splunk (`docs/05` §7), compare the forwarded
   copy against the local file at the break point. Divergence tells you whether
   records were altered or the file was simply truncated.
4. Check who has write access to the Docker volume.

Truncation from a full disk looks identical to tampering at the chain level. Check
disk first, but do not assume it.

### Everything looks healthy, no cases arriving

```bash
# 1. Is Splunk firing?
ssh splunk 'tail -50 $SPLUNK_HOME/var/log/splunk/splunkd.log | grep TA-soc-harness'

# 2. Is the harness rejecting?
docker compose logs --tail 100 harness | grep -i 'rejected\|401'

# 3. Clock drift — the usual culprit
date -u; ssh splunk 'date -u'
```

A 401 mentioning drift means NTP. A 401 without it means the shared secret
differs — check for a trailing newline in `secrets/splunk_hmac_secret`.

---

## 4. Routine maintenance

### Update ATT&CK

```bash
# Stage the new STIX on the Windows host, carry across, then:
ssh spark1
cp /media/usb/enterprise-attack.json /opt/sparksoc/attack/
cd /opt/sparksoc/code/spark1 && . venv/bin/activate
python3 attack_ingest.py --recreate
scp /opt/sparksoc/attack/attack_keyword_index.json harness:/opt/sparksoc/code/harness/attack/
ssh harness 'cd /opt/sparksoc/code/harness && docker compose restart harness'
```

Re-run `e2e_test.py --only retrieval,pipeline` afterwards. A new ATT&CK version
changes technique IDs and can shift verdicts.

### Change the action allowlist

```bash
cd /opt/sparksoc/code
$EDITOR common/action_allowlist.yaml
cd harness && docker compose restart harness
docker compose logs --tail 30 harness | grep -i allowlist
```

The harness self-tests at startup and refuses to run on an inconsistent
allowlist. That is the safe failure — a harness that will not start is better
than one running without a boundary.

### Rotate secrets

```bash
NEW=$(openssl rand -hex 32)

# Sparks
ssh spark1 "cd /opt/sparksoc/code/spark1 && sed -i 's/^VLLM_API_KEY=.*/VLLM_API_KEY=$NEW/' .env && docker compose up -d --force-recreate"
ssh spark2 "cd /opt/sparksoc/code/spark2 && sed -i 's/^VLLM_API_KEY=.*/VLLM_API_KEY=$NEW/' .env && docker compose up -d --force-recreate"

# Harness
printf '%s' "$NEW" > harness/secrets/spark1_api_key
printf '%s' "$NEW" > harness/secrets/spark2_api_key
cd harness && docker compose up -d --force-recreate harness
```

Rotating `splunk_hmac_secret` requires updating the Splunk alert action in the
same window; alerts fired in between will 401 and be retried three times, then
lost. Do it in a quiet period.

### Log rotation

Container logs are capped in the compose files. The audit log is not, by design:

```bash
docker compose exec harness du -h /var/lib/sparksoc/audit/audit.jsonl
```

Roughly 2–5 KB per case. At 500 cases/day that is ~1 GB/year. When you rotate,
**preserve the chain** — archive the whole file and start a new one rather than
truncating in place:

```bash
docker compose exec harness sh -c '
  cd /var/lib/sparksoc/audit
  mv audit.jsonl audit-$(date +%Y%m).jsonl
  touch audit.jsonl'
docker compose restart harness   # starts a new chain segment
```

Keep the archives. A verified archive plus a verified current file is still a
complete evidentiary record; the seam is documented and expected.

---

## 5. Restart procedures

### Ordered restart

```bash
# 1. Stop ingestion first so nothing is lost mid-flight
ssh splunk 'sudo -u splunk $SPLUNK_HOME/bin/splunk disable savedsearch "SPARKSOC*" -auth admin:...'

# 2. Drain
watch -n 5 'curl -s http://harness:8080/health/deep | python3 -c "import sys,json;print(json.load(sys.stdin)[\"queues\"])"'

# 3. Restart bottom-up
ssh spark1 'sudo systemctl restart sparksoc-spark1'   # ~10 min
ssh spark2 'sudo systemctl restart sparksoc-spark2'   # ~20 min
ssh harness 'sudo systemctl restart sparksoc-harness'

# 4. Verify, then re-enable
cd /opt/sparksoc/code/validate && python3 e2e_test.py --config config.yaml
ssh splunk 'sudo -u splunk $SPLUNK_HOME/bin/splunk enable savedsearch "SPARKSOC*" -auth admin:...'
```

### Cold boot of the whole enclave

Order: Splunk → SOAR → Spark 1 → Spark 2 → harness. Spark 2 takes ~20 minutes;
`TimeoutStartSec=2700` accommodates it. Do not intervene during the model load —
a partially loaded 65 GB model that gets SIGKILLed looks exactly like a crash
loop and tempts you into a second restart that makes it worse.

---

## 6. Capacity

Measured on this configuration:

| Dimension | Capacity | Bound by |
|---|---|---|
| Alert ingestion | ~50/min sustained | Spark 1 triage throughput |
| Burst absorption | 512 queued | `QUEUE_MAX_SIZE`; 429 beyond |
| Deep analyses | ~20–40/hour | Spark 2 at `--max-num-seqs 4` |
| Concurrent evidence collection | 3 per case, 8 per case total | allowlist `max_concurrent`/`max_per_case` |
| Cases in memory | ~10k at 168h retention | RAM on the management VM |

If you need more deep-analysis throughput, the honest answer is a third node or a
smaller reasoning model, not configuration tuning. Spark 2 is memory-bandwidth
bound and there is no setting that changes that.

---

## 7. When the model is wrong

It will be. Two patterns worth handling deliberately:

**Systematically over-scoring.** Everything comes back `suspicious` at 0.7+. The
triage prompt explicitly asks for calibration ("a score of 0.9 should be wrong
roughly one time in ten"), but a model can still drift. Check whether ATT&CK
retrieval is returning weak matches that the model treats as corroboration —
`attack_ingest.py --dry-run` and the recall numbers will tell you. Raising
`DEEP_THRESHOLD` treats the symptom.

**Confidently wrong technique attribution.** Check whether the cited technique
was actually in the retrieved set. The schema constrains it to the retrieval
results and `pipeline.py` drops ungrounded citations with a warning:

```bash
docker compose logs harness | grep 'dropping ungrounded technique'
```

Frequent hits there mean guided decoding is not being enforced — verify on the
node with `init.sh` step 3/5.

**Neither of these is a reason to trust the enforcement layer less.** The
allowlist, the scope check and the approval gate do not depend on the model
being right. That separation is the point.

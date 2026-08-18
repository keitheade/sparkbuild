# 07 — Validation and purple-team exercises

Prove the pipeline works, then measure how well.

---

## 1. Setup

```bash
cd /opt/sparksoc/code/validate
python3 -m venv venv && . venv/bin/activate
pip install --no-index --find-links /opt/sparksoc/wheelhouse -r requirements.txt

cp config.example.yaml config.yaml && chmod 600 config.yaml
$EDITOR config.yaml     # endpoints and the four keys
```

---

## 2. Layered validation

Run in this order. Each layer assumes the one below it passed.

```bash
# Layer 0 — airgap posture, on every host
bash egress_check.sh

# Layer 1 — connectivity and dependencies
python3 e2e_test.py --config config.yaml --only connectivity

# Layer 2 — model serving (catches vLLM #37030)
python3 e2e_test.py --config config.yaml --only models

# Layer 3 — retrieval
python3 e2e_test.py --config config.yaml --only retrieval

# Layer 4 — security controls
python3 e2e_test.py --config config.yaml --only security

# Layer 5 — full pipeline with sample alerts
python3 e2e_test.py --config config.yaml --only pipeline

# Layer 6 — prompt-injection resistance
python3 e2e_test.py --config config.yaml --only injection

# Everything, with a report
python3 e2e_test.py --config config.yaml --json validation-$(date +%F).json
```

### What the security layer actually asserts

| Check | Failure means |
|---|---|
| unsigned alert rejected | anything on the network can inject alerts |
| forged signature rejected | HMAC verification is not working |
| stale timestamp rejected | the replay window is open indefinitely |
| nonce replay rejected | captured deliveries can be replayed |
| allowlist loaded and sane | the model/range boundary is not in place |

Any failure here is a stop-work item. Do not leave dry-run mode with a failing
security layer.

### What the injection layer actually asserts

Three payloads: a direct instruction override, an action-injection attempt
naming a production host, and a scope-escape attempt.

The test **fails** only if a CONTAIN-tier action actually executed. It **passes**
if the enforcement layers held, and separately reports whether the model *also*
flagged the injection. That distinction is deliberate: the model noticing is
useful signal, but the guarantee comes from the JSON-schema enum and the scope
check, not from the model's judgement.

---

## 3. Performance baseline

```bash
python3 bench.py --config config.yaml --concurrency 1,2,4,8,16 --json baseline-$(date +%F).json
```

Record it. `08-RUNBOOK.md` alerts against these numbers, and "the pipeline feels
slow" is not actionable without them.

Reading the output: per-stream tok/s **should** fall as concurrency rises — GB10
decode is bandwidth-bound. What matters is whether aggregate throughput still
climbs. The concurrency at which aggregate stops climbing is your real
`max-num-seqs` ceiling, whatever the config says.

Expected shape:

| Node | Concurrency 1 | Concurrency 4 | Concurrency 16 |
|---|---|---|---|
| triage (35B-A3B MXFP4) | 60–75 tok/s | 40–55 each, higher aggregate | aggregate plateaus |
| reason (120B MXFP4) | 40–80 tok/s | 15–30 each | do not bother |

---

## 4. Rehearse with a replay exercise

Before the real purple team arrives, run the scripted chain. It requires no range
and validates the scoring pipeline itself — which is the only way to know your
detection-rate number means what you think it means.

```bash
python3 purple_replay.py replay \
  --config config.yaml \
  --plan plans/apt-chain.yaml \
  --html replay-$(date +%F).html \
  --json replay-$(date +%F).json
```

The plan includes four `stealth: true` steps — techniques the range does not
instrument. They **should** be missed. A plan with no stealth steps produces a
flattering detection rate that tells you nothing about coverage.

Expected on a healthy deployment: 60–75% detection rate (8 of 12 steps have
telemetry), MTTD under 30 s, precision lower bound above 70%.

---

## 5. Run a live exercise

### Before

```bash
# 1. Everything green
python3 e2e_test.py --config config.yaml
curl -s http://harness:8080/health/deep | python3 -m json.tool

# 2. Clock sync across every host
for h in spark1 spark2 harness splunk soar; do
  echo -n "$h: "; ssh $h 'date -u +%FT%TZ'
done

# 3. Queues empty, Spark 2 idle
curl -s http://harness:8080/metrics | grep -E 'queue_depth|backend_inflight'

# 4. Decide the autonomy posture for THIS exercise
curl -s http://harness:8080/v1/config | python3 -c 'import sys,json;print("dry_run:",json.load(sys.stdin)["actions"]["dry_run"])'
```

### During

```bash
python3 purple_replay.py live \
  --config config.yaml \
  --name "Purple Team August 2026" \
  --duration 120
```

This starts the exercise, attributes every incoming case to it, and prints a live
counter. Leave it running. Real Splunk alerts flow in through `TA-soc-harness`.

In another terminal, watch a single case develop:

```bash
curl -N http://harness:8080/v1/case/SPARKSOC-XXXX/stream
```

### After

Register the red team's actual execution log. This is what makes MTTD real —
timestamps from the plan are not the same as timestamps from execution.

```bash
# Atomic Red Team
curl -XPOST http://harness:8080/v1/exercise/EX-20260818-1400/ground-truth \
  -H 'Content-Type: application/json' \
  -d @- <<'JSON'
{"format":"atomic","events":[
  {"Technique":"T1059.001","TestName":"Encoded PowerShell","ExecutionTime":"2026-08-18T14:05:12Z","Hostname":"WIN11-RANGE-04"},
  {"Technique":"T1003.001","TestName":"LSASS dump via comsvcs","ExecutionTime":"2026-08-18T14:19:41Z","Hostname":"WIN11-RANGE-04"}
]}
JSON

# Caldera
curl -XPOST http://harness:8080/v1/exercise/EX-20260818-1400/ground-truth \
  -H 'Content-Type: application/json' \
  -d "{\"format\":\"caldera\",\"events\": $(cat caldera-operation.json | jq '.steps')}"
```

Then:

```bash
curl -XPOST http://harness:8080/v1/exercise/EX-20260818-1400/stop

python3 purple_replay.py report --config config.yaml \
  --exercise EX-20260818-1400 \
  --html exercise-report.html --json exercise-report.json
```

---

## 6. Reading the report

| Metric | Meaning | Reasonable target |
|---|---|---|
| **Detection rate** | executed steps detected at all | 70%+ where telemetry exists |
| **Exact rate** | detected at sub-technique precision | 50%+ |
| **MTTD median** | execution to triage verdict | < 30 s |
| **MTTD deep** | execution to deep verdict | < 180 s |
| **Precision (lower bound)** | escalations matching a real step | 60%+ |
| **Simulation recall** | correctly flagged as simulation | informational |

Four things the report will not tell you, stated in its own notes section:

1. **Precision is a lower bound.** Every escalation without a matching executed
   step counts as a false positive, including genuine background activity on the
   range. The true value is higher.
2. **A miss can be a telemetry gap, not a model failure.** If the technique
   produced no Splunk alert, the pipeline never had a chance. Cross-reference the
   missed steps against your detection content before blaming the model.
3. **Parent-only matches are real detections with a caveat.** T1059.001 detected
   as T1059 means an analyst reading the case would not have known which
   sub-technique was used. Track this separately; it usually points at ATT&CK
   retrieval quality rather than reasoning quality.
4. **Degraded RAG depresses exact rate.** If cases ran while Qdrant was down, the
   report says so. Re-run before drawing conclusions.

### Turning the report into work

```
Low detection rate, specific tactics       → detection content gap; write Splunk rules
Low exact rate, good detection rate        → retrieval quality; check attack_ingest recall
High MTTD                                  → queue saturation; check bench baseline
Low precision                              → DEEP_THRESHOLD too low, or noisy correlations
Many scope violations                      → allowlist range_cidrs vs. real range addressing
Injection flagged but actions not rejected → investigate immediately; the enforcement layer
```

---

## 7. Continuous validation

```bash
# Weekly, via cron on the management VM
0 6 * * 1 cd /opt/sparksoc/code/validate && ./venv/bin/python e2e_test.py \
    --config config.yaml --json /var/log/sparksoc/validation-$(date +\%F).json

# Daily audit chain check
0 * * * * curl -sf http://127.0.0.1:8080/v1/audit/verify | grep -q '"ok": true' \
    || logger -p auth.crit "SPARKSOC audit chain verification FAILED"
```

Re-run the full suite after any change to: the allowlist, either `.env`, a
container image, Splunk detection content, or SOAR assets.

---

## 8. Next

[`08-RUNBOOK.md`](08-RUNBOOK.md)

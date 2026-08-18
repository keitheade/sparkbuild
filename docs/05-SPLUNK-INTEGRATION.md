# 05 — Splunk Enterprise integration

Wire Splunk alerting to the harness.

---

## 1. Why not the stock webhook

Splunk ships a webhook alert action. It is inadequate here for three specific
reasons, and knowing them explains everything in `TA-soc-harness`:

1. **It sends only the first search result.** A correlation that fires on ten
   related events delivers one. The triage model never sees the pattern, which is
   usually the whole signal.
2. **It cannot set custom headers.** There is no way to authenticate the
   delivery. Anything that can reach port 8080 can inject fabricated alerts and,
   once you leave dry-run, drive evidence collection on the range.
3. **It does not retry.** A momentary harness restart loses the alert silently.

`TA-soc-harness` sends the full result set, signs each delivery with HMAC-SHA256
over `timestamp . nonce . body`, and retries with backoff.

A fallback endpoint for the stock webhook exists (`/v1/alert/webhook/{token}`)
for environments where installing an app on the search head is not possible. It
inherits problems 1 and 3 and only partly addresses 2. Use it if you must.

---

## 2. Install the app

```bash
# On the search head
sudo -u splunk cp -r /media/usb/sparksoc/code/splunk/TA-soc-harness \
    $SPLUNK_HOME/etc/apps/
sudo -u splunk chmod +x $SPLUNK_HOME/etc/apps/TA-soc-harness/bin/soc_harness.py
sudo systemctl restart splunk
```

Search head cluster: deploy through the deployer.

```bash
cp -r TA-soc-harness $SPLUNK_HOME/etc/shcluster/apps/
$SPLUNK_HOME/bin/splunk apply shcluster-bundle -target https://<captain>:8089
```

Confirm it registered:

```
Settings > Alert actions > "Send to SPARKSOC Harness"
```

The script uses only the Python standard library. Splunk's bundled interpreter
varies by version, and installing packages under `$SPLUNK_HOME` is a support
problem you do not want during an exercise.

---

## 3. Network path

```
Splunk search head  ──HTTPS/HTTP──►  harness:8080/v1/alert
```

Restrict at both ends:

```bash
# On the management VM
sudo ufw allow from 10.90.1.30 to any port 8080 proto tcp
sudo ufw allow from 10.90.1.31 to any port 8080 proto tcp
sudo ufw deny 8080
```

and in `harness/.env`:

```
ALLOWED_SOURCE_IPS=10.90.1.30,10.90.1.31
```

Two independent controls, because a firewall rule is easy to lose during a
maintenance window.

---

## 4. Create the correlation searches

`splunk/savedsearches.example.conf` contains five detection searches and five
baseline searches. Copy into your detection app:

```bash
sudo -u splunk cp savedsearches.example.conf \
  $SPLUNK_HOME/etc/apps/<your-detection-app>/local/savedsearches.conf
# replace the $SPLUNK_HMAC_SECRET$ placeholders with the real secret
sudo -u splunk $SPLUNK_HOME/bin/splunk reload savedsearch -auth admin:...
```

Or build one through the UI:

1. Run the search, **Save As → Alert**
2. Schedule: **Cron** `*/5 * * * *`, time range `-5m@m` to `now`
3. Trigger: **Number of Results**, greater than `0`
4. **Trigger: Once** — not "For each result". See below.
5. Throttle: 5–10 minutes, suppress on `host` and `user`
6. Add action: **Send to SPARKSOC Harness**
7. Harness URL: `http://10.90.1.40:8080/v1/alert`
8. Shared secret: the contents of `harness/secrets/splunk_hmac_secret`

### Trigger once, not per result

This is `alert.digest_mode = 1`. In digest mode the action fires once with the
whole result set — what `TA-soc-harness` is built for, and what lets the model
see the pattern across rows. Per-result mode produces one harness call per row,
floods the queue, and gives the model less context per call.

### Throttling

Splunk throttling and harness dedupe are complementary. Splunk suppression stops
the round trip entirely; harness dedupe (`DEDUPE_TTL_SECONDS`, default 900) is
the backstop for anything that gets through. Setting Splunk suppression to
roughly the harness TTL keeps the two consistent.

---

## 5. Field selection

Whatever your `| table` emits is what the model sees. Two failure modes:

**Too few fields.** Without `ParentImage`, the model cannot distinguish a
PowerShell launched by Explorer (routine) from one launched by WmiPrvSE
(lateral movement). Include the fields a human analyst would open the event to
look at.

**Too many fields.** Dumping every field spends the context budget on Splunk
internals (`splunk_server`, `linecount`, `punct`) and dilutes the signal.

Useful defaults:

| Platform | Include |
|---|---|
| Windows process | `_time host User Image CommandLine ParentImage ParentCommandLine ProcessGuid Hashes` |
| Windows logon | `_time host Account_Name Logon_Type Source_Network_Address Workstation_Name Status` |
| Windows registry | `_time host User EventCode TargetObject Details Image` |
| Linux auditd | `_time host user comm exe cmdline auid syscall key` |
| Network | `_time src_ip dest_ip dest_port protocol bytes_out app` |

`_raw` is worth including when the sourcetype is not fully field-extracted, and
worth excluding when it duplicates fields you already emit.

---

## 6. Test the delivery path

```bash
# On the search head, with a saved search that will match something:
$SPLUNK_HOME/bin/splunk dispatch savedsearch "SPARKSOC - Suspicious PowerShell Execution" \
  -auth admin:...

# Watch the alert action
tail -f $SPLUNK_HOME/var/log/splunk/splunkd.log | grep TA-soc-harness
```

Expected:

```
INFO TA-soc-harness - delivering 'SPARKSOC - Suspicious PowerShell Execution' (3 rows) to http://10.90.1.40:8080/v1/alert
INFO TA-soc-harness - harness accepted delivery: HTTP 202 {"status":"accepted","case_id":"SPARKSOC-A1B2C3D4E5F6",...}
```

On the harness:

```bash
docker compose logs -f harness | grep -E 'ALERT_RECEIVED|CASE_CREATED|TRIAGE'
curl -s http://127.0.0.1:8080/v1/cases?limit=5 | python3 -m json.tool
```

---

## 7. Forwarding the audit log back into Splunk

The harness audit log is hash-chained, which is tamper-evident but not
tamper-proof — someone with write access can rewrite the file and recompute the
chain. Forwarding each entry off-host as it is written closes that gap and gives
you SPARKSOC decisions as searchable events.

On the management VM, in the universal forwarder's `inputs.conf`:

```ini
[monitor:///var/lib/docker/volumes/harness_harness-state/_data/audit/audit.jsonl]
disabled = false
index = sparksoc_audit
sourcetype = sparksoc:audit
crcSalt = <SOURCE>
```

`props.conf`:

```ini
[sparksoc:audit]
INDEXED_EXTRACTIONS = json
KV_MODE = none
TIMESTAMP_FIELDS = ts
TIME_FORMAT = %s.%6N
SHOULD_LINEMERGE = false
TRUNCATE = 100000
```

Useful searches once it is flowing:

```spl
index=sparksoc_audit event=security.injection_suspected
| table _time case_id detail.evidence

index=sparksoc_audit event=security.scope_violation
| stats count by detail.action_id, detail.target_host

index=sparksoc_audit event=action.dispatched
| timechart span=5m count by detail.action_id

index=sparksoc_audit event=triage.verdict
| eval score=detail.threat_score
| timechart span=10m avg(score), p95(score)

index=sparksoc_audit event=approval.requested
| eval age=now()-_time | where age > 1800
| table _time case_id detail.approval_id detail.prompt
```

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `harness rejected the signature (401)` | secret mismatch or clock drift | compare the alert action secret to `secrets/splunk_hmac_secret` (no trailing newline); check `timedatectl` on both hosts |
| `connection error` | firewall or wrong URL | `curl -v http://harness:8080/health` from the search head |
| alert fires, nothing in splunkd.log | action not enabled on the search | check `action.soc_harness = 1` |
| harness receives 1 row when the search returned 20 | per-result mode | set Trigger to "Once" (`alert.digest_mode = 1`) |
| `no result rows were read` | results file expired | raise `ttl` in `alert_actions.conf` (default 300 s) |
| `harness saturated (429)` | fast queue full | check `/health/deep`; consider Splunk-side throttling |
| duplicate cases for one incident | fingerprint differs between firings | the fingerprint uses rule + host + user + process + signature; make sure those fields are stable in your `| table` |

---

## 9. Next

[`06-SOAR-INTEGRATION.md`](06-SOAR-INTEGRATION.md)

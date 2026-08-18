#!/usr/bin/env python
"""
TA-soc-harness — custom alert action that delivers Splunk alerts to the
SPARKSOC agent harness.

Why this exists instead of the stock webhook alert action:

  1. The stock webhook sends only the FIRST search result. A correlation that
     fires on ten related events delivers one of them, and the triage model
     never sees the pattern.
  2. The stock webhook cannot set custom headers, so there is no way to
     authenticate the delivery. Anyone who can reach the harness port can inject
     fabricated alerts and drive SOAR actions.
  3. The stock webhook has no retry. A momentary harness restart silently loses
     the alert.

This action reads the full gzipped result set, signs the delivery with
HMAC-SHA256 over timestamp + nonce + body, and retries with backoff.

Stdlib only — no third-party imports. Splunk's bundled Python varies by version
and installing packages into $SPLUNK_HOME is a support problem.
"""

from __future__ import annotations

import csv
import gzip
import hashlib
import hmac
import json
import os
import secrets
import ssl
import sys
import time
import urllib.error
import urllib.request

APP_NAME = "TA-soc-harness"
MAX_RESULTS = 200          # bound the payload; triage sees the first N rows
MAX_FIELD_CHARS = 8000     # a single _raw can be enormous
RETRIES = 3
BACKOFF_BASE = 2.0


# ---------------------------------------------------------------------------
# Splunk logging convention: write to stderr, prefixed with a level.
# These land in $SPLUNK_HOME/var/log/splunk/splunkd.log.
# ---------------------------------------------------------------------------
def log(level, message):
    sys.stderr.write("%s %s - %s\n" % (level, APP_NAME, message))
    sys.stderr.flush()


def read_results(results_file):
    """Read the gzipped CSV Splunk hands us and return a list of dicts."""
    if not results_file or not os.path.exists(results_file):
        log("WARN", "results file missing or not provided: %r" % results_file)
        return []

    rows = []
    try:
        with gzip.open(results_file, "rt", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for i, row in enumerate(reader):
                if i >= MAX_RESULTS:
                    log("INFO", "truncating result set at %d rows" % MAX_RESULTS)
                    break
                clean = {}
                for k, v in row.items():
                    if k is None or k.startswith("__mv_"):
                        continue          # multivalue shadow fields are noise
                    if v is None or v == "":
                        continue
                    if len(v) > MAX_FIELD_CHARS:
                        v = v[:MAX_FIELD_CHARS] + " ...[truncated]"
                    clean[k] = v
                if clean:
                    rows.append(clean)
    except Exception as exc:
        log("ERROR", "could not read results file: %s" % exc)
        return []

    return rows


def build_payload(settings, results):
    cfg = settings.get("configuration", {}) or {}
    return {
        "search_name": settings.get("search_name", "unknown"),
        "sid": settings.get("sid"),
        "owner": settings.get("owner"),
        "app": settings.get("app"),
        "server_host": settings.get("server_host"),
        "server_uri": settings.get("server_uri"),
        "results_link": settings.get("results_link"),
        "result_count": len(results),
        "trigger_time": int(time.time()),
        "results": results,
        "severity": cfg.get("severity") or None,
        "urgency": cfg.get("urgency") or None,
        "labels": [x.strip() for x in (cfg.get("labels") or "").split(",") if x.strip()],
    }


def sign(secret, timestamp, nonce, body):
    message = timestamp.encode("utf-8") + b"." + nonce.encode("utf-8") + b"." + body
    return "sha256=" + hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


def build_ssl_context(verify_flag, ca_path):
    if str(verify_flag).lower() in ("0", "false", "no"):
        log("WARN", "TLS verification disabled for the harness connection")
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_path and os.path.exists(ca_path):
        return ssl.create_default_context(cafile=ca_path)
    return ssl.create_default_context()


def deliver(url, secret, payload, verify_flag, ca_path, timeout):
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    ctx = build_ssl_context(verify_flag, ca_path) if url.lower().startswith("https") else None

    last_error = None
    for attempt in range(1, RETRIES + 1):
        # New timestamp and nonce per attempt: the harness rejects a replayed
        # nonce, so reusing one would make every retry fail as a replay.
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)

        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "TA-soc-harness/1.0")
        req.add_header("X-SparkSOC-Timestamp", timestamp)
        req.add_header("X-SparkSOC-Nonce", nonce)
        req.add_header("X-SparkSOC-Signature", sign(secret, timestamp, nonce, body))

        try:
            kwargs = {"timeout": timeout}
            if ctx is not None:
                kwargs["context"] = ctx
            with urllib.request.urlopen(req, **kwargs) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                log("INFO", "harness accepted delivery: HTTP %d %s" % (resp.status, text[:300]))
                return True

        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:400]
            except Exception:
                pass
            last_error = "HTTP %d: %s" % (exc.code, detail)

            if exc.code == 401:
                log("ERROR", "harness rejected the signature (401). The shared secret in "
                             "this alert action does not match SPLUNK_HMAC_SECRET on the "
                             "harness, or clock drift exceeds the window. Not retrying. %s" % detail)
                return False
            if exc.code == 400:
                log("ERROR", "harness rejected the payload (400). Not retrying. %s" % detail)
                return False
            if exc.code == 429:
                # Saturated harness. Honour Retry-After if present.
                wait = float(exc.headers.get("Retry-After", BACKOFF_BASE ** attempt))
                log("WARN", "harness saturated (429), backing off %.0fs" % wait)
                if attempt < RETRIES:
                    time.sleep(wait)
                continue
            log("WARN", "attempt %d/%d failed: %s" % (attempt, RETRIES, last_error))

        except urllib.error.URLError as exc:
            last_error = "connection error: %s" % exc.reason
            log("WARN", "attempt %d/%d failed: %s" % (attempt, RETRIES, last_error))
        except Exception as exc:
            last_error = "unexpected error: %s" % exc
            log("WARN", "attempt %d/%d failed: %s" % (attempt, RETRIES, last_error))

        if attempt < RETRIES:
            time.sleep(BACKOFF_BASE ** attempt)

    log("ERROR", "delivery failed after %d attempts: %s" % (RETRIES, last_error))
    return False


def main():
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        log("FATAL", "invoked without --execute; this script is a Splunk alert action")
        return 1

    try:
        settings = json.loads(sys.stdin.read())
    except Exception as exc:
        log("FATAL", "could not parse the alert payload from stdin: %s" % exc)
        return 2

    cfg = settings.get("configuration", {}) or {}

    url = (cfg.get("harness_url") or "").strip()
    secret = (cfg.get("shared_secret") or "").strip()

    if not url:
        log("FATAL", "harness_url is not configured for this alert action")
        return 3
    if not secret:
        log("FATAL", "shared_secret is not configured. Without it the harness will "
                     "reject every delivery with 401.")
        return 4

    try:
        timeout = float(cfg.get("timeout") or 30)
    except ValueError:
        timeout = 30.0

    results = read_results(settings.get("results_file"))
    if not results:
        log("WARN", "no result rows were read; sending alert metadata only. "
                    "Triage quality will be poor without result content.")

    payload = build_payload(settings, results)
    log("INFO", "delivering '%s' (%d rows) to %s"
        % (payload["search_name"], payload["result_count"], url))

    ok = deliver(url, secret, payload,
                 cfg.get("verify_tls", "1"),
                 (cfg.get("ca_bundle") or "").strip(),
                 timeout)
    return 0 if ok else 5


if __name__ == "__main__":
    sys.exit(main())

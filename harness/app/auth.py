"""Inbound authentication for Splunk -> harness.

The stock Splunk webhook alert action cannot set custom headers, cannot sign,
and sends only the first search result. TA-soc-harness (see splunk/) replaces
it and signs each delivery:

    X-SparkSOC-Timestamp : unix seconds
    X-SparkSOC-Nonce     : 32 hex chars, unique per delivery
    X-SparkSOC-Signature : sha256=<hex hmac>

    signed message = timestamp || "." || nonce || "." || raw_body

Replay protection needs both halves: the timestamp bounds the window, the nonce
cache prevents reuse inside it. A timestamp alone is not replay protection.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import time
from dataclasses import dataclass

from fastapi import Request

LOG = logging.getLogger("sparksoc.auth")

SIG_HEADER = "x-sparksoc-signature"
TS_HEADER = "x-sparksoc-timestamp"
NONCE_HEADER = "x-sparksoc-nonce"


@dataclass
class AuthResult:
    ok: bool
    reason: str = ""
    method: str = ""


class NonceCache:
    """Redis-backed when available, in-memory otherwise.

    The in-memory path exists so the harness still starts if Redis is down —
    replay protection degrades to single-process, which is correct for a
    single-container deployment and is logged loudly.
    """

    def __init__(self, redis_client=None, ttl: int = 86400):
        self._redis = redis_client
        self._ttl = ttl
        self._local: dict[str, float] = {}
        self._warned = False

    async def check_and_set(self, nonce: str) -> bool:
        """Return True if the nonce is fresh (and record it), False if replayed."""
        if self._redis is not None:
            try:
                # SET NX EX is atomic: no check-then-act race between workers.
                stored = await self._redis.set(f"sparksoc:nonce:{nonce}", "1",
                                               nx=True, ex=self._ttl)
                return bool(stored)
            except Exception as exc:  # redis down mid-flight
                if not self._warned:
                    LOG.error("Redis unavailable for nonce cache (%s); "
                              "falling back to in-process replay protection", exc)
                    self._warned = True

        now = time.time()
        if len(self._local) > 50_000:
            cutoff = now - self._ttl
            self._local = {k: v for k, v in self._local.items() if v > cutoff}
        if nonce in self._local:
            return False
        self._local[nonce] = now
        return True


def _ip_allowed(client_ip: str, allowed: list[str]) -> bool:
    if not allowed:
        return True
    try:
        addr = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for entry in allowed:
        try:
            if "/" in entry:
                if addr in ipaddress.ip_network(entry, strict=False):
                    return True
            elif addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            LOG.warning("Malformed entry in ALLOWED_SOURCE_IPS: %r", entry)
    return False


def compute_signature(secret: str, timestamp: str, nonce: str, body: bytes) -> str:
    message = timestamp.encode() + b"." + nonce.encode() + b"." + body
    digest = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


async def verify_signed_request(
    request: Request,
    body: bytes,
    secret: str,
    nonce_cache: NonceCache,
    window_seconds: int = 300,
    allowed_ips: list[str] | None = None,
) -> AuthResult:
    client_ip = _client_ip(request)

    if not _ip_allowed(client_ip, allowed_ips or []):
        return AuthResult(False, f"source ip {client_ip} not in ALLOWED_SOURCE_IPS")

    sig = request.headers.get(SIG_HEADER, "")
    ts = request.headers.get(TS_HEADER, "")
    nonce = request.headers.get(NONCE_HEADER, "")

    if not (sig and ts and nonce):
        return AuthResult(False, "missing signature, timestamp or nonce header")

    try:
        ts_val = int(ts)
    except ValueError:
        return AuthResult(False, "timestamp is not an integer")

    drift = abs(time.time() - ts_val)
    if drift > window_seconds:
        # In an airgap this is usually NTP skew between Splunk and the harness,
        # not an attack. Say so, because it is the most common false alarm.
        return AuthResult(
            False,
            f"timestamp drift {drift:.0f}s exceeds {window_seconds}s window "
            f"(check NTP sync between Splunk and the harness)",
        )

    expected = compute_signature(secret, ts, nonce, body)
    if not hmac.compare_digest(expected, sig):
        return AuthResult(False, "signature mismatch")

    if not await nonce_cache.check_and_set(nonce):
        return AuthResult(False, f"nonce {nonce[:12]}... already seen — replay rejected")

    if len(nonce) < 16:
        return AuthResult(False, "nonce too short (minimum 16 chars)")

    return AuthResult(True, method="hmac")


def verify_fallback_token(request: Request, token_in_path: str,
                          configured: str, allowed_ips: list[str] | None = None) -> AuthResult:
    """Weak fallback for the stock Splunk webhook, which cannot sign.

    Only enabled when WEBHOOK_FALLBACK_TOKEN is set. Documented as weaker
    because the token appears in the Splunk alert configuration and in any
    proxy logs along the path.
    """
    if not configured:
        return AuthResult(False, "fallback webhook endpoint is disabled")

    client_ip = _client_ip(request)
    if not _ip_allowed(client_ip, allowed_ips or []):
        return AuthResult(False, f"source ip {client_ip} not in ALLOWED_SOURCE_IPS")

    if not hmac.compare_digest(token_in_path, configured):
        return AuthResult(False, "fallback token mismatch")

    return AuthResult(True, method="fallback_token")


def _client_ip(request: Request) -> str:
    # Only trust XFF if a reverse proxy is deliberately in front. In this
    # enclave there is not one, so prefer the socket peer.
    if request.client:
        return request.client.host
    return request.headers.get("x-forwarded-for", "").split(",")[0].strip() or "unknown"

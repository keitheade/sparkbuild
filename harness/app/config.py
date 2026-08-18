"""Configuration for the SPARKSOC agent harness.

Everything is environment-driven so the same image runs in dry-run, staging and
production without a rebuild. Values that are secrets are read from Docker
secrets files when a *_FILE variant is present.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path


def _env(name: str, default: str | None = None, *, required: bool = False) -> str:
    """Read an env var, preferring a Docker-secret file if <NAME>_FILE is set."""
    file_var = os.getenv(f"{name}_FILE")
    if file_var:
        p = Path(file_var)
        if p.exists():
            return p.read_text(encoding="utf-8").strip()
    val = os.getenv(name, default)
    if required and not val:
        raise RuntimeError(f"Required configuration {name} is not set")
    return val or ""


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str, default: str = "") -> list[str]:
    raw = os.getenv(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


@dataclass(frozen=True)
class SparkEndpoint:
    base_url: str
    model: str
    api_key: str
    timeout: float
    max_concurrency: int


@dataclass(frozen=True)
class Settings:
    # ---- service ----------------------------------------------------------
    env: str = field(default_factory=lambda: _env("SPARKSOC_ENV", "production"))
    bind_host: str = field(default_factory=lambda: _env("BIND_HOST", "0.0.0.0"))
    bind_port: int = field(default_factory=lambda: _int("BIND_PORT", 8080))
    log_level: str = field(default_factory=lambda: _env("LOG_LEVEL", "INFO"))
    state_dir: Path = field(default_factory=lambda: Path(_env("STATE_DIR", "/var/lib/sparksoc")))

    # ---- Spark 1 (fast path) ---------------------------------------------
    triage_url: str = field(default_factory=lambda: _env("TRIAGE_URL", "http://10.90.1.11:8001/v1"))
    triage_model: str = field(default_factory=lambda: _env("TRIAGE_MODEL", "soc-triage"))
    triage_timeout: float = field(default_factory=lambda: _float("TRIAGE_TIMEOUT", 120.0))
    triage_concurrency: int = field(default_factory=lambda: _int("TRIAGE_CONCURRENCY", 8))

    embed_url: str = field(default_factory=lambda: _env("EMBED_URL", "http://10.90.1.11:8002/v1"))
    embed_model: str = field(default_factory=lambda: _env("EMBED_MODEL", "soc-embed"))
    embed_timeout: float = field(default_factory=lambda: _float("EMBED_TIMEOUT", 60.0))

    spark1_api_key: str = field(default_factory=lambda: _env("SPARK1_API_KEY", required=True))

    # ---- Spark 2 (deep path) ---------------------------------------------
    reason_url: str = field(default_factory=lambda: _env("REASON_URL", "http://10.90.1.12:8003/v1"))
    reason_model: str = field(default_factory=lambda: _env("REASON_MODEL", "soc-reason"))
    reason_timeout: float = field(default_factory=lambda: _float("REASON_TIMEOUT", 900.0))
    # Deliberately 2, below vLLM's --max-num-seqs 4. Backpressure should be
    # visible in harness metrics, not buried in the vLLM scheduler queue.
    reason_concurrency: int = field(default_factory=lambda: _int("REASON_CONCURRENCY", 2))
    spark2_api_key: str = field(default_factory=lambda: _env("SPARK2_API_KEY", required=True))

    # ---- Qdrant -----------------------------------------------------------
    qdrant_url: str = field(default_factory=lambda: _env("QDRANT_URL", "http://10.90.1.11:6333"))
    qdrant_api_key: str = field(default_factory=lambda: _env("QDRANT_API_KEY", required=True))
    qdrant_collection: str = field(default_factory=lambda: _env("QDRANT_COLLECTION", "attack_enterprise"))
    rag_top_k: int = field(default_factory=lambda: _int("RAG_TOP_K", 12))
    rag_techniques: int = field(default_factory=lambda: _int("RAG_TECHNIQUES", 8))
    attack_keyword_index: Path = field(
        default_factory=lambda: Path(_env("ATTACK_KEYWORD_INDEX", "/opt/sparksoc/attack/attack_keyword_index.json"))
    )

    # ---- Splunk SOAR ------------------------------------------------------
    soar_url: str = field(default_factory=lambda: _env("SOAR_URL", "https://10.90.1.20"))
    soar_token: str = field(default_factory=lambda: _env("SOAR_AUTH_TOKEN", required=True))
    soar_verify: str = field(default_factory=lambda: _env("SOAR_CA_BUNDLE", "/etc/sparksoc/soar-ca.pem"))
    soar_timeout: float = field(default_factory=lambda: _float("SOAR_TIMEOUT", 60.0))
    soar_label: str = field(default_factory=lambda: _env("SOAR_LABEL", "events"))
    soar_severity_map: str = field(default_factory=lambda: _env("SOAR_SEVERITY_MAP", "low:low,medium:medium,high:high,critical:high"))
    soar_action_poll_interval: float = field(default_factory=lambda: _float("SOAR_POLL_INTERVAL", 3.0))
    soar_action_poll_timeout: float = field(default_factory=lambda: _float("SOAR_POLL_TIMEOUT", 300.0))

    # ---- Splunk inbound auth ---------------------------------------------
    hmac_secret: str = field(default_factory=lambda: _env("SPLUNK_HMAC_SECRET", required=True))
    hmac_window_seconds: int = field(default_factory=lambda: _int("HMAC_WINDOW_SECONDS", 300))
    # Stock Splunk webhooks cannot sign. This token-in-path fallback is weaker;
    # leave empty to disable the fallback endpoint entirely.
    webhook_fallback_token: str = field(default_factory=lambda: _env("WEBHOOK_FALLBACK_TOKEN", ""))
    allowed_source_ips: list[str] = field(default_factory=lambda: _list("ALLOWED_SOURCE_IPS"))

    # ---- Redis (dedupe, nonce replay, queue overflow) ---------------------
    redis_url: str = field(default_factory=lambda: _env("REDIS_URL", "redis://redis:6379/0"))
    dedupe_ttl_seconds: int = field(default_factory=lambda: _int("DEDUPE_TTL_SECONDS", 900))
    nonce_ttl_seconds: int = field(default_factory=lambda: _int("NONCE_TTL_SECONDS", 86400))

    # ---- Pipeline ---------------------------------------------------------
    queue_max_size: int = field(default_factory=lambda: _int("QUEUE_MAX_SIZE", 512))
    workers: int = field(default_factory=lambda: _int("WORKERS", 6))
    deep_queue_max_size: int = field(default_factory=lambda: _int("DEEP_QUEUE_MAX_SIZE", 128))
    deep_workers: int = field(default_factory=lambda: _int("DEEP_WORKERS", 2))
    # Triage score above which the deep path is engaged.
    deep_threshold: float = field(default_factory=lambda: _float("DEEP_THRESHOLD", 0.45))
    deep_max_turns: int = field(default_factory=lambda: _int("DEEP_MAX_TURNS", 6))
    case_retention_hours: int = field(default_factory=lambda: _int("CASE_RETENTION_HOURS", 168))

    # ---- Actions ----------------------------------------------------------
    allowlist_path: Path = field(
        default_factory=lambda: Path(_env("ACTION_ALLOWLIST", "/opt/sparksoc/common/action_allowlist.yaml"))
    )
    # Overrides the allowlist's policy.dry_run when set. Use for a staged rollout.
    force_dry_run: bool = field(default_factory=lambda: _bool("FORCE_DRY_RUN", False))

    # ---- Audit ------------------------------------------------------------
    audit_path: Path = field(default_factory=lambda: Path(_env("AUDIT_PATH", "/var/lib/sparksoc/audit/audit.jsonl")))

    @property
    def triage_endpoint(self) -> SparkEndpoint:
        return SparkEndpoint(self.triage_url, self.triage_model, self.spark1_api_key,
                             self.triage_timeout, self.triage_concurrency)

    @property
    def reason_endpoint(self) -> SparkEndpoint:
        return SparkEndpoint(self.reason_url, self.reason_model, self.spark2_api_key,
                             self.reason_timeout, self.reason_concurrency)

    def severity_map(self) -> dict[str, str]:
        out = {}
        for pair in self.soar_severity_map.split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                out[k.strip()] = v.strip()
        return out


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

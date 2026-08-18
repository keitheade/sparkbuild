"""Async OpenAI-compatible client for the two Spark vLLM endpoints.

Handles the things that actually break in production:
  - structured output across vLLM versions (response_format json_schema, with
    a guided_json fallback for builds that predate it)
  - empty-content responses, which on sm_121 mean a kernel fault rather than a
    prompt problem (vLLM #37030) and must not be silently treated as a verdict
  - concurrency limits enforced here, not in the vLLM scheduler, so backpressure
    is measurable
  - retry with jitter on transient transport errors
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from dataclasses import dataclass
from typing import Any

import httpx

from .config import SparkEndpoint

LOG = logging.getLogger("sparksoc.llm")


class LLMError(RuntimeError):
    pass


class EmptyContentError(LLMError):
    """Model returned HTTP 200 with no content.

    On GB10 this is the signature of the SM121 Marlin MoE shared-memory race
    (vLLM #37030), not a prompting failure. Raised distinctly so the caller can
    surface actionable guidance instead of retrying forever.
    """


@dataclass
class Completion:
    content: str
    reasoning: str
    finish_reason: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: int

    def json(self) -> Any:
        return json.loads(self.content)


class SparkClient:
    def __init__(self, endpoint: SparkEndpoint, name: str):
        self.endpoint = endpoint
        self.name = name
        self._sem = asyncio.Semaphore(endpoint.max_concurrency)
        self._client = httpx.AsyncClient(
            base_url=endpoint.base_url.rstrip("/"),
            timeout=httpx.Timeout(endpoint.timeout, connect=15.0),
            headers={
                "Authorization": f"Bearer {endpoint.api_key}",
                "Content-Type": "application/json",
            },
            limits=httpx.Limits(max_connections=endpoint.max_concurrency + 4,
                                max_keepalive_connections=endpoint.max_concurrency),
        )
        self._inflight = 0
        self._total = 0
        self._errors = 0

    async def aclose(self) -> None:
        await self._client.aclose()

    # -- observability ------------------------------------------------------
    @property
    def stats(self) -> dict[str, int]:
        return {
            "inflight": self._inflight,
            "capacity": self.endpoint.max_concurrency,
            "total": self._total,
            "errors": self._errors,
        }

    async def health(self) -> bool:
        try:
            # /health lives at the server root, not under /v1
            root = str(self._client.base_url).rsplit("/v1", 1)[0]
            r = await self._client.get(f"{root}/health", timeout=5.0)
            return r.status_code == 200
        except Exception:
            return False

    # -- core ---------------------------------------------------------------
    async def complete(
        self,
        messages: list[dict[str, str]],
        *,
        schema: dict[str, Any] | None = None,
        schema_name: str = "response",
        max_tokens: int = 2048,
        temperature: float = 0.1,
        top_p: float = 0.9,
        retries: int = 3,
        allow_empty: bool = False,
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": self.endpoint.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "top_p": top_p,
        }
        if schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": schema_name, "strict": True, "schema": schema},
            }

        last_exc: Exception | None = None

        for attempt in range(1, retries + 1):
            async with self._sem:
                self._inflight += 1
                start = time.perf_counter()
                try:
                    resp = await self._client.post("/chat/completions", json=payload)

                    # Older vLLM builds reject response_format json_schema.
                    # Retry once with the legacy guided_json extra body.
                    if resp.status_code == 400 and schema is not None and "guided_json" not in payload:
                        detail = resp.text[:300]
                        LOG.warning("%s rejected response_format (%s); retrying with guided_json",
                                    self.name, detail)
                        payload.pop("response_format", None)
                        payload["guided_json"] = schema
                        payload["guided_decoding_backend"] = "xgrammar"
                        resp = await self._client.post("/chat/completions", json=payload)

                    resp.raise_for_status()
                    data = resp.json()
                    latency_ms = int((time.perf_counter() - start) * 1000)

                    choice = data["choices"][0]
                    msg = choice.get("message", {})
                    content = (msg.get("content") or "").strip()
                    # Harmony (gpt-oss) puts chain-of-thought here when a
                    # reasoning parser is configured.
                    reasoning = (msg.get("reasoning_content") or msg.get("reasoning") or "").strip()
                    usage = data.get("usage", {}) or {}

                    self._total += 1

                    if not content and not allow_empty:
                        # Distinguish a genuine kernel fault from a model that
                        # spent its whole budget on reasoning and got truncated.
                        if choice.get("finish_reason") == "length" and reasoning:
                            raise LLMError(
                                f"{self.name} exhausted max_tokens ({max_tokens}) inside the "
                                f"reasoning channel and emitted no final content. "
                                f"Raise max_tokens for this call."
                            )
                        raise EmptyContentError(
                            f"{self.name} returned empty content "
                            f"(finish_reason={choice.get('finish_reason')}, "
                            f"reasoning_chars={len(reasoning)}). On GB10 this is usually the "
                            f"SM121 Marlin MoE race (vLLM #37030) — see the escape hatches in "
                            f"the node's .env.example."
                        )

                    return Completion(
                        content=content,
                        reasoning=reasoning,
                        finish_reason=choice.get("finish_reason", "unknown"),
                        prompt_tokens=usage.get("prompt_tokens", 0),
                        completion_tokens=usage.get("completion_tokens", 0),
                        latency_ms=latency_ms,
                    )

                except EmptyContentError:
                    self._errors += 1
                    raise  # do not retry a kernel fault; it will not fix itself

                except httpx.HTTPStatusError as exc:
                    self._errors += 1
                    last_exc = exc
                    body = exc.response.text[:400]
                    if exc.response.status_code < 500 and exc.response.status_code != 429:
                        raise LLMError(f"{self.name} HTTP {exc.response.status_code}: {body}") from exc
                    LOG.warning("%s HTTP %s (attempt %d/%d): %s",
                                self.name, exc.response.status_code, attempt, retries, body)

                except (httpx.TimeoutException, httpx.TransportError) as exc:
                    self._errors += 1
                    last_exc = exc
                    LOG.warning("%s transport error (attempt %d/%d): %s",
                                self.name, attempt, retries, exc)

                finally:
                    self._inflight -= 1

            if attempt < retries:
                backoff = min(30.0, (2 ** attempt)) + random.uniform(0, 1.5)
                await asyncio.sleep(backoff)

        raise LLMError(f"{self.name} failed after {retries} attempts: {last_exc}")

    async def complete_json(
        self,
        messages: list[dict[str, str]],
        schema: dict[str, Any],
        *,
        schema_name: str = "response",
        max_tokens: int = 2048,
        temperature: float = 0.1,
        repair_attempts: int = 1,
        **kwargs: Any,
    ) -> tuple[dict[str, Any], Completion]:
        """Complete and parse JSON, with one repair round if parsing fails.

        Guided decoding makes malformed JSON rare but not impossible — long
        outputs can still hit max_tokens mid-object.
        """
        comp = await self.complete(messages, schema=schema, schema_name=schema_name,
                                   max_tokens=max_tokens, temperature=temperature, **kwargs)
        try:
            return json.loads(comp.content), comp
        except json.JSONDecodeError as exc:
            if repair_attempts <= 0:
                raise LLMError(
                    f"{self.name} produced unparseable JSON "
                    f"(finish_reason={comp.finish_reason}): {comp.content[:300]}"
                ) from exc

            LOG.warning("%s JSON parse failed (finish=%s); attempting repair",
                        self.name, comp.finish_reason)
            repair = messages + [
                {"role": "assistant", "content": comp.content},
                {"role": "user", "content":
                    "That response was not valid JSON. Return ONLY the corrected JSON object "
                    "matching the schema. No prose, no code fences."},
            ]
            # Give the repair more room — truncation is the usual cause.
            return await self.complete_json(
                repair, schema, schema_name=schema_name,
                max_tokens=int(max_tokens * 1.5), temperature=0.0,
                repair_attempts=repair_attempts - 1, **kwargs
            )


class EmbeddingClient:
    def __init__(self, base_url: str, model: str, api_key: str, timeout: float = 60.0):
        self.model = model
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout, connect=10.0),
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def embed(self, texts: list[str], retries: int = 3) -> list[list[float]]:
        last: Exception | None = None
        for attempt in range(1, retries + 1):
            try:
                r = await self._client.post("/embeddings", json={"model": self.model, "input": texts})
                r.raise_for_status()
                data = r.json()["data"]
                data.sort(key=lambda d: d.get("index", 0))
                return [d["embedding"] for d in data]
            except Exception as exc:
                last = exc
                if attempt < retries:
                    await asyncio.sleep(2 ** attempt + random.uniform(0, 1))
        raise LLMError(f"embedding failed after {retries} attempts: {last}")

    async def health(self) -> bool:
        try:
            root = str(self._client.base_url).rsplit("/v1", 1)[0]
            r = await self._client.get(f"{root}/health", timeout=5.0)
            return r.status_code == 200
        except Exception:
            return False

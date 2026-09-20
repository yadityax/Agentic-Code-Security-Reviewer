"""Provider-agnostic (OpenAI-compatible) LLM client with rate limiting, retries, budget and cache."""

import asyncio
import hashlib
import json
import re
import time
from collections import deque
from dataclasses import dataclass
from typing import Protocol, TypeVar

import httpx
from pydantic import BaseModel, ValidationError

from backend.config import Settings, get_settings

T = TypeVar("T", bound=BaseModel)


class BudgetExceededError(RuntimeError):
    pass


class LLMError(RuntimeError):
    pass


@dataclass
class Usage:
    requests: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cache_hits: int = 0
    cost_usd: float = 0.0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class LLMCache(Protocol):
    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str) -> None: ...


class MemoryCache:
    def __init__(self) -> None:
        self._d: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self._d.get(key)

    async def set(self, key: str, value: str) -> None:
        self._d[key] = value


class RedisCache:
    def __init__(self, url: str, ttl_s: int = 7 * 24 * 3600) -> None:
        import redis.asyncio as redis

        self._r = redis.from_url(url)  # type: ignore[no-untyped-call]
        self._ttl = ttl_s

    async def get(self, key: str) -> str | None:
        v = await self._r.get(f"llm:{key}")
        return v.decode() if v else None

    async def set(self, key: str, value: str) -> None:
        await self._r.set(f"llm:{key}", value, ex=self._ttl)


class TokenLimiter:
    """Sliding 60 s window over tokens. `reserve` waits until the estimate fits."""

    def __init__(self, tokens_per_minute: int) -> None:
        self.limit = tokens_per_minute
        self._events: deque[tuple[float, int]] = deque()
        self._lock = asyncio.Lock()

    def _used(self, now: float) -> int:
        while self._events and now - self._events[0][0] >= 60:
            self._events.popleft()
        return sum(t for _, t in self._events)

    async def reserve(self, tokens: int) -> tuple[float, int]:
        tokens = min(tokens, self.limit)  # a single oversized call must still be able to run
        async with self._lock:
            while True:
                now = time.monotonic()
                if self._used(now) + tokens <= self.limit:
                    entry = (now, tokens)
                    self._events.append(entry)
                    return entry
                # Re-check often: an in-flight request that settles for fewer tokens frees space long
                # before the oldest reservation would expire.
                wait = 60 - (now - self._events[0][0]) + 0.05
                await asyncio.sleep(min(max(wait, 0.05), 1.0))

    def settle(self, entry: tuple[float, int], actual: int) -> None:
        """Replace the reservation with what the provider actually billed."""
        try:
            i = self._events.index(entry)
            self._events[i] = (entry[0], actual)
        except ValueError:
            self._events.append((time.monotonic(), actual))


def extract_json(text: str) -> object:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise
        return json.loads(m[0])


class LLMClient:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        cache: LLMCache | None = None,
        budget_tokens: int | None = None,
        http: httpx.AsyncClient | None = None,
        limiter: TokenLimiter | None = None,
    ) -> None:
        self.s = settings or get_settings()
        self.cache = cache
        self.budget = budget_tokens if budget_tokens is not None else self.s.scan_token_budget
        self.usage = Usage()
        self.limiter = limiter or TokenLimiter(self.s.llm_tokens_per_minute)
        self._http = http or httpx.AsyncClient(timeout=self.s.llm_timeout_s)

    @property
    def model(self) -> str:
        return self.s.llm_model

    def _cache_key(self, system: str, user: str, model: str, effort: str) -> str:
        return hashlib.sha256(f"{model}\x1f{effort}\x1f{system}\x1f{user}".encode()).hexdigest()

    async def _chat(self, system: str, user: str, max_tokens: int, effort: str, model: str) -> str:
        if self.usage.total_tokens >= self.budget:
            raise BudgetExceededError(f"token budget {self.budget} exhausted")
        # Groq counts the *requested* max_tokens against the per-minute budget, so reserve all of it.
        est = (len(system) + len(user)) // 3 + max_tokens
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_object"},
            "temperature": 0,
            "max_tokens": max_tokens,
        }
        if effort and "gpt-oss" in model:
            body["reasoning_effort"] = effort
        url = f"{self.s.groq_base_url.rstrip('/')}/chat/completions"
        headers = {"Authorization": f"Bearer {self.s.groq_api_key.get_secret_value()}"}
        for attempt in range(self.s.llm_max_retries):
            entry = await self.limiter.reserve(est)
            try:
                r = await self._http.post(url, json=body, headers=headers)
            except httpx.TransportError:
                self.limiter.settle(entry, 0)
                await asyncio.sleep(min(2**attempt, 20))
                continue
            if r.status_code == 429 or r.status_code >= 500:
                self.limiter.settle(entry, 0)
                retry_after = float(r.headers.get("retry-after", 0) or 0)
                if r.status_code == 429 and retry_after > 300:
                    raise LLMError(
                        f"rate limit exhausted (retry in {retry_after:.0f}s): {r.text[:200]}"
                    )
                await asyncio.sleep(max(retry_after, min(2**attempt, 30)))
                continue
            if (
                r.status_code == 400
                and "Failed to generate JSON" in r.text
                and "response_format" in body
            ):
                # The provider's JSON mode rejected the model's output (often unescaped quotes in code).
                # Retry once without JSON mode; extract_json + schema validation still guard the result.
                self.limiter.settle(entry, 0)
                del body["response_format"]
                continue
            if r.status_code != 200:
                self.limiter.settle(entry, 0)
                raise LLMError(f"LLM HTTP {r.status_code}: {r.text[:300]}")
            data = r.json()
            u = data.get("usage", {})
            pt, ct = u.get("prompt_tokens", 0), u.get("completion_tokens", 0)
            self.limiter.settle(entry, pt + ct)
            self.usage.requests += 1
            self.usage.prompt_tokens += pt
            self.usage.completion_tokens += ct
            self.usage.cost_usd += (pt * self.s.llm_price_in + ct * self.s.llm_price_out) / 1e6
            return str(data["choices"][0]["message"]["content"] or "")
        raise LLMError("LLM request failed after retries")

    async def complete_json(
        self,
        system: str,
        user: str,
        schema: type[T],
        *,
        max_tokens: int = 1200,
        effort: str | None = None,
        model: str | None = None,
    ) -> T:
        """Ask for JSON matching `schema`. Retries once with the validation error on bad output."""
        model = model or self.s.llm_model
        effort = effort or self.s.llm_reasoning_effort
        key = self._cache_key(system, user, model, effort)
        if self.cache and (hit := await self.cache.get(key)):
            try:
                out = schema.model_validate(extract_json(hit))
                self.usage.cache_hits += 1
                return out
            except (ValidationError, json.JSONDecodeError):
                pass
        prompt, last_err = user, ""
        for _ in range(2):
            raw = await self._chat(system, prompt, max_tokens, effort, model)
            try:
                out = schema.model_validate(extract_json(raw))
            except (ValidationError, json.JSONDecodeError) as exc:
                last_err = str(exc)[:400]
                prompt = f"{user}\n\nYour previous reply was invalid ({last_err}). Reply with valid JSON only."
                continue
            if self.cache:
                await self.cache.set(key, raw)
            return out
        raise LLMError(f"model returned invalid JSON twice: {last_err}")

    async def aclose(self) -> None:
        await self._http.aclose()

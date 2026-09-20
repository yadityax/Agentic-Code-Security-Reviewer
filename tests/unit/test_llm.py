import asyncio
import time

import httpx
import pytest
import respx
from pydantic import BaseModel, SecretStr

from backend.config import Settings
from backend.services.llm import (
    BudgetExceededError,
    LLMClient,
    LLMError,
    MemoryCache,
    TokenLimiter,
    extract_json,
)  # fmt: skip

URL = "https://api.test/v1/chat/completions"


class Verdict(BaseModel):
    verdict: str
    confidence: float


def settings(**kw: object) -> Settings:
    return Settings(
        groq_api_key=SecretStr("k"), groq_base_url="https://api.test/v1",
        llm_max_retries=3, llm_tokens_per_minute=100_000, **kw,  # type: ignore[arg-type]
    )  # fmt: skip


def reply(content: str, pt: int = 10, ct: int = 5) -> httpx.Response:
    return httpx.Response(
        200, json={"choices": [{"message": {"content": content}}],
                   "usage": {"prompt_tokens": pt, "completion_tokens": ct}},
    )  # fmt: skip


def test_extract_json_handles_fences_and_prose() -> None:
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json('Sure! {"a": 1} hope that helps') == {"a": 1}


@respx.mock
async def test_complete_json_tracks_usage_and_cost() -> None:
    respx.post(URL).mock(
        return_value=reply('{"verdict":"TRUE_POSITIVE","confidence":0.9}', 1000, 500)
    )
    c = LLMClient(settings())
    v = await c.complete_json("sys", "usr", Verdict)
    assert v.verdict == "TRUE_POSITIVE"
    assert (c.usage.requests, c.usage.total_tokens) == (1, 1500)
    assert c.usage.cost_usd == pytest.approx((1000 * 0.15 + 500 * 0.60) / 1e6)


@respx.mock
async def test_retries_on_429_then_succeeds() -> None:
    route = respx.post(URL).mock(side_effect=[
        httpx.Response(429, headers={"retry-after": "0"}, text="slow down"),
        reply('{"verdict":"FALSE_POSITIVE","confidence":0.2}'),
    ])  # fmt: skip
    v = await LLMClient(settings()).complete_json("s", "u", Verdict)
    assert v.verdict == "FALSE_POSITIVE" and route.call_count == 2


@respx.mock
async def test_invalid_json_is_repaired_once() -> None:
    route = respx.post(URL).mock(side_effect=[
        reply("not json at all"), reply('{"verdict":"X","confidence":0.5}'),
    ])  # fmt: skip
    v = await LLMClient(settings()).complete_json("s", "u", Verdict)
    assert v.verdict == "X" and route.call_count == 2
    assert "previous reply was invalid" in route.calls[1].request.content.decode()


@respx.mock
async def test_gives_up_after_two_invalid_replies() -> None:
    respx.post(URL).mock(return_value=reply("nope"))
    with pytest.raises(LLMError):
        await LLMClient(settings()).complete_json("s", "u", Verdict)


@respx.mock
async def test_cache_avoids_second_call() -> None:
    route = respx.post(URL).mock(return_value=reply('{"verdict":"A","confidence":1}'))
    c = LLMClient(settings(), cache=MemoryCache())
    await c.complete_json("s", "u", Verdict)
    await c.complete_json("s", "u", Verdict)
    assert route.call_count == 1 and c.usage.cache_hits == 1


@respx.mock
async def test_budget_is_enforced() -> None:
    respx.post(URL).mock(return_value=reply('{"verdict":"A","confidence":1}', 900, 200))
    c = LLMClient(settings(), budget_tokens=1000)
    await c.complete_json("s", "u", Verdict)
    with pytest.raises(BudgetExceededError):
        await c.complete_json("s", "different", Verdict)


@respx.mock
async def test_reasoning_effort_sent_only_for_gpt_oss() -> None:
    route = respx.post(URL).mock(return_value=reply('{"verdict":"A","confidence":1}'))
    await LLMClient(settings(llm_model="openai/gpt-oss-20b")).complete_json("s", "u", Verdict)
    assert b'"reasoning_effort":"low"' in route.calls[0].request.content.replace(b" ", b"")
    await LLMClient(settings(llm_model="qwen/qwen3-32b")).complete_json("s", "u2", Verdict)
    assert b"reasoning_effort" not in route.calls[1].request.content


async def test_limiter_blocks_until_capacity_is_freed_by_settle() -> None:
    """A waiting request must proceed as soon as an in-flight one settles for fewer tokens (no 60 s stall)."""
    lim = TokenLimiter(1000)
    first = await lim.reserve(800)  # pessimistic estimate for a request now in flight
    t = time.monotonic()
    waiter = asyncio.create_task(lim.reserve(500))
    await asyncio.sleep(0.2)
    assert not waiter.done()  # 800 + 500 > 1000: it must wait
    lim.settle(first, 100)  # the provider reports the request only used 100 tokens
    await asyncio.wait_for(waiter, timeout=3)
    assert time.monotonic() - t < 3


async def test_limiter_window_expiry_still_releases_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lim = TokenLimiter(1000)
    await lim.reserve(900)
    real = time.monotonic
    monkeypatch.setattr("backend.services.llm.time.monotonic", lambda: real() + 61)  # 61 s later
    await asyncio.wait_for(lim.reserve(900), timeout=2)


@respx.mock
async def test_provider_json_mode_failure_is_retried_without_json_mode() -> None:
    route = respx.post(URL).mock(side_effect=[
        httpx.Response(400, text='{"error":{"message":"Failed to generate JSON. Please adjust your prompt."}}'),
        reply('{"verdict":"OK","confidence":0.7}'),
    ])  # fmt: skip
    v = await LLMClient(settings()).complete_json("s", "u", Verdict)
    assert v.verdict == "OK" and route.call_count == 2
    assert b"response_format" in route.calls[0].request.content
    assert b"response_format" not in route.calls[1].request.content

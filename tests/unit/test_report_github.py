import base64

import httpx
import pytest
import respx
from pydantic import SecretStr

from backend.config import Settings
from backend.models.finding import Analysis, Finding, PRScope, Severity, Verdict
from backend.services.github import REPORT_MARKER, GitHubClient, WriteDisabledError
from backend.services.report import fence, render_report, sanitize


def finding(**kw: object) -> Finding:
    base = dict(id="f1", scanner="semgrep", rule_id="r", file="a.py", line=3, severity=Severity.HIGH,
                title="SQL injection", cwe="CWE-89", fingerprint="fp", pr_scope=PRScope.NEW,
                evidence="q = 'x' + y", analysis=Analysis(verdict=Verdict.TRUE_POSITIVE, confidence=0.9,
                priority=0, exploitability="Attacker reads the DB.", reasoning="Concatenated."))  # fmt: skip
    return Finding(**{**base, **kw})  # type: ignore[arg-type]


def test_sanitize_neutralizes_mentions_html_and_secrets() -> None:
    out = sanitize(
        "ping @octocat <!-- hidden --> <script>x</script> [a](http://evil) AKIAZ5QW7NRTKLM4PXV2"
    )
    assert "@octocat" not in out and "@​octocat" in out
    assert "hidden" not in out and "<script>" not in out
    assert "](http" not in out and "AKIAZ5QW7NRTKLM4PXV2" not in out


def test_fence_grows_past_embedded_backticks() -> None:
    out = fence("a ``` b", "py")
    assert out.startswith("````py") and out.rstrip().endswith("````")


def test_report_structure() -> None:
    fs = [finding(), finding(id="f2", line=90, pr_scope=PRScope.EXISTING),
          finding(id="f3", line=50, analysis=Analysis(verdict=Verdict.FALSE_POSITIVE, confidence=0.8, priority=3,
                                                      reasoning="Parameterized."))]  # fmt: skip
    md = render_report(fs, scanners=["semgrep"], usage={"tokens": 1234, "cost_usd": 0.001})
    assert md.startswith(REPORT_MARKER)
    assert "1 pre-existing finding" in md and "1 finding(s) dismissed" in md
    assert "1 high" in md and "LLM: 1,234 tokens" in md


def test_report_clean_pr() -> None:
    assert "No actionable security findings" in render_report([], scanners=["semgrep"])


def test_report_never_leaks_secret_in_evidence() -> None:
    md = render_report([finding(evidence='key = "AKIAZ5QW7NRTKLM4PXV2"')], scanners=["semgrep"])
    assert "AKIAZ5QW7NRTKLM4PXV2" not in md


def gh(**kw: object) -> GitHubClient:
    return GitHubClient(
        Settings(github_token=SecretStr("t"), github_api_url="https://api.test", **kw)
    )  # type: ignore[arg-type]


@respx.mock
async def test_upsert_creates_then_updates() -> None:
    respx.get("https://api.test/repos/o/r/issues/1/comments").mock(side_effect=[
        httpx.Response(200, json=[]),
        httpx.Response(200, json=[{"id": 9, "body": f"{REPORT_MARKER} old"}]),
    ])  # fmt: skip
    post = respx.post("https://api.test/repos/o/r/issues/1/comments").mock(
        return_value=httpx.Response(201, json={"html_url": "https://x/1"}))  # fmt: skip
    patch = respx.patch("https://api.test/repos/o/r/issues/comments/9").mock(
        return_value=httpx.Response(200, json={"html_url": "https://x/9"}))  # fmt: skip
    c = gh()
    assert await c.upsert_report_comment("o/r", 1, "body") == "https://x/1" and post.called
    assert await c.upsert_report_comment("o/r", 1, "body2") == "https://x/9" and patch.called


@respx.mock
async def test_get_file_decodes_base64() -> None:
    respx.get("https://api.test/repos/o/r/contents/a.py").mock(
        return_value=httpx.Response(200, json={"content": base64.b64encode(b"print(1)").decode()}))  # fmt: skip
    assert await gh().get_file("o/r", "a.py", "main") == "print(1)"


async def test_write_tools_blocked_by_default() -> None:
    c = gh()
    with pytest.raises(WriteDisabledError):
        await c.create_branch("o/r", "b", "sha")
    with pytest.raises(WriteDisabledError):
        await c.create_pull_request("o/r", head="h", base="b", title="t", body="b")
    with pytest.raises(WriteDisabledError):
        await gh(post_pr_comments=False).upsert_report_comment("o/r", 1, "x")

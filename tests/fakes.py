import re
from typing import Any

from backend.services.llm import Usage


class FakeLLM:
    """Deterministic stand-in for LLMClient: marks every finding TRUE_POSITIVE citing the first shown line."""

    model = "fake"

    def __init__(self, verdicts: dict[str, str] | None = None) -> None:
        self.usage = Usage()
        self.verdicts = verdicts or {}
        self.calls = 0

    async def complete_json(self, system: str, user: str, schema: Any, **kw: Any) -> Any:
        self.calls += 1
        items = []
        for fid in re.findall(r'finding id="([^"]+)"', user):
            block = user.split(f'finding id="{fid}"', 1)[1]
            m = re.search(r"^\s*(\d+) \|", block, re.M)
            items.append({
                "id": fid, "verdict": self.verdicts.get(fid, "TRUE_POSITIVE"), "confidence": 0.9, "priority": 1,
                "exploitability": "attacker controlled input reaches the sink", "reasoning": "direct flow",
                "cited_lines": [int(m[1])] if m else [],
            })  # fmt: skip
        self.usage.requests += 1
        self.usage.prompt_tokens += 100
        self.usage.completion_tokens += 50
        return schema.model_validate({"results": items})

    async def aclose(self) -> None: ...


class FakeGitHub:
    def __init__(self, private: bool = False) -> None:
        self.comments: list[tuple[str, int, str]] = []
        self.private = private

    async def get_repository(self, repo: str) -> dict[str, Any]:
        return {"full_name": repo, "private": self.private}

    async def upsert_report_comment(self, repo: str, number: int, body: str) -> str:
        self.comments.append((repo, number, body))
        return f"https://github.test/{repo}/pull/{number}#c1"

    async def aclose(self) -> None: ...


class ScriptedLLM(FakeLLM):
    """FakeLLM for the analyst, plus a queue of scripted remediation proposals (each a PatchProposal dict)."""

    def __init__(self, proposals: list[dict[str, Any]]) -> None:
        super().__init__()
        self.proposals = list(proposals)
        self.remediation_prompts: list[str] = []

    async def complete_json(self, system: str, user: str, schema: Any, **kw: Any) -> Any:
        if schema.__name__ == "PatchProposal":
            self.remediation_prompts.append(user)
            self.usage.requests += 1
            if not self.proposals:
                return schema.model_validate(
                    {"can_fix": False, "reason": "no more scripted proposals"}
                )
            return schema.model_validate(self.proposals.pop(0))
        return await super().complete_json(system, user, schema, **kw)

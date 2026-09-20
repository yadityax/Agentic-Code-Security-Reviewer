"""Local CLI: scan a directory (or two git refs) without GitHub. Used for dev and the benchmark."""

import argparse
import asyncio
from pathlib import Path

from backend.graph.workflow import Deps, run_scan
from backend.services.llm import LLMClient
from backend.services.registry import build_adapters


async def main() -> None:
    ap = argparse.ArgumentParser(prog="acsr")
    ap.add_argument("path", type=Path)
    ap.add_argument("--no-llm", action="store_true", help="scanner-only, no analyst")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    llm = LLMClient()
    deps = Deps(llm=llm, adapters=build_adapters(), analyze=not args.no_llm)
    res = await run_scan(deps, args.path.resolve())
    print(res.report_md)
    print(
        f"\n-- {len(res.findings)} findings, {res.latency_s:.1f}s, {res.usage['tokens']} tokens, errors={res.scan_errors}"
    )
    await llm.aclose()


if __name__ == "__main__":
    asyncio.run(main())

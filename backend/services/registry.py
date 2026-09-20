"""Scanner adapter registry. Adapters register here as they are built."""

from backend.services.scanners.base import ScannerAdapter
from backend.services.scanners.gitleaks import GitleaksAdapter
from backend.services.scanners.semgrep import SemgrepAdapter


def build_adapters(names: set[str] | None = None) -> dict[str, ScannerAdapter]:
    all_: dict[str, ScannerAdapter] = {"semgrep": SemgrepAdapter(), "gitleaks": GitleaksAdapter()}
    try:  # optional adapters are added in later stages
        from backend.services.scanners.codeql import CodeQLAdapter

        all_["codeql"] = CodeQLAdapter()
    except ImportError:
        pass
    try:
        from backend.services.scanners.trivy import SyftAdapter, TrivyAdapter

        all_["trivy"] = TrivyAdapter()
        all_["syft"] = SyftAdapter()
    except ImportError:
        pass
    return {k: v for k, v in all_.items() if names is None or k in names}

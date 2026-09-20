"""Ground-truth matching and metrics. One-to-one matching: a prediction can explain only one vulnerability."""

from dataclasses import dataclass, field

from backend.services.cwe import CLASS_LABEL, FAMILIES, class_of, family  # noqa: F401

CONFIG_FILES = ("requirements.txt", "dockerfile", ".yml", ".yaml", ".toml", "package.json")
LINE_TOLERANCE = 6


@dataclass(frozen=True)
class Pred:
    file: str
    line: int
    cwe: str | None
    severity: str = "medium"
    title: str = ""
    verdict: str = "true_positive"  # analyst verdict for system C, else true_positive


@dataclass
class Truth:
    file: str
    line: int
    cwe: str


def _is_config(file: str) -> bool:
    low = file.lower()
    return any(low.endswith(x) or low.split("/")[-1].startswith(x) for x in CONFIG_FILES)


def matches(p: Pred, t: Truth) -> bool:
    if p.file.lstrip("./") != t.file:
        return False
    fp, ft = family(p.cwe), family(t.cwe)
    ok = fp == ft
    if (
        not ok
        and t.file.lower().startswith("dockerfile")
        and {fp, ft} <= {"CWE-16", "CWE-798", "CWE-1104"}
    ):
        ok = True  # any Dockerfile weakness is a container finding, whichever CWE a tool chose
    if not ok:
        return False
    return _is_config(t.file) or abs(p.line - t.line) <= LINE_TOLERANCE


def match_case(
    preds: list[Pred], truths: list[Truth]
) -> tuple[list[tuple[Pred, Truth]], list[Pred], list[Truth]]:
    """Greedy one-to-one matching by line proximity. Returns (matched pairs, false positives, missed truths)."""
    free = list(preds)
    pairs: list[tuple[Pred, Truth]] = []
    missed: list[Truth] = []
    for t in truths:
        cands = [p for p in free if matches(p, t)]
        if not cands:
            missed.append(t)
            continue
        best = min(cands, key=lambda p: abs(p.line - t.line))
        free.remove(best)
        pairs.append((best, t))
    return pairs, free, missed


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    safe_cases: int = 0
    safe_cases_flagged: int = 0
    per_class: dict[str, list[int]] = field(default_factory=dict)  # class -> [tp, fn]

    def add_case(self, preds: list[Pred], truths: list[Truth]) -> None:
        pairs, fps, missed = match_case(preds, truths)
        self.tp += len(pairs)
        self.fp += len(fps)
        self.fn += len(missed)
        if not truths:
            self.safe_cases += 1
            self.safe_cases_flagged += bool(preds)
        for _, t in pairs:
            self.per_class.setdefault(class_of(t.cwe), [0, 0])[0] += 1
        for t in missed:
            self.per_class.setdefault(class_of(t.cwe), [0, 0])[1] += 1

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    @property
    def fp_rate_safe_cases(self) -> float:
        return self.safe_cases_flagged / self.safe_cases if self.safe_cases else 0.0

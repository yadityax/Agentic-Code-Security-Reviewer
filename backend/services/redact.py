"""Secret redaction for anything that leaves the process: LLM prompts, logs, traces, PR comments."""

import re

PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"), "[REDACTED AWS KEY]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "[REDACTED GITHUB TOKEN]"),
    (re.compile(r"\bgsk_[A-Za-z0-9]{20,}\b"), "[REDACTED GROQ KEY]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "[REDACTED API KEY]"),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "[REDACTED SLACK TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "[REDACTED JWT]"),
    (re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{16,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)([a-z0-9_.-]*(?:secret|passw(?:or)?d|pwd|token|api[_-]?key|apikey|auth|credential)[a-z0-9_.-]*"
                r"\s*[:=]\s*)(['\"])([^'\"\n]{6,})\2"), r"\1\2[REDACTED]\2"),
    (re.compile(r"(?i)((?:postgres(?:ql)?|mysql|mongodb|redis|amqp)(?:\+\w+)?://[^:/\s]+:)([^@\s]+)(@)"), r"\1[REDACTED]\3"),
]  # fmt: skip


def redact_secrets(text: str) -> str:
    for pattern, repl in PATTERNS:
        text = pattern.sub(repl, text)
    return text

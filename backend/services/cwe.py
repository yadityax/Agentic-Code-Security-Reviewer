"""CWE families: different scanners label the same weakness with different (often neighbouring) CWEs."""

# First element of each family is its canonical CWE.
FAMILIES: list[list[str]] = [
    ["CWE-89", "CWE-564"],
    ["CWE-78", "CWE-77", "CWE-88"],
    ["CWE-79", "CWE-80", "CWE-116"],
    ["CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-99"],
    ["CWE-918"],
    ["CWE-798", "CWE-259", "CWE-321"],
    ["CWE-327", "CWE-328", "CWE-916", "CWE-759", "CWE-760", "CWE-326", "CWE-1240"],
    ["CWE-502"],
    ["CWE-639", "CWE-862", "CWE-863", "CWE-284", "CWE-285", "CWE-306", "CWE-287", "CWE-425"],
    ["CWE-1104", "CWE-937", "CWE-1035", "CWE-1395"],
    ["CWE-16", "CWE-250", "CWE-269", "CWE-732", "CWE-1188"],
    ["CWE-330", "CWE-338", "CWE-331", "CWE-335"],
    ["CWE-94", "CWE-1336", "CWE-95", "CWE-96", "CWE-74", "CWE-917"],  # code / template injection
]

CLASS_LABEL = {
    "CWE-89": "SQL injection", "CWE-79": "XSS", "CWE-78": "Command injection", "CWE-22": "Path traversal",
    "CWE-918": "SSRF", "CWE-798": "Hardcoded secrets", "CWE-327": "Weak crypto", "CWE-502": "Insecure deserialization",
    "CWE-639": "Broken access control", "CWE-1104": "Vulnerable dependency", "CWE-16": "Container misconfig",
    "CWE-330": "Weak randomness", "CWE-94": "Code/template injection",
}  # fmt: skip


def family(cwe: str | None) -> str | None:
    """Canonical CWE of the family containing `cwe` (unknown CWEs are their own family)."""
    if not cwe:
        return None
    return next((fam[0] for fam in FAMILIES if cwe in fam), cwe)


def class_of(cwe: str | None) -> str:
    f = family(cwe)
    return CLASS_LABEL.get(f or "", f or "unknown")

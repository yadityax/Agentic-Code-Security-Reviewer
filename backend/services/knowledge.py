"""Static security knowledge used to ground the analyst and remediation prompts (RAG-lite).

Kept deliberately small and curated. A Qdrant-backed store is a stretch goal (Phase 7).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Guidance:
    name: str
    exploit_when: str  # what must be true for the issue to be real
    not_exploitable_when: str
    fix: str


KB: dict[str, Guidance] = {
    "CWE-89": Guidance(
        "SQL injection",
        "attacker-influenced data reaches a SQL string built by concatenation/formatting/f-string",
        "the value is a constant, or passed as a bound parameter (?, %s placeholders with args tuple), or an ORM filter",
        "use parameterized queries / bound parameters; never build SQL with string operations",
    ),
    "CWE-78": Guidance(
        "OS command injection",
        "attacker-influenced data reaches a shell (shell=True, os.system, os.popen) or is concatenated into a command",
        "arguments are a fixed list with shell=False and the data is a single argument, or the value is a constant/validated against an allow-list",
        "use subprocess.run([...], shell=False) with an argument list; validate against an allow-list",
    ),
    "CWE-79": Guidance(
        "Cross-site scripting",
        "attacker-influenced data is rendered into HTML without escaping (Markup, |safe, render_template_string with concatenation, string-built HTML)",
        "output goes through an auto-escaping template, or is escaped (markupsafe.escape, html.escape)",
        "rely on auto-escaping templates; escape untrusted values; avoid |safe and Markup on user data",
    ),
    "CWE-22": Guidance(
        "Path traversal",
        "attacker-influenced path components are joined to a base directory and opened without normalization/containment check",
        "path is resolved and verified to stay inside the base directory (resolve + is_relative_to), or comes from a fixed allow-list, or werkzeug secure_filename/send_from_directory is used",
        "resolve the path and check it is inside the intended base directory; use send_from_directory/secure_filename",
    ),
    "CWE-918": Guidance(
        "Server-side request forgery",
        "attacker-influenced URL/host is requested server-side without allow-list validation",
        "the URL is constant, or the host is validated against an allow-list of trusted hosts and schemes",
        "validate scheme and host against an allow-list; block private/link-local ranges; do not follow redirects blindly",
    ),
    "CWE-798": Guidance(
        "Hardcoded credentials",
        "a real credential/key/token literal is present in source",
        "the value is an obvious placeholder, a test fixture, or read from the environment",
        "remove the literal, rotate the credential, load it from environment/secret manager",
    ),
    "CWE-327": Guidance(
        "Weak cryptography",
        "MD5/SHA-1/DES/ECB used for security purposes (passwords, signatures, tokens)",
        "used only for non-security purposes (cache keys, checksums) and marked so",
        "use bcrypt/scrypt/argon2 for passwords, SHA-256+ for integrity, AES-GCM for encryption",
    ),
    "CWE-328": Guidance(
        "Weak hash",
        "MD5/SHA-1 used to protect secrets or verify integrity against an attacker",
        "non-security use such as cache keys",
        "use SHA-256+ or a password KDF (argon2/bcrypt/scrypt)",
    ),
    "CWE-916": Guidance(
        "Weak password hashing",
        "passwords hashed with a fast unsalted hash",
        "not used for passwords",
        "use argon2/bcrypt/scrypt with per-user salts",
    ),
    "CWE-502": Guidance(
        "Insecure deserialization",
        "untrusted bytes reach pickle.loads / yaml.load (non-safe loader) / marshal / jsonpickle",
        "data is produced and consumed only by trusted code, or yaml.safe_load / json is used",
        "use json or yaml.safe_load; never unpickle untrusted data; sign data if pickle is unavoidable",
    ),
    "CWE-94": Guidance(
        "Code injection",
        "attacker-influenced data reaches eval/exec/compile/template compile",
        "argument is constant or ast.literal_eval on a literal",
        "avoid eval/exec; use ast.literal_eval or a safe parser",
    ),
    "CWE-95": Guidance(
        "Eval injection",
        "attacker-influenced data reaches eval()",
        "constant argument",
        "avoid eval; use ast.literal_eval",
    ),
    "CWE-611": Guidance(
        "XXE",
        "XML parsed from untrusted input with external entities enabled",
        "defusedxml is used or entities are disabled",
        "use defusedxml",
    ),
    "CWE-601": Guidance(
        "Open redirect",
        "attacker-influenced URL is used for a redirect without allow-list",
        "target is validated as a relative path or against an allow-list",
        "validate redirect targets against an allow-list",
    ),
    "CWE-352": Guidance(
        "CSRF",
        "state-changing endpoint relies on cookies without a CSRF token",
        "token-based auth in headers, or CSRF protection enabled",
        "enable CSRF protection tokens",
    ),
    "CWE-287": Guidance(
        "Improper authentication",
        "authentication can be bypassed or is missing on a sensitive endpoint",
        "endpoint is public by design",
        "enforce authentication centrally (decorator/middleware)",
    ),
    "CWE-862": Guidance(
        "Missing authorization",
        "a sensitive action or object is reachable without an ownership/role check",
        "an authorization check exists on the code path",
        "check the caller's permission for the specific object/action",
    ),
    "CWE-639": Guidance(
        "IDOR",
        "an object is fetched by a client-supplied id with no check that it belongs to the caller",
        "ownership is verified",
        "scope queries to the authenticated user or verify ownership",
    ),
    "CWE-306": Guidance(
        "Missing authentication",
        "sensitive functionality has no authentication",
        "public by design",
        "require authentication",
    ),
    "CWE-1104": Guidance(
        "Unmaintained/vulnerable component",
        "a dependency with a known CVE is used",
        "package is unused or the vulnerable function is never reached",
        "upgrade to the fixed version",
    ),
    "CWE-16": Guidance(
        "Misconfiguration",
        "container/config setting weakens isolation (root user, latest tag, exposed secrets)",
        "setting is intentional and mitigated elsewhere",
        "run as non-root, pin versions, drop privileges",
    ),
    "CWE-732": Guidance(
        "Incorrect permission assignment",
        "files/dirs made world-writable",
        "intended for public data",
        "apply least-privilege permissions",
    ),
    "CWE-330": Guidance(
        "Insufficient randomness",
        "random/uuid1 used for tokens, session ids or secrets",
        "non-security use",
        "use the secrets module",
    ),
    "CWE-295": Guidance(
        "Improper certificate validation",
        "verify=False / disabled TLS verification in production paths",
        "test-only code",
        "keep TLS verification enabled",
    ),
    "CWE-489": Guidance(
        "Debug enabled",
        "debug mode (Flask debug=True) exposed in a deployable entry point",
        "development-only script",
        "disable debug in deployable code",
    ),
}

ALIASES = {"CWE-1240": "CWE-327", "CWE-326": "CWE-327", "CWE-759": "CWE-916", "CWE-760": "CWE-916",
           "CWE-95": "CWE-94", "CWE-73": "CWE-22", "CWE-23": "CWE-22", "CWE-36": "CWE-22"}  # fmt: skip


def guidance_for(cwe: str | None) -> Guidance | None:
    if not cwe:
        return None
    return KB.get(cwe) or KB.get(ALIASES.get(cwe, ""))


def guidance_text(cwe: str | None) -> str:
    g = guidance_for(cwe)
    if not g:
        return ""
    return (f"{cwe} {g.name}. Real when: {g.exploit_when}. Not exploitable when: "
            f"{g.not_exploitable_when}. Typical fix: {g.fix}.")  # fmt: skip

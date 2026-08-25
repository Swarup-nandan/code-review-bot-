"""
Heuristic checks for SQL injection and missing input validation, modeled on the
OWASP Top 10 categories (A03: Injection). These are pattern-level checks meant
to catch common footguns quickly — the LLM pass catches the more contextual cases.
"""
import re

from app.analyzers.secrets_scanner import DiffLine
from app.models import Finding, Severity

# String formatting / concatenation feeding into a SQL-looking call.
SQL_KEYWORDS = r"(SELECT|INSERT|UPDATE|DELETE|DROP|WHERE|VALUES)"

SQLI_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    (
        "f-string interpolated directly into a SQL query",
        re.compile(rf"(?i)f['\"].*{SQL_KEYWORDS}.*\{{[^}}]+\}}.*['\"]"),
        Severity.CRITICAL,
    ),
    (
        "% or .format() string interpolation into a SQL query",
        re.compile(rf"(?i)['\"].*{SQL_KEYWORDS}.*['\"]\s*(%|\.format\()"),
        Severity.CRITICAL,
    ),
    (
        "String concatenation building a SQL query",
        re.compile(rf"(?i)['\"].*{SQL_KEYWORDS}.*['\"]\s*\+\s*\w"),
        Severity.HIGH,
    ),
    (
        "execute() called with an interpolated/concatenated string",
        re.compile(r"\.execute\(\s*(f['\"]|['\"].*['\"]\s*(%|\+))"),
        Severity.CRITICAL,
    ),
]

# Very common "trusts user input directly" smells.
INPUT_VALIDATION_PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    (
        "request data used directly without apparent validation",
        re.compile(r"(?i)(request\.(GET|POST|args|form|json)\[)"),
        Severity.LOW,
    ),
    (
        "eval()/exec() on what looks like external input",
        re.compile(r"\b(eval|exec)\s*\("),
        Severity.HIGH,
    ),
    (
        "os.system / shell=True with interpolated input",
        re.compile(r"(os\.system\(|subprocess\.\w+\([^)]*shell\s*=\s*True)"),
        Severity.HIGH,
    ),
    (
        "pickle.loads on potentially untrusted data",
        re.compile(r"pickle\.loads\("),
        Severity.MEDIUM,
    ),
]


def scan_diff_lines(lines: list[DiffLine]) -> list[Finding]:
    findings: list[Finding] = []
    for dl in lines:
        for label, pattern, severity in SQLI_PATTERNS:
            if pattern.search(dl.text):
                findings.append(
                    Finding(
                        file_path=dl.file_path,
                        line=dl.line_number,
                        severity=severity,
                        category="sql_injection",
                        message=f"{label}. Use parameterized queries / prepared statements "
                                f"(e.g. `cursor.execute(query, params)`) instead of building SQL via string interpolation.",
                        source="static",
                    )
                )
                break
        for label, pattern, severity in INPUT_VALIDATION_PATTERNS:
            if pattern.search(dl.text):
                findings.append(
                    Finding(
                        file_path=dl.file_path,
                        line=dl.line_number,
                        severity=severity,
                        category="input_validation",
                        message=f"{label}. Confirm this input is validated/sanitized before use, "
                                f"or add explicit validation (schema, allow-list, type coercion).",
                        source="static",
                    )
                )
                break
    return findings

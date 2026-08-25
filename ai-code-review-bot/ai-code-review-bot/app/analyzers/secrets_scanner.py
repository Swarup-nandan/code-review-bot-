"""
Lightweight hardcoded-secret detector.

Operates on added lines from a unified diff (lines starting with '+', excluding
the '+++' file header). Pattern set favors precision over recall — it's meant
to run on every PR without drowning reviewers in false positives.
"""
import re
from dataclasses import dataclass

from app.models import Finding, Severity

# (label, regex, severity)
PATTERNS: list[tuple[str, re.Pattern, Severity]] = [
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), Severity.CRITICAL),
    ("AWS Secret Access Key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"][A-Za-z0-9/+=]{40}['\"]"), Severity.CRITICAL),
    ("Generic API key assignment", re.compile(r"(?i)\b(api[_-]?key|apikey|secret[_-]?key)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"), Severity.HIGH),
    ("Private key block", re.compile(r"-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----"), Severity.CRITICAL),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), Severity.CRITICAL),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), Severity.CRITICAL),
    ("Generic password assignment", re.compile(r"(?i)\bpassword\s*[=:]\s*['\"](?!.*\{)[^'\"]{6,}['\"]"), Severity.HIGH),
    ("JWT-looking literal", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), Severity.MEDIUM),
    ("Database connection string with credentials", re.compile(r"(?i)(postgres|mysql|mongodb)(\+\w+)?://[^:\s]+:[^@\s]+@"), Severity.HIGH),
]

# Reduce false positives on obvious placeholders/examples.
PLACEHOLDER_HINTS = re.compile(r"(?i)(your[_-]?key|example|placeholder|xxxx|dummy|changeme|<.*>|\$\{)")


@dataclass
class DiffLine:
    file_path: str
    line_number: int  # line number in the new file
    text: str


def scan_diff_lines(lines: list[DiffLine]) -> list[Finding]:
    findings: list[Finding] = []
    for dl in lines:
        if PLACEHOLDER_HINTS.search(dl.text):
            continue
        for label, pattern, severity in PATTERNS:
            if pattern.search(dl.text):
                findings.append(
                    Finding(
                        file_path=dl.file_path,
                        line=dl.line_number,
                        severity=severity,
                        category="hardcoded_secret",
                        message=f"Possible hardcoded secret ({label}) committed in this line. "
                                f"Move it to an environment variable or secrets manager and rotate the credential if it was ever pushed.",
                        source="static",
                    )
                )
                break  # one finding per line is enough
    return findings

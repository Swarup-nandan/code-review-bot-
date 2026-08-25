"""
Runs Bandit (the standard Python security linter) against full .py file
contents fetched from the PR head, then filters results down to lines that
were actually touched in the diff — so we only comment on new/changed risk,
not pre-existing issues elsewhere in the file.
"""
import json
import subprocess
import tempfile
from pathlib import Path

from app.models import Finding, Severity

BANDIT_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def run_bandit_on_file(file_path: str, file_contents: str, changed_lines: set[int]) -> list[Finding]:
    if not file_path.endswith(".py") or not changed_lines:
        return []

    findings: list[Finding] = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_file = Path(tmp) / "target.py"
        tmp_file.write_text(file_contents, encoding="utf-8")

        try:
            proc = subprocess.run(
                ["bandit", "-f", "json", "-q", str(tmp_file)],
                capture_output=True, text=True, timeout=30,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []  # bandit not installed or timed out — degrade gracefully

        if not proc.stdout.strip():
            return []

        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []

        for item in report.get("results", []):
            line_no = item.get("line_number")
            if line_no not in changed_lines:
                continue  # only surface issues on lines this PR actually touched
            findings.append(
                Finding(
                    file_path=file_path,
                    line=line_no,
                    severity=BANDIT_SEVERITY_MAP.get(item.get("issue_severity", "LOW"), Severity.LOW),
                    category="static_analysis",
                    message=f"{item.get('test_name')}: {item.get('issue_text')}",
                    source="static",
                )
            )
    return findings

"""Quick sanity tests for the diff parser and pattern-based analyzers — run with: pytest tests/"""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.analyzers.diff_parser import added_lines_from_patch
from app.analyzers.secrets_scanner import scan_diff_lines as scan_secrets
from app.analyzers.injection_checks import scan_diff_lines as scan_injection

SQLI_PATCH = """@@ -1,3 +1,4 @@
 def get_user(user_id):
     conn = get_db()
+    query = f"SELECT * FROM users WHERE id = {user_id}"
+    return conn.execute(query).fetchone()
"""

SECRET_PATCH = """@@ -1,2 +1,3 @@
 import os
+aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYzt7Jd91abc"
"""

SAFE_PATCH = """@@ -1,2 +1,3 @@
 def add(a, b):
+    return a + b
"""


def test_diff_parser_extracts_added_lines_with_correct_numbers():
    lines = added_lines_from_patch("app.py", SQLI_PATCH)
    assert len(lines) == 2
    assert lines[0].line_number == 3
    assert lines[1].line_number == 4


def test_sql_injection_detected():
    lines = added_lines_from_patch("app.py", SQLI_PATCH)
    findings = scan_injection(lines)
    assert any(f.category == "sql_injection" for f in findings)
    assert findings[0].severity.value in ("critical", "high")


def test_hardcoded_secret_detected():
    lines = added_lines_from_patch("config.py", SECRET_PATCH)
    findings = scan_secrets(lines)
    assert any(f.category == "hardcoded_secret" for f in findings)


def test_clean_code_produces_no_findings():
    lines = added_lines_from_patch("math_utils.py", SAFE_PATCH)
    assert scan_injection(lines) == []
    assert scan_secrets(lines) == []


if __name__ == "__main__":
    test_diff_parser_extracts_added_lines_with_correct_numbers()
    test_sql_injection_detected()
    test_hardcoded_secret_detected()
    test_clean_code_produces_no_findings()
    print("All sanity tests passed.")

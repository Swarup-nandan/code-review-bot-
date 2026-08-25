"""
LLM-based review pass. Static analyzers catch known patterns; this pass catches
the contextual stuff — logic bugs, missing error handling, unclear naming,
security issues that don't match a regex (broken access control, missing
auth checks, race conditions, etc.) — the same categories your resume's
pentest work covers (OWASP broken-access-control / auth-failure classes).

Uses structured JSON output so findings map cleanly onto the same Finding
model as the static analyzers and can be posted as GitHub review comments.
"""
import json

import httpx

from app.config import settings
from app.models import Finding, Severity

SYSTEM_PROMPT = """You are a senior software engineer performing a focused code review on a pull \
request diff. You review for:
1. Security issues (OWASP-class): broken access control, missing authn/authz checks, \
injection beyond obvious SQL patterns, insecure deserialization, SSRF, path traversal, \
race conditions, insecure defaults.
2. Correctness: logic errors, off-by-one, unhandled exceptions, resource leaks.
3. Code quality: only flag issues that materially affect readability or maintainability \
— do not nitpick style that a linter/formatter would already catch.

Only report genuine issues. Do not invent problems to have something to say. If the diff \
looks fine, return an empty findings list.

Respond ONLY with JSON, no prose, no markdown fences, in this exact shape:
{"findings": [{"line": <int or null>, "severity": "critical"|"high"|"medium"|"low", \
"category": "<short category>", "message": "<one or two sentence explanation and suggested fix>"}]}

The "line" field must refer to a line number that appears in the diff's added lines (lines \
prefixed with the line number given in the diff). If you cannot confidently pin an issue to \
a specific added line, set line to null."""


def _build_user_prompt(file_path: str, patch: str) -> str:
    return f"File: {file_path}\n\nDiff (unified format, added lines are prefixed with the new line number):\n{patch}"


async def review_file(file_path: str, annotated_patch: str) -> list[Finding]:
    """
    annotated_patch: the patch text with each added line prefixed by its new-file
    line number, e.g. "42: + user = User.objects.get(id=request.GET['id'])"
    This lets the model reference real line numbers without us doing fuzzy matching.
    """
    if not settings.anthropic_api_key:
        return []

    payload = {
        "model": settings.llm_model,
        "max_tokens": 1500,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": _build_user_prompt(file_path, annotated_patch)}],
    }

    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": settings.anthropic_api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=payload,
        )
        resp.raise_for_status()
        data = resp.json()

    text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
    raw = "".join(text_blocks).strip()
    raw = raw.removeprefix("```json").removeprefix("```").removesuffix("```").strip()

    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings: list[Finding] = []
    for item in parsed.get("findings", []):
        try:
            severity = Severity(item.get("severity", "low"))
        except ValueError:
            severity = Severity.LOW
        findings.append(
            Finding(
                file_path=file_path,
                line=item.get("line"),
                severity=severity,
                category=item.get("category", "general"),
                message=item.get("message", ""),
                source="llm",
            )
        )
    return findings

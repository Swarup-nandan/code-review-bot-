import logging

from app import db, github_client
from app.analyzers import bandit_check, diff_parser, injection_checks, llm_reviewer, secrets_scanner
from app.config import settings
from app.models import Finding

logger = logging.getLogger("reviewer")

# Skip generated/vendored/binary-ish paths — reviewing these wastes LLM budget and adds noise.
SKIP_PATH_HINTS = ("/dist/", "/build/", "/vendor/", "/node_modules/", ".min.js", ".lock", ".svg", ".png", ".jpg")


def _should_skip(path: str) -> bool:
    return any(hint in path for hint in SKIP_PATH_HINTS)


def _annotate_patch_with_line_numbers(patch: str) -> str:
    """Rewrites a unified diff so each added line is prefixed with its new-file line number,
    which is what we ask the LLM to reference back."""
    out_lines = []
    new_line_no = None
    for raw in patch.splitlines():
        header = diff_parser.HUNK_HEADER.match(raw)
        if header:
            new_line_no = int(header.group(1))
            out_lines.append(raw)
            continue
        if new_line_no is None:
            out_lines.append(raw)
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            out_lines.append(f"{new_line_no}: {raw}")
            new_line_no += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            out_lines.append(raw)
        else:
            out_lines.append(raw)
            new_line_no += 1
    return "\n".join(out_lines)


async def review_pull_request(repo: str, pr_number: int, pr_title: str, author: str, head_sha: str) -> dict:
    review_id = db.create_review(repo, pr_number, pr_title, author)

    files = await github_client.get_pr_files(repo, pr_number)
    files = [f for f in files if not _should_skip(f.filename) and f.status != "removed"]
    files = files[: settings.max_files_per_pr]

    all_findings: list[Finding] = []
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in files:
        if not f.patch:
            continue

        diff_lines = diff_parser.added_lines_from_patch(f.filename, f.patch)

        # Static, fast, deterministic checks first.
        file_findings: list[Finding] = []
        file_findings += secrets_scanner.scan_diff_lines(diff_lines)
        file_findings += injection_checks.scan_diff_lines(diff_lines)

        # Bandit for Python files, restricted to changed lines.
        if f.filename.endswith(".py"):
            full_contents = await github_client.get_file_contents(repo, f.filename, head_sha)
            if full_contents:
                changed_lines = {dl.line_number for dl in diff_lines}
                file_findings += bandit_check.run_bandit_on_file(f.filename, full_contents, changed_lines)

        # LLM pass, capped to keep cost/latency predictable.
        patch_for_llm = f.patch[: settings.max_diff_chars_per_file]
        annotated = _annotate_patch_with_line_numbers(patch_for_llm)
        try:
            file_findings += await llm_reviewer.review_file(f.filename, annotated)
        except Exception as exc:  # LLM pass is best-effort — never fail the whole review over it
            logger.warning("LLM review failed for %s: %s", f.filename, exc)

        for finding in file_findings:
            db.add_finding(review_id, finding.file_path, finding.line, finding.severity.value,
                            finding.category, finding.message, finding.source)
            counts[finding.severity.value] += 1

        all_findings.extend(file_findings)

    db.finalize_review(review_id, len(files), counts)

    if settings.github_token:
        await github_client.post_review_comments(repo, pr_number, head_sha, all_findings)
        await github_client.post_summary_comment(repo, pr_number, all_findings)

    return {"review_id": review_id, "files_reviewed": len(files), "findings": len(all_findings), "counts": counts}

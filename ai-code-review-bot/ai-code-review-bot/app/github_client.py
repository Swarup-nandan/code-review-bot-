import base64

import httpx

from app.config import settings
from app.models import Finding, PRFile

GITHUB_API = "https://api.github.com"


def _headers() -> dict:
    # In production, exchange the GitHub App's private key for a short-lived
    # installation token here instead of a static PAT. Kept simple for the MVP.
    return {
        "Authorization": f"Bearer {settings.github_token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def get_pr_files(repo: str, pr_number: int) -> list[PRFile]:
    files: list[PRFile] = []
    page = 1
    async with httpx.AsyncClient(timeout=30) as client:
        while True:
            resp = await client.get(
                f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}/files",
                headers=_headers(),
                params={"per_page": 100, "page": page},
            )
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break
            for f in batch:
                files.append(PRFile(
                    filename=f["filename"],
                    status=f["status"],
                    patch=f.get("patch"),
                    additions=f.get("additions", 0),
                    deletions=f.get("deletions", 0),
                    raw_url=f.get("raw_url"),
                ))
            page += 1
    return files


async def get_file_contents(repo: str, path: str, ref: str) -> str | None:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.get(
            f"{GITHUB_API}/repos/{repo}/contents/{path}",
            headers=_headers(),
            params={"ref": ref},
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("encoding") != "base64":
            return None
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")


async def post_review_comments(repo: str, pr_number: int, head_sha: str, findings: list[Finding]) -> None:
    """Posts one GitHub PR review containing an inline comment per finding that has a line number."""
    line_findings = [f for f in findings if f.line is not None]
    if not line_findings:
        return

    comments = [
        {"path": f.file_path, "line": f.line, "side": "RIGHT", "body": f.as_comment_body()}
        for f in line_findings
    ]

    body = f"🤖 Automated review found **{len(findings)}** issue(s) — see inline comments."
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{GITHUB_API}/repos/{repo}/pulls/{pr_number}/reviews",
            headers=_headers(),
            json={
                "commit_id": head_sha,
                "body": body,
                "event": "COMMENT",
                "comments": comments,
            },
        )
        resp.raise_for_status()


async def post_summary_comment(repo: str, pr_number: int, findings: list[Finding]) -> None:
    """Fallback: a single summary comment, used for findings without a resolvable line number."""
    unresolvable = [f for f in findings if f.line is None]
    if not unresolvable:
        return
    lines = "\n".join(f"- **{f.severity.value.upper()}** [{f.file_path}] {f.category}: {f.message}" for f in unresolvable)
    body = f"🤖 Additional findings without a specific line reference:\n\n{lines}"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{GITHUB_API}/repos/{repo}/issues/{pr_number}/comments",
            headers=_headers(),
            json={"body": body},
        )
        resp.raise_for_status()

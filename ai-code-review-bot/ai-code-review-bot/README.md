# AI Code Review Bot

A GitHub App-style service that reviews pull requests automatically: static
security/quality checks + an LLM pass, posted back as inline PR comments,
with a dashboard showing findings across your repos.

## How it works

```
GitHub PR opened/updated
        │  (webhook: pull_request event)
        ▼
FastAPI  /webhook/github  ──verifies HMAC signature──▶ queues background task
        │
        ▼
reviewer.review_pull_request()
        │
        ├─▶ github_client.get_pr_files()        fetch changed files + diffs
        │
        ├─▶ analyzers/secrets_scanner.py         regex: hardcoded keys/tokens/passwords
        ├─▶ analyzers/injection_checks.py        regex: SQLi patterns, eval/exec, shell=True
        ├─▶ analyzers/bandit_check.py            Bandit static analysis (Python files, changed lines only)
        ├─▶ analyzers/llm_reviewer.py            Claude reviews the diff for logic/security issues
        │       regex checks catch known patterns; the model catches everything contextual
        │       (missing auth checks, broken access control, race conditions, etc.)
        │
        ├─▶ db.py (SQLite)                        every finding stored for the dashboard
        │
        └─▶ github_client.post_review_comments()  inline comments on the exact changed lines
                                                    + a summary comment for anything unpinnable
```

Each analyzer returns the same `Finding` model (file, line, severity, category,
message, source), so static and LLM findings merge into one review with no
special-casing downstream.

## Why this design

- **Diff-scoped, not whole-file.** Every check (including Bandit) is filtered
  to lines the PR actually changed. Flagging pre-existing issues elsewhere in
  a file the author didn't touch is how review bots become noise people mute.
- **Static checks run first and never depend on the LLM.** Even with no API
  key configured, secrets/SQLi/Bandit checks still work — the LLM pass is
  additive, not load-bearing.
- **Line numbers are real, not fuzzy-matched.** The diff parser tracks the
  new-file line number through the unified diff, and the LLM is given the
  same annotated line numbers to reference — so inline comments land on the
  right line via GitHub's review API instead of a generic PR comment.
- **Best-effort LLM pass.** If the model call fails or returns unparseable
  output, that file's LLM findings are just dropped — the rest of the review
  still posts.

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# fill in GITHUB_WEBHOOK_SECRET, GITHUB_TOKEN, ANTHROPIC_API_KEY
```

For an MVP/personal use, a classic GitHub Personal Access Token (`repo` scope)
in `GITHUB_TOKEN` is enough — that's what `github_client.py` uses by default.
To run this as an installable GitHub App across multiple repos/orgs, register
an App, and swap `_headers()` in `github_client.py` to exchange the App's
private key for a short-lived installation access token per request instead.

### 3. Run it

```bash
uvicorn app.main:app --reload --port 8000
```

- Dashboard: `http://localhost:8000/dashboard/`
- API docs: `http://localhost:8000/docs`

### 4. Expose it and point a webhook at it

For local testing, tunnel port 8000 (e.g. `ngrok http 8000`), then on your
GitHub repo: **Settings → Webhooks → Add webhook**
- Payload URL: `https://<your-tunnel>/webhook/github`
- Content type: `application/json`
- Secret: same value as `GITHUB_WEBHOOK_SECRET`
- Events: just "Pull requests"

Open or update a PR and the bot reviews it within a few seconds.

## Project layout

```
app/
  main.py               FastAPI app, webhook endpoint, dashboard API
  reviewer.py            orchestrates all analyzers per PR
  github_client.py       GitHub REST API calls (fetch diffs, post comments)
  db.py                  SQLite persistence for the dashboard
  config.py               env-driven settings
  analyzers/
    diff_parser.py        unified diff → addressable (file, line) pairs
    secrets_scanner.py     hardcoded secrets/keys/tokens
    injection_checks.py    SQLi + input-validation pattern checks
    bandit_check.py        Bandit wrapper, filtered to changed lines
    llm_reviewer.py        Claude review pass, structured JSON output
dashboard/
  index.html              stats + recent PRs, vanilla JS polling /api/stats
tests/
  test_analyzers.py       sanity tests for the diff parser + pattern checks
```

## Extending it
- **More languages:** `bandit_check.py` is Python-only; add an equivalent
  wrapper for `semgrep --config=auto` (language-agnostic) alongside it.
- **PR status checks:** post a commit status (`POST /repos/{repo}/statuses/{sha}`)
  that fails the check on any `critical` finding, so it can gate merges.
- **Team-wide dashboard:** the SQLite schema already aggregates by repo — add
  a `GROUP BY repo` view to `db.get_stats()` for a per-repo breakdown.
- **Cost control:** `MAX_DIFF_CHARS_PER_FILE` and `MAX_FILES_PER_PR` in
  `.env` cap LLM spend per review; tune down for very large PRs.

## Tests

```bash
pytest tests/
```

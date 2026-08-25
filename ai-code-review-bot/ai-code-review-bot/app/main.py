import hashlib
import hmac
import logging

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app import db
from app.config import settings
from app.reviewer import review_pull_request

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI(title="AI Code Review Bot")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    db.init_db()


def _verify_signature(payload_body: bytes, signature_header: str | None) -> None:
    if not settings.github_webhook_secret:
        return  # no secret configured — skip verification (dev mode only)
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing X-Hub-Signature-256 header")

    expected = "sha256=" + hmac.new(
        settings.github_webhook_secret.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise HTTPException(status_code=401, detail="Invalid signature")


@app.post("/webhook/github")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
):
    raw_body = await request.body()
    _verify_signature(raw_body, x_hub_signature_256)
    payload = await request.json()

    if x_github_event != "pull_request":
        return {"status": "ignored", "reason": f"event={x_github_event}"}

    action = payload.get("action")
    if action not in ("opened", "synchronize", "reopened"):
        return {"status": "ignored", "reason": f"action={action}"}

    pr = payload["pull_request"]
    repo = payload["repository"]["full_name"]
    pr_number = pr["number"]
    pr_title = pr.get("title", "")
    author = pr["user"]["login"]
    head_sha = pr["head"]["sha"]

    background_tasks.add_task(review_pull_request, repo, pr_number, pr_title, author, head_sha)

    return {"status": "queued", "repo": repo, "pr_number": pr_number}


@app.get("/api/stats")
def api_stats():
    return db.get_stats()


@app.get("/api/reviews/{review_id}/findings")
def api_review_findings(review_id: int):
    return db.get_findings_for_review(review_id)


@app.get("/health")
def health():
    return {"status": "ok"}


# Serves the dashboard at /dashboard (mounted last so /api and /webhook routes take priority)
app.mount("/dashboard", StaticFiles(directory="dashboard", html=True), name="dashboard")

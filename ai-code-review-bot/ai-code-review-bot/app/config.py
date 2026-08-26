import os
from dataclasses import dataclass


@dataclass
class Settings:
    github_webhook_secret: str = os.environ.get("GITHUB_WEBHOOK_SECRET", "")
    github_app_id: str = os.environ.get("GITHUB_APP_ID", "")
    github_private_key_path: str = os.environ.get("GITHUB_PRIVATE_KEY_PATH", "")
    # Fallback for local/dev use with a classic PAT instead of a GitHub App installation token.
    github_token: str = os.environ.get("GITHUB_TOKEN", "")

    anthropic_api_key: str = os.environ.get("ANTHROPIC_API_KEY", "")
    llm_model: str = os.environ.get("LLM_MODEL", "claude-sonnet-4-6")

    database_path: str = os.environ.get("DATABASE_PATH", "reviewbot.db")

    # Cap how much diff we send to the LLM per file, to control cost/latency.
    max_diff_chars_per_file: int = int(os.environ.get("MAX_DIFF_CHARS_PER_FILE", "6000"))
    max_files_per_pr: int = int(os.environ.get("MAX_FILES_PER_PR", "25"))
    
settings = Settings()

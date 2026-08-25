from enum import Enum
from typing import Optional

from pydantic import BaseModel


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(BaseModel):
    file_path: str
    line: Optional[int] = None
    severity: Severity
    category: str          # e.g. "sql_injection", "hardcoded_secret", "input_validation", "quality"
    message: str
    source: str             # "static" or "llm"

    def as_comment_body(self) -> str:
        icon = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "⚪",
        }[self.severity]
        return f"{icon} **{self.severity.value.upper()} · {self.category}**\n\n{self.message}\n\n_source: {self.source}_"


class PRFile(BaseModel):
    filename: str
    status: str
    patch: Optional[str] = None
    additions: int = 0
    deletions: int = 0
    raw_url: Optional[str] = None

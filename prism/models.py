"""
Pydantic models for Prism review data structures.

Defines the schema for review comments, analysis results,
and API request/response types.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Comment severity levels."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class ReviewCategory(str, Enum):
    """Categories of review findings."""

    BUG = "bug"
    SECURITY = "security"
    PERFORMANCE = "performance"
    STYLE = "style"
    MAINTAINABILITY = "maintainability"
    TESTING = "testing"
    DOCUMENTATION = "documentation"
    ARCHITECTURE = "architecture"


class ReviewMode(str, Enum):
    """Available review modes."""

    FULL = "full"
    SECURITY = "security"
    STYLE = "style"
    QUICK = "quick"


class InlineComment(BaseModel):
    """A single inline review comment to post on a PR."""

    path: str = Field(..., description="File path relative to repo root")
    line: int = Field(..., ge=1, description="Line number in the file")
    body: str = Field(..., description="Comment body in Markdown")
    severity: Severity = Severity.INFO
    category: ReviewCategory = ReviewCategory.BUG
    suggestion: Optional[str] = Field(
        None, description="Suggested code fix"
    )

    def to_github_body(self) -> str:
        """Format comment body for GitHub API."""
        severity_emoji = {
            Severity.INFO: "ℹ️",
            Severity.WARNING: "⚠️",
            Severity.ERROR: "❌",
            Severity.CRITICAL: "🚨",
        }
        emoji = severity_emoji.get(self.severity, "")
        parts = [f"{emoji} **{self.category.value.upper()}** ({self.severity.value})", ""]
        parts.append(self.body)
        if self.suggestion:
            parts.extend(["", "**Suggested fix:**", "```python", self.suggestion, "```"])
        return "\n".join(parts)


class FileAnalysis(BaseModel):
    """Analysis results for a single file."""

    path: str
    language: Optional[str] = None
    comments: list[InlineComment] = Field(default_factory=list)
    summary: str = ""
    risk_score: float = Field(0.0, ge=0.0, le=10.0)


class ReviewResult(BaseModel):
    """Complete review result for a pull request."""

    pr_owner: str
    pr_repo: str
    pr_number: int
    head_sha: str
    mode: ReviewMode = ReviewMode.FULL
    files: list[FileAnalysis] = Field(default_factory=list)
    overall_summary: str = ""
    total_comments: int = 0
    risk_score: float = Field(0.0, ge=0.0, le=10.0)
    reviewed_at: datetime = Field(default_factory=datetime.utcnow)

    @property
    def all_comments(self) -> list[InlineComment]:
        """Flatten all inline comments from all files."""
        return [c for f in self.files for c in f.comments]

    @property
    def critical_count(self) -> int:
        return sum(1 for c in self.all_comments if c.severity == Severity.CRITICAL)

    @property
    def error_count(self) -> int:
        return sum(1 for c in self.all_comments if c.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.all_comments if c.severity == Severity.WARNING)

    def to_check_run_output(self) -> dict:
        """Format as GitHub Check Run output."""
        title = f"Prism Review: {self.total_comments} comments"
        if self.critical_count:
            title = f"🚨 {self.critical_count} critical issues found"
        elif self.error_count:
            title = f"❌ {self.error_count} errors found"

        summary_parts = [
            f"**Mode:** {self.mode.value}",
            f"**Files reviewed:** {len(self.files)}",
            f"**Total comments:** {self.total_comments}",
            f"**Risk score:** {self.risk_score:.1f}/10",
            "",
        ]
        if self.overall_summary:
            summary_parts.extend(["## Summary", self.overall_summary])

        return {
            "title": title[:255],
            "summary": "\n".join(summary_parts),
            "annotations": [],
        }


class WebhookPayload(BaseModel):
    """GitHub webhook payload wrapper."""

    action: str
    number: Optional[int] = None
    pull_request: Optional[dict] = None
    repository: dict
    sender: dict


class ReviewRequest(BaseModel):
    """Internal review request passed between components."""

    owner: str
    repo: str
    pr_number: int
    head_sha: str
    base_sha: str
    mode: ReviewMode = ReviewMode.FULL
    files_changed: list[str] = Field(default_factory=list)


class HealthCheck(BaseModel):
    """Health check response."""

    status: str = "ok"
    version: str
    uptime_seconds: float
    reviews_completed: int = 0
    reviews_failed: int = 0

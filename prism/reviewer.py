"""
Prism review engine.

Orchestrates the full code review pipeline:
1. Fetch PR diff and changed files
2. Parse diffs into reviewable chunks
3. Send to LLM for analysis
4. Collect and deduplicate findings
5. Post inline comments to GitHub
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from .config import ReviewConfig, get_config
from .github_client import GitHubClient, PullRequestInfo
from .models import (
    FileAnalysis,
    InlineComment,
    ReviewCategory,
    ReviewMode,
    ReviewRequest,
    ReviewResult,
    Severity,
)

logger = logging.getLogger(__name__)


@dataclass
class DiffHunk:
    """A parsed diff hunk for a single file."""

    path: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str] = field(default_factory=list)
    context_before: list[str] = field(default_factory=list)
    context_after: list[str] = field(default_factory=list)


@dataclass
class DiffFile:
    """Parsed diff information for a single file."""

    path: str
    old_path: Optional[str] = None
    status: str = "modified"  # added, modified, deleted, renamed
    additions: int = 0
    deletions: int = 0
    hunks: list[DiffHunk] = field(default_factory=list)

    @property
    def patch_text(self) -> str:
        """Reconstruct the patch text from hunks."""
        parts = []
        for hunk in self.hunks:
            header = (
                f"@@ -{hunk.old_start},{hunk.old_count} "
                f"+{hunk.new_start},{hunk.new_count} @@"
            )
            parts.append(header)
            parts.extend(hunk.lines)
        return "\n".join(parts)


def parse_diff(diff_text: str) -> list[DiffFile]:
    """Parse a unified diff string into structured DiffFile objects."""
    files: list[DiffFile] = []
    current_file: Optional[DiffFile] = None
    current_hunk: Optional[DiffHunk] = None

    hunk_pattern = re.compile(
        r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$"
    )

    for line in diff_text.split("\n"):
        if line.startswith("diff --git"):
            # Extract file paths from "diff --git a/path b/path"
            match = re.search(r"diff --git a/(.+?) b/(.+?)$", line)
            if match:
                current_file = DiffFile(path=match.group(2))
                files.append(current_file)
            continue

        if current_file is None:
            continue

        if line.startswith("--- a/"):
            current_file.old_path = line[6:]
            continue
        if line.startswith("+++ b/"):
            continue
        if line.startswith("new file"):
            current_file.status = "added"
            continue
        if line.startswith("deleted file"):
            current_file.status = "deleted"
            continue
        if line.startswith("rename from"):
            current_file.status = "renamed"
            continue

        hunk_match = hunk_pattern.match(line)
        if hunk_match:
            current_hunk = DiffHunk(
                path=current_file.path,
                old_start=int(hunk_match.group(1)),
                old_count=int(hunk_match.group(2) or "1"),
                new_start=int(hunk_match.group(3)),
                new_count=int(hunk_match.group(4) or "1"),
            )
            current_file.hunks.append(current_hunk)
            continue

        if current_hunk is not None:
            current_hunk.lines.append(line)
            if line.startswith("+") and not line.startswith("+++"):
                current_file.additions += 1
            elif line.startswith("-") and not line.startswith("---"):
                current_file.deletions += 1

    return files


def should_ignore_file(path: str, patterns: tuple[str, ...]) -> bool:
    """Check if a file should be ignored based on glob patterns."""
    import fnmatch

    for pattern in patterns:
        if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path.split("/")[-1], pattern):
            return True
    return False


class ReviewEngine:
    """Core review engine that coordinates analysis and commenting."""

    def __init__(
        self,
        github_client: GitHubClient,
        config: Optional[ReviewConfig] = None,
    ) -> None:
        self._github = github_client
        self._config = config or get_config().review
        self._start_time = time.monotonic()
        self._reviews_completed = 0
        self._reviews_failed = 0

    async def review_pr(
        self,
        pr_info: PullRequestInfo,
        mode: ReviewMode = ReviewMode.FULL,
        analyzer: Optional[object] = None,
        llm_caller: Optional[object] = None,
    ) -> ReviewResult:
        """Run a full review on a pull request.

        Args:
            pr_info: Parsed PR information from webhook.
            mode: Review mode (full, security, style, quick).
            analyzer: Optional static analyzer instance.
            llm_caller: Optional LLM callable for AI review.

        Returns:
            Complete review result with comments.
        """
        logger.info(
            f"Starting {mode.value} review of {pr_info.owner}/{pr_info.repo}#{pr_info.pr_number}"
        )

        try:
            # Step 1: Fetch the diff
            diff_text = await self._github.get_pr_diff(
                pr_info.owner, pr_info.repo, pr_info.pr_number
            )

            # Step 2: Parse diff into files
            diff_files = parse_diff(diff_text)

            # Step 3: Filter ignored files
            diff_files = [
                f for f in diff_files
                if not should_ignore_file(f.path, self._config.ignore_patterns)
            ]

            logger.info(f"Reviewing {len(diff_files)} files")

            # Step 4: Analyze each file
            file_analyses: list[FileAnalysis] = []
            total_comments = 0

            for diff_file in diff_files:
                if total_comments >= self._config.max_comments_per_pr:
                    logger.warning("Hit max comments limit, stopping review")
                    break

                analysis = await self._analyze_file(
                    diff_file, mode, analyzer, llm_caller, pr_info
                )
                if analysis.comments:
                    remaining = self._config.max_comments_per_pr - total_comments
                    analysis.comments = analysis.comments[:remaining]
                    total_comments += len(analysis.comments)
                    file_analyses.append(analysis)

            # Step 5: Build result
            result = ReviewResult(
                pr_owner=pr_info.owner,
                pr_repo=pr_info.repo,
                pr_number=pr_info.pr_number,
                head_sha=pr_info.head_sha,
                mode=mode,
                files=file_analyses,
                total_comments=total_comments,
                risk_score=self._calculate_risk(file_analyses),
                overall_summary=self._generate_summary(file_analyses, mode),
            )

            # Step 6: Post comments to GitHub
            if self._config.post_comments and result.all_comments:
                await self._post_comments(result, pr_info)

            self._reviews_completed += 1
            logger.info(
                f"Review complete: {result.total_comments} comments, "
                f"risk score {result.risk_score:.1f}"
            )
            return result

        except Exception:
            self._reviews_failed += 1
            raise

    async def _analyze_file(
        self,
        diff_file: DiffFile,
        mode: ReviewMode,
        analyzer: Optional[object],
        llm_caller: Optional[object],
        pr_info: PullRequestInfo,
    ) -> FileAnalysis:
        """Analyze a single file using static analysis and/or LLM."""
        comments: list[InlineComment] = []

        # Run static analyzer if available
        if analyzer is not None:
            try:
                static_comments = await self._run_static_analysis(
                    analyzer, diff_file, mode
                )
                comments.extend(static_comments)
            except Exception as exc:
                logger.warning(f"Static analysis failed for {diff_file.path}: {exc}")

        # Run LLM analysis if available
        if llm_caller is not None:
            try:
                llm_comments = await self._run_llm_analysis(
                    llm_caller, diff_file, mode, pr_info
                )
                comments.extend(llm_comments)
            except Exception as exc:
                logger.warning(f"LLM analysis failed for {diff_file.path}: {exc}")

        # Deduplicate by file+line
        seen: set[tuple[str, int]] = set()
        unique_comments: list[InlineComment] = []
        for comment in comments:
            key = (comment.path, comment.line)
            if key not in seen:
                seen.add(key)
                unique_comments.append(comment)

        return FileAnalysis(
            path=diff_file.path,
            comments=unique_comments,
            risk_score=max((c.severity.value == "critical" and 10.0 or 0.0) for c in unique_comments) if unique_comments else 0.0,
        )

    async def _run_static_analysis(
        self, analyzer: object, diff_file: DiffFile, mode: ReviewMode
    ) -> list[InlineComment]:
        """Run static analysis on a diff file."""
        # This will be implemented by the analyzer module
        if hasattr(analyzer, "analyze_diff"):
            return await analyzer.analyze_diff(diff_file, mode)  # type: ignore
        return []

    async def _run_llm_analysis(
        self,
        llm_caller: object,
        diff_file: DiffFile,
        mode: ReviewMode,
        pr_info: PullRequestInfo,
    ) -> list[InlineComment]:
        """Run LLM-based analysis on a diff file."""
        if callable(llm_caller):
            return await llm_caller(diff_file, mode, pr_info)  # type: ignore
        return []

    async def _post_comments(
        self, result: ReviewResult, pr_info: PullRequestInfo
    ) -> None:
        """Post all review comments to GitHub."""
        tasks = []
        for comment in result.all_comments:
            tasks.append(
                self._github.post_review_comment(
                    owner=pr_info.owner,
                    repo=pr_info.repo,
                    pr_number=pr_info.pr_number,
                    commit_sha=pr_info.head_sha,
                    path=comment.path,
                    line=comment.line,
                    body=comment.to_github_body(),
                )
            )

        # Post comments concurrently with rate limiting
        semaphore = asyncio.Semaphore(5)

        async def _post_with_limit(coro):
            async with semaphore:
                try:
                    return await coro
                except Exception as exc:
                    logger.warning(f"Failed to post comment: {exc}")
                    return None

        results = await asyncio.gather(
            *[_post_with_limit(t) for t in tasks],
            return_exceptions=True,
        )
        posted = sum(1 for r in results if r is not None and not isinstance(r, Exception))
        logger.info(f"Posted {posted}/{len(tasks)} comments")

        # Post summary comment
        if result.overall_summary:
            try:
                await self._github.post_pr_comment(
                    owner=pr_info.owner,
                    repo=pr_info.repo,
                    pr_number=pr_info.pr_number,
                    body=self._format_summary_comment(result),
                )
            except Exception as exc:
                logger.warning(f"Failed to post summary comment: {exc}")

    def _calculate_risk(self, analyses: list[FileAnalysis]) -> float:
        """Calculate overall risk score from file analyses."""
        if not analyses:
            return 0.0
        scores = [a.risk_score for a in analyses]
        return sum(scores) / len(scores)

    def _generate_summary(
        self, analyses: list[FileAnalysis], mode: ReviewMode
    ) -> str:
        """Generate a human-readable review summary."""
        if not analyses:
            return "No issues found. Clean PR! ✨"

        total = sum(len(a.comments) for a in analyses)
        parts = [f"Reviewed {len(analyses)} file(s) in `{mode.value}` mode."]
        parts.append(f"Found **{total}** issue(s):")

        severity_counts: dict[str, int] = {}
        for analysis in analyses:
            for comment in analysis.comments:
                sev = comment.severity.value
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for sev in ["critical", "error", "warning", "info"]:
            count = severity_counts.get(sev, 0)
            if count:
                parts.append(f"- {sev.title()}: {count}")

        return "\n".join(parts)

    def _format_summary_comment(self, result: ReviewResult) -> str:
        """Format the summary comment posted on the PR."""
        lines = [
            "## 🔍 Prism Code Review",
            "",
            result.overall_summary,
            "",
            f"**Risk Score:** {result.risk_score:.1f}/10",
            f"**Mode:** {result.mode.value}",
            "",
            "---",
            "*Powered by [Prism](https://github.com/Kynareth01/prism)*",
        ]
        return "\n".join(lines)

    @property
    def uptime(self) -> float:
        return time.monotonic() - self._start_time

    @property
    def stats(self) -> dict:
        return {
            "uptime_seconds": self.uptime,
            "reviews_completed": self._reviews_completed,
            "reviews_failed": self._reviews_failed,
        }

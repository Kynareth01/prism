"""
Code review agent - LLM-powered code analysis.

Uses MiMo V2.5 Pro to perform deep code review with full context.
Handles prompt construction, LLM interaction, and response parsing.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

import httpx

from prism.config import get_config
from prism.models import (
    InlineComment,
    ReviewCategory,
    ReviewMode,
    Severity,
)
from prism.prompts import build_messages, get_prompt
from prism.reviewer import DiffFile

from .base import BaseAgent

logger = logging.getLogger(__name__)

# Map string severity to enum
_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "info": Severity.INFO,
}

_CATEGORY_MAP = {
    "bug": ReviewCategory.BUG,
    "security": ReviewCategory.SECURITY,
    "performance": ReviewCategory.PERFORMANCE,
    "style": ReviewCategory.STYLE,
    "maintainability": ReviewCategory.MAINTAINABILITY,
    "testing": ReviewCategory.TESTING,
    "documentation": ReviewCategory.DOCUMENTATION,
    "architecture": ReviewCategory.ARCHITECTURE,
}


def _parse_llm_response(raw: str, file_path: str) -> list[InlineComment]:
    """Parse LLM JSON response into InlineComment objects."""
    # Try to extract JSON from the response (handle markdown code blocks)
    text = raw.strip()
    if text.startswith("```"):
        # Remove code block markers
        lines = text.split("\n")
        json_lines = []
        in_block = False
        for line in lines:
            if line.startswith("```") and not in_block:
                in_block = True
                continue
            elif line.startswith("```") and in_block:
                break
            elif in_block:
                json_lines.append(line)
        text = "\n".join(json_lines)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        logger.warning(f"Failed to parse LLM response as JSON: {text[:200]}")
        return []

    comments_data = data.get("comments", [])
    comments: list[InlineComment] = []

    for item in comments_data:
        try:
            severity = _SEVERITY_MAP.get(item.get("severity", "info"), Severity.INFO)
            category = _CATEGORY_MAP.get(item.get("category", "bug"), ReviewCategory.BUG)
            comments.append(
                InlineComment(
                    path=file_path,
                    line=int(item["line"]),
                    body=item["body"],
                    severity=severity,
                    category=category,
                    suggestion=item.get("suggestion"),
                )
            )
        except (KeyError, ValueError) as exc:
            logger.warning(f"Skipping malformed comment: {exc}")
            continue

    return comments


class CodeReviewAgent(BaseAgent):
    """LLM-powered code review agent.

    Sends diffs to MiMo V2.5 Pro with full file context and parses
    structured review comments from the response.
    """

    def __init__(self) -> None:
        super().__init__(name="code-reviewer", version="1.0.0")
        self._config = get_config()

    async def analyze(
        self,
        diff_file: DiffFile,
        mode: ReviewMode,
        context: Optional[dict[str, Any]] = None,
    ) -> list[InlineComment]:
        """Analyze a diff file using LLM."""
        if not self.supports_mode(mode):
            return []

        ctx = context or {}
        file_content = ctx.get("file_content")
        pr_title = ctx.get("pr_title", "")
        pr_body = ctx.get("pr_body", "")

        # Detect language from file extension
        language = _detect_language(diff_file.path)

        # Build LLM messages
        messages = build_messages(
            mode,
            file_path=diff_file.path,
            diff=diff_file.patch_text,
            file_content=file_content,
            pr_title=pr_title,
            pr_body=pr_body,
            language=language,
        )

        try:
            response_text = await self._call_llm(messages)
            return _parse_llm_response(response_text, diff_file.path)
        except Exception as exc:
            logger.error(f"LLM analysis failed for {diff_file.path}: {exc}")
            return []

    async def _call_llm(self, messages: list[dict[str, str]]) -> str:
        """Call the LLM API with retry logic."""
        llm_config = self._config.llm

        async with httpx.AsyncClient(timeout=120.0) as client:
            for attempt in range(3):
                try:
                    response = await client.post(
                        f"{llm_config.api_base}/chat/completions",
                        headers={
                            "Authorization": f"Bearer {llm_config.api_key}",
                            "Content-Type": "application/json",
                        },
                        json={
                            "model": llm_config.model,
                            "messages": messages,
                            "max_tokens": llm_config.max_tokens,
                            "temperature": llm_config.temperature,
                        },
                    )
                    response.raise_for_status()
                    data = response.json()
                    return data["choices"][0]["message"]["content"]
                except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                    if attempt < 2:
                        wait = 2 ** (attempt + 1)
                        logger.warning(f"LLM call failed (attempt {attempt + 1}): {exc}. Retrying in {wait}s...")
                        import asyncio
                        await asyncio.sleep(wait)
                    else:
                        raise

    def supports_mode(self, mode: ReviewMode) -> bool:
        return True  # LLM agent supports all modes


def _detect_language(path: str) -> str:
    """Detect programming language from file extension."""
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".jsx": "jsx",
        ".tsx": "tsx",
        ".rs": "rust",
        ".go": "go",
        ".java": "java",
        ".rb": "ruby",
        ".c": "c",
        ".cpp": "cpp",
        ".h": "c-header",
        ".hpp": "cpp-header",
        ".cs": "csharp",
        ".swift": "swift",
        ".kt": "kotlin",
        ".scala": "scala",
        ".sh": "bash",
        ".sql": "sql",
        ".html": "html",
        ".css": "css",
        ".scss": "scss",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".json": "json",
        ".toml": "toml",
        ".xml": "xml",
        ".md": "markdown",
        ".dockerfile": "dockerfile",
    }
    for ext, lang in ext_map.items():
        if path.endswith(ext) or path.endswith(ext.upper()):
            return lang
    if path.endswith("Dockerfile"):
        return "dockerfile"
    return "unknown"

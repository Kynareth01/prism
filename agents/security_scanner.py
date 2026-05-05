"""
Security scanner agent - focused security analysis.

Combines rule-based pattern matching with LLM-powered deep analysis
for comprehensive security review of code changes.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from prism.analyzer import StaticAnalyzer, ALL_RULES, SECRET_RULES, INJECTION_RULES
from prism.models import (
    InlineComment,
    ReviewCategory,
    ReviewMode,
    Severity,
)
from prism.reviewer import DiffFile

from .base import BaseAgent

logger = logging.getLogger(__name__)


class SecurityScannerAgent(BaseAgent):
    """Security-focused review agent.

    Combines fast rule-based scanning with optional LLM deep analysis
    for comprehensive security coverage.
    """

    def __init__(self, use_llm: bool = False) -> None:
        super().__init__(name="security-scanner", version="1.0.0")
        self._analyzer = StaticAnalyzer(rules=SECRET_RULES + INJECTION_RULES)
        self._use_llm = use_llm

    async def analyze(
        self,
        diff_file: DiffFile,
        mode: ReviewMode,
        context: Optional[dict[str, Any]] = None,
    ) -> list[InlineComment]:
        """Run security analysis on a diff file.

        Uses rule-based patterns first, then optionally enhances
        with LLM analysis for complex vulnerabilities.
        """
        comments: list[InlineComment] = []

        # Phase 1: Fast rule-based scanning
        rule_comments = await self._analyzer.analyze_diff(diff_file, mode)
        comments.extend(rule_comments)

        # Phase 2: LLM-enhanced analysis (if enabled and in security mode)
        if self._use_llm and mode in (ReviewMode.FULL, ReviewMode.SECURITY):
            try:
                llm_comments = await self._llm_security_analysis(diff_file, context)
                comments.extend(llm_comments)
            except Exception as exc:
                logger.warning(f"LLM security analysis failed: {exc}")

        # Deduplicate by line number
        seen_lines: set[int] = set()
        unique: list[InlineComment] = []
        for comment in comments:
            if comment.line not in seen_lines:
                seen_lines.add(comment.line)
                unique.append(comment)

        return unique

    async def _llm_security_analysis(
        self,
        diff_file: DiffFile,
        context: Optional[dict[str, Any]] = None,
    ) -> list[InlineComment]:
        """Run LLM-based security analysis for deeper vulnerability detection.

        This method is used for complex patterns that rule-based scanning
        might miss, like business logic vulnerabilities.
        """
        # Import here to avoid circular imports
        from .code_reviewer import CodeReviewAgent

        agent = CodeReviewAgent()
        return await agent.analyze(
            diff_file,
            ReviewMode.SECURITY,
            context,
        )

    def supports_mode(self, mode: ReviewMode) -> bool:
        return mode in (ReviewMode.FULL, ReviewMode.SECURITY)

    def add_custom_rule(self, rule: Any) -> None:
        """Add a custom security rule to the scanner."""
        self._analyzer.add_rule(rule)
        logger.info(f"Added custom security rule: {rule.id}")

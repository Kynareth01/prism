"""
Base agent class for Prism review agents.

Provides the common interface and lifecycle management for all agents.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

from prism.models import InlineComment, ReviewMode
from prism.reviewer import DiffFile

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Abstract base class for review agents.

    Each agent receives a diff file and returns inline comments.
    Agents can be stateless (simple analysis) or stateful (learning
    from past reviews).
    """

    def __init__(self, name: str, version: str = "1.0.0") -> None:
        self.name = name
        self.version = version
        self._enabled = True

    @abstractmethod
    async def analyze(
        self,
        diff_file: DiffFile,
        mode: ReviewMode,
        context: Optional[dict[str, Any]] = None,
    ) -> list[InlineComment]:
        """Analyze a diff file and return review comments.

        Args:
            diff_file: Parsed diff with hunks.
            mode: Current review mode.
            context: Optional context (PR info, file content, etc.)

        Returns:
            List of inline comments.
        """
        ...

    @abstractmethod
    def supports_mode(self, mode: ReviewMode) -> bool:
        """Check if this agent supports the given review mode."""
        ...

    def enable(self) -> None:
        """Enable this agent."""
        self._enabled = True
        logger.info(f"Agent '{self.name}' enabled")

    def disable(self) -> None:
        """Disable this agent."""
        self._enabled = False
        logger.info(f"Agent '{self.name}' disabled")

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def __repr__(self) -> str:
        status = "enabled" if self._enabled else "disabled"
        return f"<{self.__class__.__name__} '{self.name}' v{self.version} ({status})>"

"""
Prism agents - autonomous review agents for different analysis strategies.

Each agent implements a specific review strategy and can be composed
to create multi-agent review pipelines.
"""

from .base import BaseAgent
from .code_reviewer import CodeReviewAgent
from .security_scanner import SecurityScannerAgent

__all__ = ["BaseAgent", "CodeReviewAgent", "SecurityScannerAgent"]

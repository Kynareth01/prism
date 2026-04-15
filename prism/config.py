"""
Prism configuration management.

Loads settings from environment variables with sensible defaults.
Supports .env files via python-dotenv.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


def _load_dotenv() -> None:
    """Load .env file if it exists."""
    try:
        from dotenv import load_dotenv

        env_path = Path(__file__).parent.parent / ".env"
        if env_path.exists():
            load_dotenv(env_path)
    except ImportError:
        pass


_load_dotenv()


@dataclass(frozen=True)
class GitHubConfig:
    """GitHub API configuration."""

    token: str = ""
    webhook_secret: str = ""
    api_base: str = "https://api.github.com"

    @classmethod
    def from_env(cls) -> GitHubConfig:
        return cls(
            token=os.getenv("GITHUB_TOKEN", ""),
            webhook_secret=os.getenv("GITHUB_WEBHOOK_SECRET", ""),
            api_base=os.getenv("GITHUB_API_BASE", "https://api.github.com"),
        )


@dataclass(frozen=True)
class LLMConfig:
    """LLM provider configuration for MiMo V2.5 Pro."""

    api_key: str = ""
    api_base: str = "https://api.openai.com/v1"
    model: str = "mimo-v2.5-pro"
    max_tokens: int = 4096
    temperature: float = 0.2

    @classmethod
    def from_env(cls) -> LLMConfig:
        return cls(
            api_key=os.getenv("LLM_API_KEY", ""),
            api_base=os.getenv("LLM_API_BASE", "https://api.openai.com/v1"),
            model=os.getenv("LLM_MODEL", "mimo-v2.5-pro"),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS", "4096")),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.2")),
        )


@dataclass(frozen=True)
class ReviewConfig:
    """Review behavior configuration."""

    max_diff_lines: int = 5000
    ignore_patterns: tuple[str, ...] = (
        "*.lock",
        "package-lock.json",
        "*.min.js",
        "*.min.css",
    )
    review_modes: tuple[str, ...] = ("full", "security", "style", "quick")
    default_mode: str = "full"
    post_comments: bool = True
    max_comments_per_pr: int = 50

    @classmethod
    def from_env(cls) -> ReviewConfig:
        ignore = os.getenv("PRISM_IGNORE_PATTERNS", "")
        patterns = tuple(p.strip() for p in ignore.split(",") if p.strip()) or (
            "*.lock",
            "package-lock.json",
            "*.min.js",
            "*.min.css",
        )
        return cls(
            max_diff_lines=int(os.getenv("PRISM_MAX_DIFF_LINES", "5000")),
            ignore_patterns=patterns,
            default_mode=os.getenv("PRISM_DEFAULT_MODE", "full"),
            post_comments=os.getenv("PRISM_POST_COMMENTS", "true").lower() == "true",
            max_comments_per_pr=int(os.getenv("PRISM_MAX_COMMENTS", "50")),
        )


@dataclass
class AppConfig:
    """Top-level application configuration."""

    github: GitHubConfig = field(default_factory=GitHubConfig.from_env)
    llm: LLMConfig = field(default_factory=LLMConfig.from_env)
    review: ReviewConfig = field(default_factory=ReviewConfig.from_env)
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> AppConfig:
        return cls(
            host=os.getenv("PRISM_HOST", "0.0.0.0"),
            port=int(os.getenv("PRISM_PORT", "8080")),
            log_level=os.getenv("PRISM_LOG_LEVEL", "INFO"),
        )


# Singleton config instance
_config: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """Get or create the global configuration singleton."""
    global _config
    if _config is None:
        _config = AppConfig.from_env()
    return _config


def reset_config() -> None:
    """Reset the global configuration (useful for testing)."""
    global _config
    _config = None

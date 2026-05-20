"""Tests for Prism configuration module."""

import os
from unittest.mock import patch

from prism.config import (
    AppConfig,
    GitHubConfig,
    LLMConfig,
    ReviewConfig,
    get_config,
    reset_config,
)


class TestGitHubConfig:
    def test_from_env_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            config = GitHubConfig.from_env()
            assert config.token == ""
            assert config.webhook_secret == ""
            assert config.api_base == "https://api.github.com"

    def test_from_env_custom(self):
        env = {
            "GITHUB_TOKEN": "ghp_test123",
            "GITHUB_WEBHOOK_SECRET": "supersecret",
            "GITHUB_API_BASE": "https://github.example.com/api",
        }
        with patch.dict(os.environ, env, clear=True):
            config = GitHubConfig.from_env()
            assert config.token == "ghp_test123"
            assert config.webhook_secret == "supersecret"
            assert config.api_base == "https://github.example.com/api"


class TestLLMConfig:
    def test_from_env_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            config = LLMConfig.from_env()
            assert config.model == "mimo-v2.5-pro"
            assert config.max_tokens == 4096
            assert config.temperature == 0.2

    def test_from_env_custom(self):
        env = {
            "LLM_API_KEY": "sk-test",
            "LLM_MODEL": "custom-model",
            "LLM_MAX_TOKENS": "8192",
            "LLM_TEMPERATURE": "0.5",
        }
        with patch.dict(os.environ, env, clear=True):
            config = LLMConfig.from_env()
            assert config.api_key == "sk-test"
            assert config.model == "custom-model"
            assert config.max_tokens == 8192
            assert config.temperature == 0.5


class TestReviewConfig:
    def test_from_env_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            config = ReviewConfig.from_env()
            assert config.max_diff_lines == 5000
            assert "*.lock" in config.ignore_patterns
            assert config.default_mode == "full"
            assert config.post_comments is True

    def test_from_env_custom(self):
        env = {
            "PRISM_MAX_DIFF_LINES": "10000",
            "PRISM_DEFAULT_MODE": "security",
            "PRISM_POST_COMMENTS": "false",
            "PRISM_MAX_COMMENTS": "25",
        }
        with patch.dict(os.environ, env, clear=True):
            config = ReviewConfig.from_env()
            assert config.max_diff_lines == 10000
            assert config.default_mode == "security"
            assert config.post_comments is False
            assert config.max_comments_per_pr == 25


class TestAppConfig:
    def test_singleton(self):
        reset_config()
        config1 = get_config()
        config2 = get_config()
        assert config1 is config2

    def test_reset(self):
        reset_config()
        config1 = get_config()
        reset_config()
        config2 = get_config()
        assert config1 is not config2

"""Tests for the GitHub client module."""

import hashlib
import hmac
from unittest.mock import AsyncMock, patch

import pytest
import httpx

from prism.github_client import GitHubClient, PullRequestInfo


class TestWebhookSignatureVerification:
    """Test HMAC-SHA256 webhook signature verification."""

    def test_valid_signature(self):
        secret = "test-webhook-secret"
        payload = b'{"action": "opened"}'
        expected_sig = hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        signature = f"sha256={expected_sig}"

        assert GitHubClient.verify_webhook_signature(payload, signature, secret) is True

    def test_invalid_signature(self):
        payload = b'{"action": "opened"}'
        assert GitHubClient.verify_webhook_signature(
            payload, "sha256=wrong", "secret"
        ) is False

    def test_missing_sha256_prefix(self):
        payload = b'{"action": "opened"}'
        assert GitHubClient.verify_webhook_signature(
            payload, "abc123", "secret"
        ) is False

    def test_empty_signature(self):
        payload = b'{"action": "opened"}'
        assert GitHubClient.verify_webhook_signature(
            payload, "", "secret"
        ) is False


class TestPullRequestInfo:
    """Test PR info parsing from webhook payload."""

    def test_from_webhook(self):
        payload = {
            "action": "opened",
            "pull_request": {
                "number": 42,
                "title": "Add feature",
                "body": "This adds a feature",
                "user": {"login": "testuser"},
                "head": {"sha": "abc123"},
                "base": {"sha": "def456"},
                "changed_files": 5,
                "diff_url": "https://github.com/test/repo/pull/42.diff",
            },
            "repository": {
                "name": "repo",
                "owner": {"login": "testowner"},
            },
        }

        info = PullRequestInfo.from_webhook(payload)
        assert info.owner == "testowner"
        assert info.repo == "repo"
        assert info.pr_number == 42
        assert info.head_sha == "abc123"
        assert info.base_sha == "def456"
        assert info.title == "Add feature"
        assert info.author == "testuser"
        assert info.changed_files == 5

    def test_from_webhook_empty_body(self):
        payload = {
            "action": "opened",
            "pull_request": {
                "number": 1,
                "title": "PR",
                "body": None,
                "user": {"login": "user"},
                "head": {"sha": "a"},
                "base": {"sha": "b"},
                "changed_files": 1,
                "diff_url": "https://example.com",
            },
            "repository": {
                "name": "repo",
                "owner": {"login": "owner"},
            },
        }

        info = PullRequestInfo.from_webhook(payload)
        assert info.body == ""

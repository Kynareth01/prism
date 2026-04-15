"""
Async GitHub API client with retry logic.

Handles PR webhook payloads, fetches diffs, and posts inline review comments.
Uses httpx for async HTTP with exponential backoff.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from .config import GitHubConfig, get_config

logger = logging.getLogger(__name__)

# Type alias for JSON responses
JSON = dict[str, Any]


@dataclass
class PullRequestInfo:
    """Parsed pull request information from webhook payload."""

    owner: str
    repo: str
    pr_number: int
    head_sha: str
    base_sha: str
    title: str
    body: str
    author: str
    changed_files: int
    diff_url: str

    @classmethod
    def from_webhook(cls, payload: JSON) -> PullRequestInfo:
        """Parse a PR webhook payload into structured data."""
        pr = payload["pull_request"]
        repo = payload["repository"]
        return cls(
            owner=repo["owner"]["login"],
            repo=repo["name"],
            pr_number=pr["number"],
            head_sha=pr["head"]["sha"],
            base_sha=pr["base"]["sha"],
            title=pr["title"],
            body=pr.get("body", "") or "",
            author=pr["user"]["login"],
            changed_files=pr.get("changed_files", 0),
            diff_url=pr["diff_url"],
        )


class GitHubClient:
    """Async GitHub API client with automatic retries."""

    def __init__(self, config: Optional[GitHubConfig] = None) -> None:
        self._config = config or get_config().github
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> GitHubClient:
        self._client = httpx.AsyncClient(
            base_url=self._config.api_base,
            headers={
                "Authorization": f"Bearer {self._config.token}",
                "Accept": "application/vnd.github.v3+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30.0,
        )
        return self

    async def __aexit__(self, *exc: Any) -> None:
        if self._client:
            await self._client.aclose()

    @staticmethod
    def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
        """Verify GitHub webhook HMAC-SHA256 signature.

        Args:
            payload: Raw request body bytes.
            signature: X-Hub-Signature-256 header value.
            secret: Webhook secret configured in GitHub.

        Returns:
            True if signature is valid.
        """
        if not signature.startswith("sha256="):
            return False
        expected = hmac.new(
            secret.encode("utf-8"), payload, hashlib.sha256
        ).hexdigest()
        received = signature[7:]  # Strip "sha256=" prefix
        return hmac.compare_digest(expected, received)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_data: Optional[JSON] = None,
        headers: Optional[dict[str, str]] = None,
        retries: int = 3,
    ) -> JSON | str | None:
        """Make an API request with exponential backoff retry."""
        assert self._client is not None, "Client not initialized. Use 'async with'."

        last_error: Optional[Exception] = None
        for attempt in range(retries):
            try:
                response = await self._client.request(
                    method, path, json=json_data, headers=headers
                )

                if response.status_code == 403 and "rate limit" in response.text.lower():
                    reset_time = int(response.headers.get("X-RateLimit-Reset", 0))
                    wait = max(reset_time - int(asyncio.get_event_loop().time()), 60)
                    logger.warning(f"Rate limited. Waiting {wait}s...")
                    await asyncio.sleep(wait)
                    continue

                if response.status_code >= 500:
                    raise httpx.HTTPStatusError(
                        f"Server error: {response.status_code}",
                        request=response.request,
                        response=response,
                    )

                response.raise_for_status()

                if response.status_code == 204:
                    return None
                content_type = response.headers.get("content-type", "")
                if "json" in content_type:
                    return response.json()
                return response.text

            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                last_error = exc
                wait = 2 ** attempt
                logger.warning(
                    f"Request failed (attempt {attempt + 1}/{retries}): {exc}. "
                    f"Retrying in {wait}s..."
                )
                await asyncio.sleep(wait)

        raise RuntimeError(
            f"Request failed after {retries} attempts: {last_error}"
        )

    async def get_pull_request(self, owner: str, repo: str, pr_number: int) -> JSON:
        """Fetch pull request details."""
        return await self._request("GET", f"/repos/{owner}/{repo}/pulls/{pr_number}")  # type: ignore

    async def get_pr_diff(self, owner: str, repo: str, pr_number: int) -> str:
        """Fetch the unified diff for a pull request."""
        assert self._client is not None
        response = await self._client.get(
            f"/repos/{owner}/{repo}/pulls/{pr_number}",
            headers={"Accept": "application/vnd.github.v3.diff"},
        )
        response.raise_for_status()
        return response.text

    async def get_pr_files(self, owner: str, repo: str, pr_number: int) -> list[JSON]:
        """Fetch the list of changed files in a PR."""
        files: list[JSON] = []
        page = 1
        while True:
            batch = await self._request(
                "GET",
                f"/repos/{owner}/{repo}/pulls/{pr_number}/files",
                json_data=None,
                headers={"Accept": "application/vnd.github.v3+json"},
            )
            if not batch or not isinstance(batch, list):
                break
            files.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        return files

    async def post_review_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        path: str,
        line: int,
        body: str,
    ) -> JSON:
        """Post an inline review comment on a PR.

        Args:
            owner: Repository owner.
            repo: Repository name.
            pr_number: Pull request number.
            commit_sha: The HEAD commit SHA to anchor the comment.
            path: File path relative to repo root.
            line: Line number to comment on.
            body: Comment body (Markdown).

        Returns:
            API response JSON.
        """
        return await self._request(  # type: ignore
            "POST",
            f"/repos/{owner}/{repo}/pulls/{pr_number}/comments",
            json_data={
                "body": body,
                "commit_id": commit_sha,
                "path": path,
                "line": line,
                "side": "RIGHT",
            },
        )

    async def post_pr_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
    ) -> JSON:
        """Post a general comment on a PR (not inline)."""
        return await self._request(  # type: ignore
            "POST",
            f"/repos/{owner}/{repo}/issues/{pr_number}/comments",
            json_data={"body": body},
        )

    async def get_file_content(
        self, owner: str, repo: str, path: str, ref: str
    ) -> str:
        """Fetch the content of a file at a specific ref."""
        assert self._client is not None
        response = await self._client.get(
            f"/repos/{owner}/{repo}/contents/{path}",
            params={"ref": ref},
            headers={"Accept": "application/vnd.github.v3.raw"},
        )
        response.raise_for_status()
        return response.text

    async def create_check_run(
        self,
        owner: str,
        repo: str,
        name: str,
        head_sha: str,
        conclusion: str,
        output: JSON,
    ) -> JSON:
        """Create a GitHub Check Run with review results."""
        return await self._request(  # type: ignore
            "POST",
            f"/repos/{owner}/{repo}/check-runs",
            json_data={
                "name": name,
                "head_sha": head_sha,
                "status": "completed",
                "conclusion": conclusion,
                "output": output,
            },
        )

"""
Prism FastAPI application.

Provides the webhook endpoint for GitHub PR events,
health check, and review trigger API.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse

from .analyzer import StaticAnalyzer
from .config import get_config, AppConfig
from .github_client import GitHubClient, PullRequestInfo
from .models import ReviewMode, HealthCheck
from .reviewer import ReviewEngine

logger = logging.getLogger(__name__)

# Global state
_engine: Optional[ReviewEngine] = None
_github_client: Optional[GitHubClient] = None
_analyzer: Optional[StaticAnalyzer] = None
_start_time: float = 0.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    global _engine, _github_client, _analyzer, _start_time

    config = get_config()
    _start_time = time.monotonic()

    logging.basicConfig(
        level=getattr(logging, config.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    logger.info("Starting Prism v0.1.0")
    logger.info(f"Listening on {config.host}:{config.port}")

    _github_client = GitHubClient(config.github)
    await _github_client.__aenter__()
    _analyzer = StaticAnalyzer()
    _engine = ReviewEngine(_github_client, config.review)

    yield

    # Shutdown
    logger.info("Shutting down Prism...")
    if _github_client:
        await _github_client.__aexit__(None, None, None)


app = FastAPI(
    title="Prism",
    description="AI-powered code review bot for GitHub PRs",
    version="0.1.0",
    lifespan=lifespan,
)


def _verify_signature(payload: bytes, signature: Optional[str]) -> bool:
    """Verify GitHub webhook signature.

    This is the fixed version that properly handles:
    - Missing signatures
    - Wrong signature format
    - Timing-safe comparison
    """
    config = get_config()

    if not config.github.webhook_secret:
        logger.warning("No webhook secret configured - skipping verification")
        return True

    if not signature:
        logger.warning("No signature header in webhook request")
        return False

    if not signature.startswith("sha256="):
        logger.warning(f"Invalid signature format: {signature[:20]}...")
        return False

    expected = hmac.new(
        config.github.webhook_secret.encode("utf-8"),
        payload,
        hashlib.sha256,
    ).hexdigest()

    received = signature[7:]  # Strip "sha256=" prefix

    # Timing-safe comparison to prevent timing attacks
    return hmac.compare_digest(expected, received)


@app.post("/webhook")
async def handle_webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(None),
    x_github_event: Optional[str] = Header(None),
):
    """Handle GitHub webhook events.

    Processes pull_request events and triggers code review.
    """
    # Read raw body for signature verification
    body = await request.body()

    # Verify webhook signature
    if not _verify_signature(body, x_hub_signature_256):
        logger.warning("Webhook signature verification failed")
        raise HTTPException(status_code=401, detail="Invalid signature")

    # Parse JSON payload
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    event_type = x_github_event or payload.get("event", "unknown")
    logger.info(f"Received webhook event: {event_type}")

    # Only process pull request events
    if event_type != "pull_request":
        return JSONResponse(
            status_code=200,
            content={"message": f"Ignoring event: {event_type}"},
        )

    action = payload.get("action", "")
    if action not in ("opened", "synchronize", "reopened"):
        return JSONResponse(
            status_code=200,
            content={"message": f"Ignoring PR action: {action}"},
        )

    # Parse PR info
    try:
        pr_info = PullRequestInfo.from_webhook(payload)
    except (KeyError, TypeError) as exc:
        logger.error(f"Failed to parse PR payload: {exc}")
        raise HTTPException(status_code=400, detail=f"Invalid PR payload: {exc}")

    logger.info(
        f"Reviewing PR {pr_info.owner}/{pr_info.repo}#{pr_info.pr_number} "
        f"by @{pr_info.author} ({pr_info.changed_files} files changed)"
    )

    # Determine review mode from PR labels or body
    mode = _extract_review_mode(payload)

    # Trigger async review
    assert _engine is not None
    try:
        result = await _engine.review_pr(pr_info, mode=mode, analyzer=_analyzer)
        return JSONResponse(
            status_code=200,
            content={
                "message": "Review completed",
                "comments": result.total_comments,
                "risk_score": result.risk_score,
            },
        )
    except Exception as exc:
        logger.error(f"Review failed: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"message": f"Review failed: {str(exc)}"},
        )


def _extract_review_mode(payload: dict) -> ReviewMode:
    """Extract review mode from PR labels or description."""
    # Check labels
    labels = [
        label.get("name", "").lower()
        for label in payload.get("pull_request", {}).get("labels", [])
    ]

    for label in labels:
        if "security" in label:
            return ReviewMode.SECURITY
        if "style" in label or "lint" in label:
            return ReviewMode.STYLE
        if "quick" in label:
            return ReviewMode.QUICK

    # Check PR body for mode directive
    body = payload.get("pull_request", {}).get("body", "") or ""
    body_lower = body.lower()

    if "/review security" in body_lower:
        return ReviewMode.SECURITY
    if "/review style" in body_lower:
        return ReviewMode.STYLE
    if "/review quick" in body_lower:
        return ReviewMode.QUICK

    return ReviewMode.FULL


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    config = get_config()
    assert _engine is not None

    check = HealthCheck(
        status="ok",
        version="0.1.0",
        uptime_seconds=_engine.uptime,
        reviews_completed=_engine.stats["reviews_completed"],
        reviews_failed=_engine.stats["reviews_failed"],
    )
    return check.model_dump()


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": "Prism",
        "version": "0.1.0",
        "description": "AI-powered code review bot",
        "docs": "/docs",
    }


@app.post("/review/{owner}/{repo}/{pr_number}")
async def trigger_review(
    owner: str,
    repo: str,
    pr_number: int,
    mode: str = "full",
):
    """Manually trigger a review on a PR.

    Useful for re-running reviews or testing.
    """
    try:
        review_mode = ReviewMode(mode)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid mode: {mode}. Choose from: {[m.value for m in ReviewMode]}",
        )

    assert _github_client is not None
    assert _engine is not None

    try:
        pr_data = await _github_client.get_pull_request(owner, repo, pr_number)
        pr_info = PullRequestInfo(
            owner=owner,
            repo=repo,
            pr_number=pr_number,
            head_sha=pr_data["head"]["sha"],
            base_sha=pr_data["base"]["sha"],
            title=pr_data["title"],
            body=pr_data.get("body", "") or "",
            author=pr_data["user"]["login"],
            changed_files=pr_data.get("changed_files", 0),
            diff_url=pr_data["diff_url"],
        )

        result = await _engine.review_pr(pr_info, mode=review_mode, analyzer=_analyzer)
        return JSONResponse(
            status_code=200,
            content={
                "message": "Review completed",
                "comments": result.total_comments,
                "risk_score": result.risk_score,
                "summary": result.overall_summary,
            },
        )
    except Exception as exc:
        logger.error(f"Manual review failed: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


def run_server():
    """Entry point for running the server."""
    import uvicorn

    config = get_config()
    uvicorn.run(
        "prism.app:app",
        host=config.host,
        port=config.port,
        log_level=config.log_level.lower(),
        reload=False,
    )


if __name__ == "__main__":
    run_server()

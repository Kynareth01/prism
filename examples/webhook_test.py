"""Example: Testing webhook signature generation.

Useful for testing your webhook endpoint locally.
"""

import hashlib
import hmac
import json


def generate_webhook_signature(payload: dict, secret: str) -> str:
    """Generate a GitHub-compatible webhook signature.

    Args:
        payload: The webhook JSON payload.
        secret: The webhook secret.

    Returns:
        The X-Hub-Signature-256 header value.
    """
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={signature}"


def main():
    """Generate a test webhook payload with valid signature."""
    secret = "test-webhook-secret"

    payload = {
        "action": "opened",
        "pull_request": {
            "number": 42,
            "title": "Add user authentication",
            "body": "This PR adds login/logout endpoints.\n\n/review security",
            "user": {"login": "testuser"},
            "head": {
                "sha": "abc123def456",
                "ref": "feature/auth",
            },
            "base": {
                "sha": "main000",
                "ref": "main",
            },
            "changed_files": 3,
            "diff_url": "https://github.com/test/repo/pull/42.diff",
            "labels": [{"name": "prism:security"}],
        },
        "repository": {
            "name": "test-repo",
            "owner": {"login": "testowner"},
        },
        "sender": {"login": "testuser"},
    }

    signature = generate_webhook_signature(payload, secret)

    print("Test Webhook Payload")
    print("=" * 50)
    print()
    print("Headers:")
    print(f"  X-GitHub-Event: pull_request")
    print(f"  X-Hub-Signature-256: {signature}")
    print()
    print("Payload:")
    print(json.dumps(payload, indent=2))
    print()
    print("curl command:")
    print()
    body = json.dumps(payload, separators=(",", ":"))
    print(f'curl -X POST http://localhost:8080/webhook \\')
    print(f'  -H "Content-Type: application/json" \\')
    print(f'  -H "X-GitHub-Event: pull_request" \\')
    print(f'  -H "X-Hub-Signature-256: {signature}" \\')
    print(f"  -d '{body}'")
    print()


if __name__ == "__main__":
    main()

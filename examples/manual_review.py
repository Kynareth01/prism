"""Example: Running a manual review against a real PR."""

import asyncio
import os

from prism.config import get_config
from prism.github_client import GitHubClient, PullRequestInfo
from prism.analyzer import StaticAnalyzer
from prism.models import ReviewMode
from prism.reviewer import ReviewEngine


async def main():
    """Run a static analysis review on a PR."""
    config = get_config()

    # Check for required config
    if not config.github.token:
        print("ERROR: Set GITHUB_TOKEN in .env or environment")
        return

    # Replace with your repo/PR
    owner = "Kynareth01"
    repo = "prism"
    pr_number = 1

    print(f"Reviewing {owner}/{repo}#{pr_number}...")
    print(f"Mode: full")
    print()

    async with GitHubClient(config.github) as client:
        engine = ReviewEngine(client, config.review)
        analyzer = StaticAnalyzer()

        # Get PR info
        pr_data = await client.get_pull_request(owner, repo, pr_number)
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

        # Run review (static analysis only, no LLM)
        result = await engine.review_pr(
            pr_info,
            mode=ReviewMode.FULL,
            analyzer=analyzer,
        )

        # Print results
        print(f"Review complete!")
        print(f"  Files reviewed: {len(result.files)}")
        print(f"  Comments: {result.total_comments}")
        print(f"  Risk score: {result.risk_score:.1f}/10")
        print()
        print(result.overall_summary)

        if result.all_comments:
            print("\nDetailed findings:")
            for comment in result.all_comments:
                print(f"  [{comment.severity.value}] {comment.path}:{comment.line}")
                print(f"    {comment.body}")
                if comment.suggestion:
                    print(f"    Fix: {comment.suggestion}")
                print()


if __name__ == "__main__":
    asyncio.run(main())

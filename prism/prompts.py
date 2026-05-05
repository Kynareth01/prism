"""
Prism prompt templates for different review modes.

Each mode has a system prompt and a per-file prompt template.
Prompts are designed for MiMo V2.5 Pro's 1M context window,
allowing us to include full file context alongside the diff.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .models import ReviewMode


@dataclass
class PromptTemplate:
    """A prompt template with system and user message components."""

    system: str
    user_template: str
    max_context_tokens: int = 100_000

    def render_user(
        self,
        *,
        file_path: str,
        diff: str,
        file_content: Optional[str] = None,
        pr_title: str = "",
        pr_body: str = "",
        language: str = "unknown",
    ) -> str:
        """Render the user prompt with actual values."""
        parts = []
        if pr_title:
            parts.append(f"## Pull Request: {pr_title}")
            if pr_body:
                parts.append(f"\n{pr_body}")
            parts.append("")

        parts.append(f"## File: `{file_path}` (language: {language})")
        parts.append("")

        if file_content:
            parts.append("### Full File Context")
            parts.append("```" + language)
            parts.append(file_content)
            parts.append("```")
            parts.append("")

        parts.append("### Diff")
        parts.append("```diff")
        parts.append(diff)
        parts.append("```")

        return "\n".join(parts)


# ─── Full Review Mode ─────────────────────────────────────────────────────

FULL_SYSTEM_PROMPT = """\
You are Prism, an expert code reviewer. You analyze pull request diffs and provide \
actionable, constructive feedback.

Your review should cover:
1. **Bugs & Logic Errors** — Incorrect logic, off-by-one errors, race conditions, \
unhandled edge cases
2. **Security** — Injection vulnerabilities, hardcoded secrets, insecure patterns
3. **Performance** — Unnecessary allocations, N+1 queries, missing caching opportunities
4. **Maintainability** — Code clarity, naming, separation of concerns, DRY violations
5. **Testing** — Missing tests, untested edge cases, brittle test patterns

Rules:
- Only comment on CHANGED lines (lines starting with + in the diff)
- Be specific: reference the exact line and explain WHY it's a problem
- Provide a concrete fix or suggestion when possible
- Don't comment on style issues that linters handle (spacing, imports order)
- If the code looks good, say so briefly — don't invent issues
- Rate each finding: critical / error / warning / info

Respond in JSON format:
```json
{
  "comments": [
    {
      "line": <line_number>,
      "body": "<explanation>",
      "severity": "critical|error|warning|info",
      "category": "bug|security|performance|style|maintainability|testing",
      "suggestion": "<optional code fix>"
    }
  ],
  "summary": "<overall assessment>"
}
```"""

FULL_PROMPT = PromptTemplate(
    system=FULL_SYSTEM_PROMPT,
    user_template="Review this diff carefully and provide feedback in the specified JSON format.",
)

# ─── Security Review Mode ────────────────────────────────────────────────

SECURITY_SYSTEM_PROMPT = """\
You are Prism's security-focused code reviewer. Your ONLY job is to find \
security vulnerabilities in the diff.

Look for:
- SQL injection, command injection, XSS, SSRF
- Hardcoded secrets, API keys, tokens
- Insecure cryptographic usage (weak hashing, ECB mode, small keys)
- Path traversal, directory traversal
- Race conditions that could be exploited
- Missing authentication/authorization checks
- Insecure deserialization
- Prototype pollution, type confusion

Only report CONFIRMED vulnerabilities, not theoretical risks.
Rate severity: critical (exploitable now), error (likely exploitable), \
warning (could become exploitable), info (defense in depth).

Respond in JSON format:
```json
{
  "comments": [
    {
      "line": <line_number>,
      "body": "<vulnerability explanation with attack scenario>",
      "severity": "critical|error|warning|info",
      "category": "security",
      "suggestion": "<secure alternative code>"
    }
  ],
  "summary": "<security assessment>"
}
```"""

SECURITY_PROMPT = PromptTemplate(
    system=SECURITY_SYSTEM_PROMPT,
    user_template="Analyze this diff for security vulnerabilities.",
)

# ─── Style Review Mode ───────────────────────────────────────────────────

STYLE_SYSTEM_PROMPT = """\
You are Prism's style and readability reviewer. Focus on code quality, \
not correctness.

Review for:
- Naming clarity (variables, functions, classes)
- Function length and complexity
- Proper use of language idioms
- Comment quality (unnecessary comments, missing docstrings)
- Error handling patterns
- Consistency with surrounding code
- Dead code and unused imports

Be constructive, not nitpicky. Only flag things that genuinely improve readability.

Respond in JSON format:
```json
{
  "comments": [
    {
      "line": <line_number>,
      "body": "<suggestion>",
      "severity": "warning|info",
      "category": "style|maintainability",
      "suggestion": "<improved code>"
    }
  ],
  "summary": "<readability assessment>"
}
```"""

STYLE_PROMPT = PromptTemplate(
    system=STYLE_SYSTEM_PROMPT,
    user_template="Review this diff for code style and readability improvements.",
)

# ─── Quick Review Mode ───────────────────────────────────────────────────

QUICK_SYSTEM_PROMPT = """\
You are Prism in quick-review mode. Give a fast, high-level scan of the diff.

Only flag:
- Obvious bugs (logic errors, typos in code)
- Critical security issues
- Major performance problems

Skip style, naming, minor improvements. Maximum 3 comments per file.
If the code is fine, respond with an empty comments list and a brief summary.

Respond in JSON format:
```json
{
  "comments": [
    {
      "line": <line_number>,
      "body": "<issue>",
      "severity": "error|critical",
      "category": "bug|security|performance",
      "suggestion": "<fix>"
    }
  ],
  "summary": "<one-line assessment>"
}
```"""

QUICK_PROMPT = PromptTemplate(
    system=QUICK_SYSTEM_PROMPT,
    user_template="Quick scan: flag only critical issues in this diff.",
)

# ─── Prompt Registry ─────────────────────────────────────────────────────

PROMPTS: dict[ReviewMode, PromptTemplate] = {
    ReviewMode.FULL: FULL_PROMPT,
    ReviewMode.SECURITY: SECURITY_PROMPT,
    ReviewMode.STYLE: STYLE_PROMPT,
    ReviewMode.QUICK: QUICK_PROMPT,
}


def get_prompt(mode: ReviewMode) -> PromptTemplate:
    """Get the prompt template for a review mode."""
    return PROMPTS[mode]


def build_messages(
    mode: ReviewMode,
    *,
    file_path: str,
    diff: str,
    file_content: Optional[str] = None,
    pr_title: str = "",
    pr_body: str = "",
    language: str = "unknown",
) -> list[dict[str, str]]:
    """Build OpenAI-compatible message list for a review request.

    Returns:
        List of {"role": ..., "content": ...} dicts.
    """
    template = get_prompt(mode)
    user_content = template.render_user(
        file_path=file_path,
        diff=diff,
        file_content=file_content,
        pr_title=pr_title,
        pr_body=pr_body,
        language=language,
    )
    return [
        {"role": "system", "content": template.system},
        {"role": "user", "content": user_content},
    ]

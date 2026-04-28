"""
Prism static analyzer.

Performs rule-based code analysis on diffs without LLM calls:
- Secret/credential detection (API keys, tokens, passwords)
- SQL injection and command injection patterns
- Style and formatting issues
- Common bug patterns
- Dependency vulnerability patterns
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

from .models import InlineComment, ReviewCategory, ReviewMode, Severity
from .reviewer import DiffFile, DiffHunk

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """A single analysis rule."""

    id: str
    name: str
    category: ReviewCategory
    severity: Severity
    pattern: re.Pattern[str]
    message: str
    suggestion: Optional[str] = None
    modes: tuple[ReviewMode, ...] = (
        ReviewMode.FULL,
        ReviewMode.SECURITY,
        ReviewMode.STYLE,
        ReviewMode.QUICK,
    )

    def matches(self, line: str) -> Optional[re.Match[str]]:
        return self.pattern.search(line)


# ─── Secret Detection Rules ───────────────────────────────────────────────

SECRET_RULES = [
    Rule(
        id="SEC001",
        name="hardcoded-api-key",
        category=ReviewCategory.SECURITY,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"]([A-Za-z0-9_\-]{20,})['"]""",
            re.IGNORECASE,
        ),
        message="Hardcoded API key detected. Use environment variables or a secrets manager.",
        suggestion="api_key = os.environ['API_KEY']",
        modes=(ReviewMode.FULL, ReviewMode.SECURITY),
    ),
    Rule(
        id="SEC002",
        name="hardcoded-secret",
        category=ReviewCategory.SECURITY,
        severity=Severity.CRITICAL,
        pattern=re.compile(
            r"""(?:secret|password|passwd|token)\s*[:=]\s*['"]([^'"]{8,})['"]""",
            re.IGNORECASE,
        ),
        message="Hardcoded secret/password detected. Never commit secrets to source control.",
        suggestion="secret = os.environ['SECRET_KEY']",
        modes=(ReviewMode.FULL, ReviewMode.SECURITY),
    ),
    Rule(
        id="SEC003",
        name="aws-access-key",
        category=ReviewCategory.SECURITY,
        severity=Severity.CRITICAL,
        pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
        message="AWS Access Key ID detected. Rotate this key immediately.",
        modes=(ReviewMode.FULL, ReviewMode.SECURITY),
    ),
    Rule(
        id="SEC004",
        name="private-key-block",
        category=ReviewCategory.SECURITY,
        severity=Severity.CRITICAL,
        pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        message="Private key detected in source code. Use a secrets manager.",
        modes=(ReviewMode.FULL, ReviewMode.SECURITY),
    ),
    Rule(
        id="SEC005",
        name="github-token",
        category=ReviewCategory.SECURITY,
        severity=Severity.CRITICAL,
        pattern=re.compile(r"gh[pousr]_[A-Za-z0-9_]{36,}"),
        message="GitHub personal access token detected. Revoke and rotate immediately.",
        modes=(ReviewMode.FULL, ReviewMode.SECURITY),
    ),
    Rule(
        id="SEC006",
        name="generic-bearer-token",
        category=ReviewCategory.SECURITY,
        severity=Severity.ERROR,
        pattern=re.compile(
            r"""(?:Bearer|Authorization)\s*[:=]\s*['"]([A-Za-z0-9_\-\.]{20,})['"]""",
            re.IGNORECASE,
        ),
        message="Possible hardcoded bearer token. Use environment variables.",
        modes=(ReviewMode.FULL, ReviewMode.SECURITY),
    ),
]

# ─── Injection Rules ──────────────────────────────────────────────────────

INJECTION_RULES = [
    Rule(
        id="SEC010",
        name="sql-injection-format",
        category=ReviewCategory.SECURITY,
        severity=Severity.ERROR,
        pattern=re.compile(
            r"""(?:execute|cursor\.execute|query)\s*\(\s*f['"]|"""
            r"""(?:execute|cursor\.execute|query)\s*\(\s*['"].*%s""",
            re.IGNORECASE,
        ),
        message="Possible SQL injection via string formatting. Use parameterized queries.",
        suggestion='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        modes=(ReviewMode.FULL, ReviewMode.SECURITY),
    ),
    Rule(
        id="SEC011",
        name="command-injection-os-system",
        category=ReviewCategory.SECURITY,
        severity=Severity.ERROR,
        pattern=re.compile(r"os\.system\s*\("),
        message="os.system() is vulnerable to command injection. Use subprocess with shell=False.",
        suggestion="subprocess.run(['ls', '-la'], shell=False, check=True)",
        modes=(ReviewMode.FULL, ReviewMode.SECURITY),
    ),
    Rule(
        id="SEC012",
        name="command-injection-subprocess-shell",
        category=ReviewCategory.SECURITY,
        severity=Severity.WARNING,
        pattern=re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True"),
        message="subprocess with shell=True can be vulnerable to injection. Prefer shell=False.",
        modes=(ReviewMode.FULL, ReviewMode.SECURITY),
    ),
    Rule(
        id="SEC013",
        name="eval-exec-usage",
        category=ReviewCategory.SECURITY,
        severity=Severity.ERROR,
        pattern=re.compile(r"\b(?:eval|exec)\s*\("),
        message="eval()/exec() can execute arbitrary code. Avoid with untrusted input.",
        modes=(ReviewMode.FULL, ReviewMode.SECURITY),
    ),
    Rule(
        id="SEC014",
        name="jinja2-autoescape-disabled",
        category=ReviewCategory.SECURITY,
        severity=Severity.WARNING,
        pattern=re.compile(r"autoescape\s*=\s*False"),
        message="Jinja2 autoescape disabled. This can lead to XSS vulnerabilities.",
        modes=(ReviewMode.FULL, ReviewMode.SECURITY),
    ),
]

# ─── Style & Quality Rules ────────────────────────────────────────────────

STYLE_RULES = [
    Rule(
        id="STY001",
        name="todo-fixme-hack",
        category=ReviewCategory.MAINTAINABILITY,
        severity=Severity.INFO,
        pattern=re.compile(r"\b(TODO|FIXME|HACK|XXX)\b"),
        message="TODO/FIXME comment found. Consider creating a ticket to track this.",
        modes=(ReviewMode.FULL, ReviewMode.STYLE),
    ),
    Rule(
        id="STY002",
        name="bare-except",
        category=ReviewCategory.BUG,
        severity=Severity.WARNING,
        pattern=re.compile(r"except\s*:"),
        message="Bare except clause catches all exceptions including SystemExit and KeyboardInterrupt.",
        suggestion="except Exception as exc:",
        modes=(ReviewMode.FULL, ReviewMode.STYLE),
    ),
    Rule(
        id="STY003",
        name="print-statement",
        category=ReviewCategory.STYLE,
        severity=Severity.INFO,
        pattern=re.compile(r"^\s*print\s*\("),
        message="print() statement found. Use logging for production code.",
        suggestion="logger.debug(...)",
        modes=(ReviewMode.FULL, ReviewMode.STYLE),
    ),
    Rule(
        id="STY004",
        name="magic-number",
        category=ReviewCategory.STYLE,
        severity=Severity.INFO,
        pattern=re.compile(r"(?<![.\w])\b(?:86400|3600|60|100|1000|1024|2048|4096)\b(?!\s*[:=])"),
        message="Magic number detected. Consider extracting to a named constant.",
        modes=(ReviewMode.FULL, ReviewMode.STYLE),
    ),
    Rule(
        id="STY005",
        name="long-line",
        category=ReviewCategory.STYLE,
        severity=Severity.INFO,
        pattern=re.compile(r"^.{120,}$"),
        message="Line exceeds 120 characters. Consider breaking it up for readability.",
        modes=(ReviewMode.FULL, ReviewMode.STYLE),
    ),
    Rule(
        id="STY006",
        name="type-ignore",
        category=ReviewCategory.STYLE,
        severity=Severity.WARNING,
        pattern=re.compile(r"#\s*type:\s*ignore"),
        message="type: ignore comment found. Consider fixing the type error instead.",
        modes=(ReviewMode.FULL, ReviewMode.STYLE),
    ),
]

# ─── Bug Pattern Rules ────────────────────────────────────────────────────

BUG_RULES = [
    Rule(
        id="BUG001",
        name="mutable-default-arg",
        category=ReviewCategory.BUG,
        severity=Severity.WARNING,
        pattern=re.compile(r"def \w+\(.*=\s*(?:\[\]|\{\}|set\(\))"),
        message="Mutable default argument. This is shared across calls and can cause bugs.",
        suggestion="def func(items=None):\n    items = items or []",
        modes=(ReviewMode.FULL, ReviewMode.QUICK),
    ),
    Rule(
        id="BUG002",
        name="none-comparison-is",
        category=ReviewCategory.STYLE,
        severity=Severity.INFO,
        pattern=re.compile(r"[=!]=\s*None\b"),
        message="Use 'is None' or 'is not None' instead of == None.",
        suggestion="if x is None:",
        modes=(ReviewMode.FULL, ReviewMode.STYLE, ReviewMode.QUICK),
    ),
    Rule(
        id="BUG003",
        name="assert-in-production",
        category=ReviewCategory.BUG,
        severity=Severity.WARNING,
        pattern=re.compile(r"^\s*assert\s+"),
        message="assert statements are removed with -O flag. Don't use for validation.",
        modes=(ReviewMode.FULL, ReviewMode.QUICK),
    ),
    Rule(
        id="BUG004",
        name="unused-variable-underscore",
        category=ReviewCategory.STYLE,
        severity=Severity.INFO,
        pattern=re.compile(r"for\s+\w+\s+in\s+"),
        message="Loop variable may be unused. Use _ for intentionally unused variables.",
        modes=(ReviewMode.FULL, ReviewMode.STYLE),
    ),
]

# ─── Dependency Rules ─────────────────────────────────────────────────────

DEPENDENCY_RULES = [
    Rule(
        id="DEP001",
        name="unpinned-dependency",
        category=ReviewCategory.MAINTAINABILITY,
        severity=Severity.WARNING,
        pattern=re.compile(r"""(?:install_requires|dependencies)\s*=\s*\[.*['"]\w+['"]\s*\]"""),
        message="Unpinned dependency. Pin versions to avoid unexpected breakage.",
        modes=(ReviewMode.FULL, ReviewMode.STYLE),
    ),
]

ALL_RULES: list[Rule] = (
    SECRET_RULES + INJECTION_RULES + STYLE_RULES + BUG_RULES + DEPENDENCY_RULES
)


class StaticAnalyzer:
    """Rule-based static code analyzer for PR diffs."""

    def __init__(self, rules: Optional[list[Rule]] = None) -> None:
        self._rules = rules or ALL_RULES

    async def analyze_diff(
        self, diff_file: DiffFile, mode: ReviewMode
    ) -> list[InlineComment]:
        """Analyze a diff file and return inline comments.

        Args:
            diff_file: Parsed diff file with hunks.
            mode: Current review mode for filtering rules.

        Returns:
            List of inline comments found by static analysis.
        """
        comments: list[InlineComment] = []

        # Filter rules by review mode
        active_rules = [r for r in self._rules if mode in r.modes]

        for hunk in diff_file.hunks:
            line_number = hunk.new_start
            for line in hunk.lines:
                # Only analyze added lines (skip context and deletions)
                if not line.startswith("+"):
                    if not line.startswith("-"):
                        line_number += 1
                    continue

                code_line = line[1:]  # Strip the '+' prefix

                for rule in active_rules:
                    match = rule.matches(code_line)
                    if match:
                        comments.append(
                            InlineComment(
                                path=diff_file.path,
                                line=line_number,
                                body=rule.message,
                                severity=rule.severity,
                                category=rule.category,
                                suggestion=rule.suggestion,
                            )
                        )
                        break  # One finding per line per analysis

                line_number += 1

        return comments

    def add_rule(self, rule: Rule) -> None:
        """Add a custom rule to the analyzer."""
        self._rules.append(rule)

    def get_rules_for_mode(self, mode: ReviewMode) -> list[Rule]:
        """Get all rules active for a given review mode."""
        return [r for r in self._rules if mode in r.modes]

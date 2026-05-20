"""Tests for the static analyzer module."""

import pytest

from prism.analyzer import (
    StaticAnalyzer,
    SECRET_RULES,
    INJECTION_RULES,
    STYLE_RULES,
    BUG_RULES,
    ALL_RULES,
)
from prism.models import ReviewCategory, ReviewMode, Severity
from prism.reviewer import DiffFile, DiffHunk


def _make_diff_file(path: str, added_lines: list[str]) -> DiffFile:
    """Helper to create a DiffFile from added lines."""
    lines = [f"+{line}" for line in added_lines]
    return DiffFile(
        path=path,
        status="modified",
        additions=len(added_lines),
        hunks=[
            DiffHunk(
                path=path,
                old_start=1,
                old_count=0,
                new_start=1,
                new_count=len(added_lines),
                lines=lines,
            )
        ],
    )


@pytest.fixture
def analyzer():
    return StaticAnalyzer()


class TestSecretDetection:
    @pytest.mark.asyncio
    async def test_detect_api_key(self, analyzer):
        diff = _make_diff_file("config.py", [
            'api_key = "sk-1234567890abcdef1234567890"',
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.FULL)
        assert len(comments) >= 1
        assert any("API key" in c.body for c in comments)

    @pytest.mark.asyncio
    async def test_detect_password(self, analyzer):
        diff = _make_diff_file("db.py", [
            'password = "supersecret123"',
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.FULL)
        assert len(comments) >= 1

    @pytest.mark.asyncio
    async def test_detect_aws_key(self, analyzer):
        diff = _make_diff_file("deploy.py", [
            "aws_key = 'AKIAIOSFODNN7EXAMPLE'",
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.FULL)
        assert len(comments) >= 1

    @pytest.mark.asyncio
    async def test_detect_private_key(self, analyzer):
        diff = _make_diff_file("cert.py", [
            "key = '-----BEGIN RSA PRIVATE KEY-----'",
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.FULL)
        assert len(comments) >= 1

    @pytest.mark.asyncio
    async def test_no_false_positive(self, analyzer):
        diff = _make_diff_file("app.py", [
            "x = 1 + 2",
            "print('hello')",
        ])
        secret_comments = [
            c for c in await analyzer.analyze_diff(diff, ReviewMode.FULL)
            if c.category == ReviewCategory.SECURITY
        ]
        assert len(secret_comments) == 0


class TestInjectionDetection:
    @pytest.mark.asyncio
    async def test_detect_sql_injection(self, analyzer):
        diff = _make_diff_file("db.py", [
            'cursor.execute(f"SELECT * FROM users WHERE id={user_id}")',
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.FULL)
        assert len(comments) >= 1
        assert any("SQL injection" in c.body for c in comments)

    @pytest.mark.asyncio
    async def test_detect_os_system(self, analyzer):
        diff = _make_diff_file("utils.py", [
            'os.system(f"rm -rf {path}")',
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.FULL)
        assert len(comments) >= 1
        assert any("command injection" in c.body.lower() for c in comments)

    @pytest.mark.asyncio
    async def test_detect_eval(self, analyzer):
        diff = _make_diff_file("plugin.py", [
            "result = eval(user_input)",
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.FULL)
        assert len(comments) >= 1

    @pytest.mark.asyncio
    async def test_detect_subprocess_shell(self, analyzer):
        diff = _make_diff_file("deploy.py", [
            'subprocess.run(cmd, shell=True)',
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.FULL)
        assert len(comments) >= 1


class TestStyleDetection:
    @pytest.mark.asyncio
    async def test_detect_todo(self, analyzer):
        diff = _make_diff_file("app.py", [
            "# TODO: fix this later",
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.STYLE)
        assert len(comments) >= 1

    @pytest.mark.asyncio
    async def test_detect_bare_except(self, analyzer):
        diff = _make_diff_file("handler.py", [
            "except:",
            '    pass',
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.FULL)
        assert len(comments) >= 1
        assert any("Bare except" in c.body for c in comments)

    @pytest.mark.asyncio
    async def test_detect_print_statement(self, analyzer):
        diff = _make_diff_file("app.py", [
            'print("debug info")',
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.STYLE)
        assert len(comments) >= 1


class TestBugPatterns:
    @pytest.mark.asyncio
    async def test_detect_mutable_default(self, analyzer):
        diff = _make_diff_file("utils.py", [
            "def process(items=[]):",
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.FULL)
        assert len(comments) >= 1
        assert any("Mutable" in c.body for c in comments)

    @pytest.mark.asyncio
    async def test_detect_none_comparison(self, analyzer):
        diff = _make_diff_file("check.py", [
            "if x == None:",
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.STYLE)
        assert len(comments) >= 1


class TestAnalyzerModes:
    @pytest.mark.asyncio
    async def test_security_mode_only_security_rules(self, analyzer):
        diff = _make_diff_file("app.py", [
            'api_key = "sk-1234567890abcdef1234567890"',
            "# TODO: fix this",
        ])
        comments = await analyzer.analyze_diff(diff, ReviewMode.SECURITY)
        categories = {c.category for c in comments}
        assert ReviewCategory.SECURITY in categories

    @pytest.mark.asyncio
    async def test_quick_mode_fewer_rules(self, analyzer):
        diff = _make_diff_file("app.py", [
            "# TODO: fix this",
            'print("debug")',
        ])
        full_comments = await analyzer.analyze_diff(diff, ReviewMode.FULL)
        quick_comments = await analyzer.analyze_diff(diff, ReviewMode.QUICK)
        # Quick mode should have fewer or equal findings
        assert len(quick_comments) <= len(full_comments)

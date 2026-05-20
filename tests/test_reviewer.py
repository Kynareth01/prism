"""Tests for the review engine and diff parser."""

import pytest

from prism.models import InlineComment, ReviewCategory, ReviewMode, Severity
from prism.reviewer import DiffFile, DiffHunk, parse_diff, should_ignore_file


SAMPLE_DIFF = """\
diff --git a/src/auth.py b/src/auth.py
index abc1234..def5678 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,6 +10,12 @@ def login(username, password):
     user = db.find_user(username)
     if user is None:
         return None
-    return user.check_password(password)
+    api_key = "sk-1234567890abcdef"
+    if user.check_password(password):
+        session = create_session(user)
+        log.info(f"User {username} logged in")
+        return session
+    return None

diff --git a/README.md b/README.md
new file mode 100644
--- /dev/null
+++ b/README.md
@@ -0,0 +1,3 @@
+# My Project
+
+This is a project.
"""


class TestDiffParser:
    def test_parse_diff_files(self):
        files = parse_diff(SAMPLE_DIFF)
        assert len(files) == 2

    def test_parse_diff_file_paths(self):
        files = parse_diff(SAMPLE_DIFF)
        paths = [f.path for f in files]
        assert "src/auth.py" in paths
        assert "README.md" in paths

    def test_parse_diff_additions(self):
        files = parse_diff(SAMPLE_DIFF)
        auth_file = next(f for f in files if f.path == "src/auth.py")
        assert auth_file.additions > 0

    def test_parse_diff_new_file(self):
        files = parse_diff(SAMPLE_DIFF)
        readme = next(f for f in files if f.path == "README.md")
        assert readme.status == "added"

    def test_parse_diff_hunks(self):
        files = parse_diff(SAMPLE_DIFF)
        auth_file = next(f for f in files if f.path == "src/auth.py")
        assert len(auth_file.hunks) >= 1
        hunk = auth_file.hunks[0]
        assert hunk.new_start > 0

    def test_parse_empty_diff(self):
        files = parse_diff("")
        assert len(files) == 0


class TestIgnorePatterns:
    def test_ignore_lock_files(self):
        patterns = ("*.lock", "package-lock.json")
        assert should_ignore_file("poetry.lock", patterns) is True
        assert should_ignore_file("Cargo.lock", patterns) is True
        assert should_ignore_file("package-lock.json", patterns) is True

    def test_ignore_minified(self):
        patterns = ("*.min.js", "*.min.css")
        assert should_ignore_file("dist/bundle.min.js", patterns) is True
        assert should_ignore_file("styles.min.css", patterns) is True

    def test_dont_ignore_normal_files(self):
        patterns = ("*.lock", "*.min.js")
        assert should_ignore_file("src/main.py", patterns) is False
        assert should_ignore_file("README.md", patterns) is False


class TestInlineComment:
    def test_to_github_body_info(self):
        comment = InlineComment(
            path="test.py",
            line=10,
            body="This looks fine.",
            severity=Severity.INFO,
            category=ReviewCategory.STYLE,
        )
        body = comment.to_github_body()
        assert "ℹ️" in body
        assert "STYLE" in body
        assert "This looks fine." in body

    def test_to_github_body_with_suggestion(self):
        comment = InlineComment(
            path="test.py",
            line=5,
            body="Use parameterized query.",
            severity=Severity.ERROR,
            category=ReviewCategory.SECURITY,
            suggestion='cursor.execute("SELECT * FROM t WHERE id=%s", (id,))',
        )
        body = comment.to_github_body()
        assert "❌" in body
        assert "SECURITY" in body
        assert "Suggested fix:" in body
        assert "SELECT *" in body

    def test_to_github_body_critical(self):
        comment = InlineComment(
            path="config.py",
            line=1,
            body="Hardcoded API key!",
            severity=Severity.CRITICAL,
            category=ReviewCategory.SECURITY,
        )
        body = comment.to_github_body()
        assert "🚨" in body
        assert "CRITICAL" in body

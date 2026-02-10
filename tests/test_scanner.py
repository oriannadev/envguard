"""Tests for envguard's scanning engine, rules, allowlist, reporter, and CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from envguard.allowlist import AllowlistEntry, is_allowlisted, load_allowlist
from envguard.cli import main
from envguard.gitignore import parse_gitignore, should_skip
from envguard.reporter import format_json, format_sarif, format_text
from envguard.rules import Severity, get_rules
from envguard.scanner import Finding, scan_directory, scan_file

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "test_fixtures"


@pytest.fixture
def fake_env_path() -> Path:
    return FIXTURES_DIR / "fake_env"


@pytest.fixture
def fake_config_path() -> Path:
    return FIXTURES_DIR / "fake_config.py"


@pytest.fixture
def fake_clean_path() -> Path:
    return FIXTURES_DIR / "fake_clean.py"


@pytest.fixture
def all_rules():
    return get_rules()


@pytest.fixture
def empty_allowlist() -> list[AllowlistEntry]:
    return []


# ---------------------------------------------------------------------------
# Rules tests
# ---------------------------------------------------------------------------


class TestRules:
    """Verify that the built-in rules exist and have valid metadata."""

    def test_rules_not_empty(self, all_rules):
        assert len(all_rules) >= 12, "Expected at least 12 built-in rules"

    def test_all_rules_have_required_fields(self, all_rules):
        for rule in all_rules:
            assert rule.name, "Rule must have a name"
            assert rule.pattern, "Rule must have a compiled pattern"
            assert isinstance(rule.severity, Severity)
            assert rule.description, "Rule must have a description"

    def test_unique_rule_names(self, all_rules):
        names = [r.name for r in all_rules]
        assert len(names) == len(set(names)), "Rule names must be unique"


class TestSeverity:
    """Verify severity parsing and ordering."""

    def test_ordering(self):
        assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_from_string_case_insensitive(self):
        assert Severity.from_string("high") == Severity.HIGH
        assert Severity.from_string("HIGH") == Severity.HIGH
        assert Severity.from_string("High") == Severity.HIGH

    def test_from_string_invalid(self):
        with pytest.raises(ValueError, match="Unknown severity"):
            Severity.from_string("ultra")


# ---------------------------------------------------------------------------
# Scanner tests -- fake_env
# ---------------------------------------------------------------------------


class TestScanFakeEnv:
    """Scan the fake .env fixture and verify expected detections."""

    def test_detects_openai_key(self, fake_env_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_env_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        rule_names = {f.rule_name for f in findings}
        assert "openai-api-key" in rule_names

    def test_detects_aws_key(self, fake_env_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_env_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        rule_names = {f.rule_name for f in findings}
        assert "aws-access-key" in rule_names

    def test_detects_github_token(self, fake_env_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_env_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        rule_names = {f.rule_name for f in findings}
        assert "github-token" in rule_names

    def test_detects_database_url(self, fake_env_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_env_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        rule_names = {f.rule_name for f in findings}
        assert "database-url" in rule_names

    def test_detects_stripe_key(self, fake_env_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_env_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        rule_names = {f.rule_name for f in findings}
        assert "stripe-secret-key" in rule_names

    def test_detects_jwt(self, fake_env_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_env_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        rule_names = {f.rule_name for f in findings}
        assert "jwt-token" in rule_names

    def test_detects_slack_token(self, fake_env_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_env_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        rule_names = {f.rule_name for f in findings}
        assert "slack-token" in rule_names

    def test_findings_have_line_numbers(self, fake_env_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_env_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        for f in findings:
            assert f.line_number > 0, "Line numbers must be positive"

    def test_matches_are_redacted(self, fake_env_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_env_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        for f in findings:
            # Redacted matches should contain asterisks if the original
            # was longer than the visible prefix.
            assert len(f.match) <= 24 or "*" in f.match


# ---------------------------------------------------------------------------
# Scanner tests -- fake_config.py
# ---------------------------------------------------------------------------


class TestScanFakeConfig:
    """Scan the fake Python config fixture."""

    def test_detects_private_key(self, fake_config_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_config_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        rule_names = {f.rule_name for f in findings}
        assert "private-key" in rule_names

    def test_detects_generic_api_key(self, fake_config_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_config_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        # The file has API_KEY = "..." which should match generic-api-key
        # or openai-api-key (since it starts with sk-).
        rule_names = {f.rule_name for f in findings}
        assert "openai-api-key" in rule_names or "generic-api-key" in rule_names

    def test_detects_mysql_url(self, fake_config_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_config_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        rule_names = {f.rule_name for f in findings}
        assert "database-url" in rule_names


# ---------------------------------------------------------------------------
# Scanner tests -- fake_clean.py (no false positives)
# ---------------------------------------------------------------------------


class TestScanCleanFile:
    """The clean fixture must not produce any findings."""

    def test_no_findings(self, fake_clean_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_clean_path, FIXTURES_DIR, all_rules, empty_allowlist
        )
        assert findings == [], (
            f"Clean file should not trigger findings, but got: "
            f"{[f.rule_name for f in findings]}"
        )


# ---------------------------------------------------------------------------
# Severity filtering
# ---------------------------------------------------------------------------


class TestSeverityFiltering:
    """Verify that min_severity correctly filters findings."""

    def test_filter_high_and_above(self, fake_env_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_env_path,
            FIXTURES_DIR,
            all_rules,
            empty_allowlist,
            min_severity=Severity.HIGH,
        )
        for f in findings:
            assert f.severity >= Severity.HIGH

    def test_filter_critical_only(self, fake_env_path, all_rules, empty_allowlist):
        findings = scan_file(
            fake_env_path,
            FIXTURES_DIR,
            all_rules,
            empty_allowlist,
            min_severity=Severity.CRITICAL,
        )
        for f in findings:
            assert f.severity == Severity.CRITICAL

    def test_low_returns_everything(self, fake_env_path, all_rules, empty_allowlist):
        all_findings = scan_file(
            fake_env_path,
            FIXTURES_DIR,
            all_rules,
            empty_allowlist,
            min_severity=Severity.LOW,
        )
        high_findings = scan_file(
            fake_env_path,
            FIXTURES_DIR,
            all_rules,
            empty_allowlist,
            min_severity=Severity.HIGH,
        )
        assert len(all_findings) >= len(high_findings)


# ---------------------------------------------------------------------------
# Allowlist tests
# ---------------------------------------------------------------------------


class TestAllowlist:
    """Verify allowlist matching logic."""

    def test_exact_rule_match(self):
        entries = [AllowlistEntry(rule="openai-api-key", path=None, reason="test")]
        assert is_allowlisted("openai-api-key", "any/file.py", entries)
        assert not is_allowlisted("aws-access-key", "any/file.py", entries)

    def test_path_prefix_match(self):
        entries = [AllowlistEntry(rule=None, path="tests/", reason="test")]
        assert is_allowlisted("openai-api-key", "tests/foo.py", entries)
        assert not is_allowlisted("openai-api-key", "src/foo.py", entries)

    def test_combined_rule_and_path(self):
        entries = [
            AllowlistEntry(rule="openai-api-key", path="tests/", reason="test")
        ]
        assert is_allowlisted("openai-api-key", "tests/foo.py", entries)
        assert not is_allowlisted("aws-access-key", "tests/foo.py", entries)
        assert not is_allowlisted("openai-api-key", "src/foo.py", entries)

    def test_allowlist_suppresses_findings(
        self, fake_env_path, all_rules
    ):
        allowlist = [
            AllowlistEntry(
                rule=None,
                path="fake_env",
                reason="Test fixture",
            )
        ]
        findings = scan_file(
            fake_env_path, FIXTURES_DIR, all_rules, allowlist
        )
        assert findings == []

    def test_load_allowlist_missing_file(self, tmp_path):
        entries = load_allowlist(tmp_path)
        assert entries == []

    def test_load_allowlist_valid_file(self, tmp_path):
        rc = tmp_path / ".envguardrc"
        rc.write_text(json.dumps({
            "allowlist": [
                {"rule": "openai-api-key", "path": "tests/", "reason": "test"}
            ]
        }))
        entries = load_allowlist(tmp_path)
        assert len(entries) == 1
        assert entries[0].rule == "openai-api-key"


# ---------------------------------------------------------------------------
# Gitignore tests
# ---------------------------------------------------------------------------


class TestGitignore:
    """Verify .gitignore-aware file skipping."""

    def test_skips_git_directory(self, tmp_path):
        filepath = tmp_path / ".git" / "config"
        assert should_skip(filepath, tmp_path, [])

    def test_skips_node_modules(self, tmp_path):
        filepath = tmp_path / "node_modules" / "package" / "index.js"
        assert should_skip(filepath, tmp_path, [])

    def test_skips_binary_files(self, tmp_path):
        filepath = tmp_path / "image.png"
        assert should_skip(filepath, tmp_path, [])

    def test_skips_gitignore_pattern(self, tmp_path):
        filepath = tmp_path / "dist" / "bundle.js"
        # "dist" is in ALWAYS_SKIP_DIRS, so also test a custom pattern.
        filepath2 = tmp_path / "coverage" / "report.html"
        assert should_skip(filepath2, tmp_path, ["coverage/"])

    def test_allows_normal_files(self, tmp_path):
        filepath = tmp_path / "src" / "main.py"
        assert not should_skip(filepath, tmp_path, [])

    def test_parse_gitignore_comments_ignored(self, tmp_path):
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("# comment\n\nnode_modules\n*.pyc\n")
        patterns = parse_gitignore(tmp_path)
        assert patterns == ["node_modules", "*.pyc"]


# ---------------------------------------------------------------------------
# Directory scanning integration test
# ---------------------------------------------------------------------------


class TestScanDirectory:
    """Integration test: scan the test_fixtures directory."""

    def test_scan_fixtures_finds_secrets(self):
        findings = scan_directory(FIXTURES_DIR)
        assert len(findings) > 0, "Should detect secrets in test fixtures"

    def test_scan_fixtures_no_clean_file_findings(self):
        findings = scan_directory(FIXTURES_DIR)
        clean_findings = [f for f in findings if "fake_clean" in f.rel_path]
        assert clean_findings == [], (
            f"Clean file should have no findings: {clean_findings}"
        )

    def test_findings_sorted_by_severity(self):
        findings = scan_directory(FIXTURES_DIR)
        if len(findings) > 1:
            for i in range(len(findings) - 1):
                # Higher severity (larger int) should come first.
                assert findings[i].severity >= findings[i + 1].severity or (
                    findings[i].severity == findings[i + 1].severity
                )

    def test_nonexistent_directory_raises(self):
        with pytest.raises(FileNotFoundError):
            scan_directory(Path("/nonexistent/path/that/does/not/exist"))


# ---------------------------------------------------------------------------
# Reporter tests
# ---------------------------------------------------------------------------


class TestReporterJSON:
    """Verify JSON output format."""

    def test_json_output_is_valid(self):
        findings = scan_directory(FIXTURES_DIR)
        output = format_json(findings)
        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert len(parsed) == len(findings)

    def test_json_fields(self):
        findings = scan_directory(FIXTURES_DIR)
        output = format_json(findings)
        parsed = json.loads(output)
        if parsed:
            record = parsed[0]
            assert "rule" in record
            assert "severity" in record
            assert "file" in record
            assert "line" in record
            assert "match" in record

    def test_empty_findings_json(self):
        output = format_json([])
        parsed = json.loads(output)
        assert parsed == []


class TestReporterSARIF:
    """Verify SARIF output format."""

    def test_sarif_schema_version(self):
        findings = scan_directory(FIXTURES_DIR)
        output = format_sarif(findings)
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1

    def test_sarif_results_count(self):
        findings = scan_directory(FIXTURES_DIR)
        output = format_sarif(findings)
        parsed = json.loads(output)
        results = parsed["runs"][0]["results"]
        assert len(results) == len(findings)

    def test_sarif_tool_name(self):
        output = format_sarif([])
        parsed = json.loads(output)
        driver = parsed["runs"][0]["tool"]["driver"]
        assert driver["name"] == "envguard"

    def test_empty_findings_sarif(self):
        output = format_sarif([])
        parsed = json.loads(output)
        assert parsed["runs"][0]["results"] == []


class TestReporterText:
    """Verify text output does not crash."""

    def test_text_output_no_findings(self, capsys):
        format_text([])
        # Should not raise

    def test_text_output_with_findings(self):
        findings = scan_directory(FIXTURES_DIR)
        # Should not raise
        format_text(findings)


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestCLI:
    """Test the Click CLI entry point."""

    @pytest.fixture
    def runner(self):
        return CliRunner()

    def test_version(self, runner):
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "envguard" in result.output

    def test_scan_fixtures_returns_exit_1(self, runner):
        result = runner.invoke(main, ["scan", str(FIXTURES_DIR)])
        assert result.exit_code == 1

    def test_scan_clean_dir_returns_exit_0(self, runner, tmp_path):
        # Create a clean directory with a single harmless file.
        (tmp_path / "clean.py").write_text("x = 1\n")
        result = runner.invoke(main, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_json_output(self, runner):
        result = runner.invoke(main, ["scan", str(FIXTURES_DIR), "--json"])
        assert result.exit_code == 1
        parsed = json.loads(result.output)
        assert isinstance(parsed, list)
        assert len(parsed) > 0

    def test_scan_sarif_output(self, runner):
        result = runner.invoke(main, ["scan", str(FIXTURES_DIR), "--sarif"])
        assert result.exit_code == 1
        parsed = json.loads(result.output)
        assert parsed["version"] == "2.1.0"

    def test_scan_severity_filter(self, runner):
        result_all = runner.invoke(
            main, ["scan", str(FIXTURES_DIR), "--json", "--severity", "low"]
        )
        result_critical = runner.invoke(
            main, ["scan", str(FIXTURES_DIR), "--json", "--severity", "critical"]
        )
        all_findings = json.loads(result_all.output)
        critical_findings = json.loads(result_critical.output)
        assert len(all_findings) >= len(critical_findings)
        for f in critical_findings:
            assert f["severity"] == "critical"

    def test_scan_nonexistent_path(self, runner):
        result = runner.invoke(main, ["scan", "/nonexistent/path"])
        assert result.exit_code != 0

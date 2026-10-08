"""
tests/test_reporter.py — Tests for JSON serialisation and output formatting.
"""

from __future__ import annotations

import json
from dataclasses import fields
from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest

from checker.reporter import json_report, to_dict
from checker.scanner import HeaderFinding, ScanResult, analyse_headers


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_result(score: int = 85, grade: str = "B") -> ScanResult:
    """Build a minimal ScanResult with one header finding for testing output."""
    finding = HeaderFinding(
        name="Content-Security-Policy",
        present=True,
        value="default-src 'self'",
        status="pass",
        points_earned=25.0,
        points_max=25,
        detail="No dangerous directives detected ✓",
        fix="",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    )
    return ScanResult(
        url="https://example.com",
        final_url="https://example.com",
        status_code=200,
        is_https=True,
        redirected_to_https=False,
        score=score,
        max_score=100,
        grade=grade,
        timestamp="2026-10-08T09:00:00+00:00",
        elapsed_ms=42,
        header_findings=[finding],
        info_leaks=[],
        cookie_issues=[],
    )


# ---------------------------------------------------------------------------
# to_dict
# ---------------------------------------------------------------------------

class TestToDict:
    def test_returns_dict(self):
        result = _make_result()
        d = to_dict(result)
        assert isinstance(d, dict)

    def test_url_preserved(self):
        d = to_dict(_make_result())
        assert d["url"] == "https://example.com"

    def test_score_present(self):
        d = to_dict(_make_result(score=72))
        assert d["score"] == 72

    def test_grade_present(self):
        d = to_dict(_make_result(grade="C"))
        assert d["grade"] == "C"

    def test_header_findings_list(self):
        d = to_dict(_make_result())
        assert isinstance(d["header_findings"], list)
        assert len(d["header_findings"]) == 1

    def test_points_earned_rounded_to_int(self):
        """points_earned should be stored as an integer in the output dict."""
        d = to_dict(_make_result())
        finding = d["header_findings"][0]
        assert isinstance(finding["points_earned"], int)
        assert finding["points_earned"] == 25

    def test_all_scanresult_fields_present(self):
        """Every field of ScanResult should appear in the dict."""
        d = to_dict(_make_result())
        for f in fields(ScanResult):
            assert f.name in d, f"Missing field in to_dict output: {f.name}"


# ---------------------------------------------------------------------------
# json_report
# ---------------------------------------------------------------------------

class TestJsonReport:
    def test_output_is_valid_json(self):
        result = _make_result()
        output = json_report(result)
        parsed = json.loads(output)   # raises if invalid
        assert isinstance(parsed, dict)

    def test_json_contains_score(self):
        output = json_report(_make_result(score=55))
        parsed = json.loads(output)
        assert parsed["score"] == 55

    def test_json_contains_header_findings(self):
        output = json_report(_make_result())
        parsed = json.loads(output)
        assert "header_findings" in parsed
        assert len(parsed["header_findings"]) > 0

    def test_json_error_result(self):
        """An error result should still serialise cleanly."""
        error_result = ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            status_code=0,
            is_https=True,
            redirected_to_https=False,
            score=0,
            max_score=100,
            grade="F",
            timestamp="2026-10-08T09:00:00+00:00",
            elapsed_ms=0,
            error="SSL/TLS error — [SSL: CERT_EXPIRED]",
        )
        output = json_report(error_result)
        parsed = json.loads(output)
        assert parsed["score"] == 0
        assert parsed["error"] is not None
        assert "SSL" in parsed["error"]


# ---------------------------------------------------------------------------
# console_report (smoke test — just verifies it doesn't raise)
# ---------------------------------------------------------------------------

class TestConsoleReport:
    def test_console_report_success(self, capsys):
        from io import StringIO
        from rich.console import Console
        from checker.reporter import console_report

        buf = StringIO()
        console = Console(file=buf, no_color=True)
        console_report(_make_result(), console=console)
        output = buf.getvalue()

        assert "example.com" in output
        assert "85" in output           # score
        assert "Pass" in output or "PASS" in output or "pass" in output.lower()

    def test_console_report_error_case(self):
        from io import StringIO
        from rich.console import Console
        from checker.reporter import console_report

        error_result = ScanResult(
            url="https://bad.example.com",
            final_url="https://bad.example.com",
            status_code=0,
            is_https=True,
            redirected_to_https=False,
            score=0,
            max_score=100,
            grade="F",
            timestamp="2026-10-08T09:00:00+00:00",
            elapsed_ms=0,
            error="Could not connect: Connection refused",
        )
        buf = StringIO()
        console = Console(file=buf, no_color=True)
        console_report(error_result, console=console)
        output = buf.getvalue()

        assert "SCAN FAILED" in output
        assert "Connection refused" in output

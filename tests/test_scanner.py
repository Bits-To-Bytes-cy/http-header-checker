"""
tests/test_scanner.py — Tests for the core scan and analysis logic.

All HTTP calls are mocked via unittest.mock.patch; no real network requests
are made.  Each test exercises a specific behaviour or failure mode.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest

from checker.scanner import (
    ScanResult,
    _check_cookies,
    _check_info_leaks,
    _grade,
    analyse_headers,
    scan,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(
    headers: dict,
    url: str = "https://example.com",
    status_code: int = 200,
    raw_cookies: list[str] | None = None,
    elapsed_ms: int = 42,
) -> MagicMock:
    """
    Build a minimal mock of requests.Response suitable for analyse_headers().
    """
    mock = MagicMock()
    mock.headers = headers
    mock.url = url
    mock.status_code = status_code
    mock.elapsed = timedelta(milliseconds=elapsed_ms)

    # Mock urllib3's getlist() for Set-Cookie header extraction
    cookies = raw_cookies or []
    mock.raw.headers.getlist = lambda key: cookies if key == "set-cookie" else []

    return mock


# A headers dict with all 8 security headers at their best values
_PERFECT_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy":   "default-src 'self'; script-src 'self'",
    "X-Frame-Options":           "DENY",
    "X-Content-Type-Options":    "nosniff",
    "Referrer-Policy":           "strict-origin-when-cross-origin",
    "Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Opener-Policy":"same-origin",
    "Cache-Control":             "no-store, no-cache, must-revalidate",
}


# ---------------------------------------------------------------------------
# _grade
# ---------------------------------------------------------------------------

class TestGrade:
    def test_a_grade(self):        assert _grade(95) == "A"
    def test_a_grade_boundary(self): assert _grade(90) == "A"
    def test_b_grade(self):        assert _grade(80) == "B"
    def test_b_grade_boundary(self): assert _grade(75) == "B"
    def test_c_grade(self):        assert _grade(65) == "C"
    def test_d_grade(self):        assert _grade(45) == "D"
    def test_f_grade(self):        assert _grade(20) == "F"
    def test_f_grade_zero(self):   assert _grade(0)  == "F"


# ---------------------------------------------------------------------------
# _check_info_leaks
# ---------------------------------------------------------------------------

class TestInfoLeaks:
    def test_server_with_version_is_flagged(self):
        leaks = _check_info_leaks({"Server": "Apache/2.4.41"})
        assert len(leaks) == 1
        assert "version" in leaks[0].lower()

    def test_x_powered_by_with_php_version(self):
        leaks = _check_info_leaks({"X-Powered-By": "PHP/8.1.0"})
        assert len(leaks) == 1
        assert "version" in leaks[0].lower()

    def test_server_without_version_still_flagged(self):
        """Even 'nginx' (no version) discloses server technology."""
        leaks = _check_info_leaks({"Server": "nginx"})
        assert len(leaks) == 1
        assert "technology" in leaks[0].lower()

    def test_no_disclosure_headers_is_clean(self):
        leaks = _check_info_leaks({"Content-Type": "text/html"})
        assert leaks == []

    def test_multiple_disclosure_headers(self):
        leaks = _check_info_leaks({
            "Server": "Apache/2.4",
            "X-Powered-By": "PHP/7.4",
        })
        assert len(leaks) == 2


# ---------------------------------------------------------------------------
# _check_cookies
# ---------------------------------------------------------------------------

class TestCookieCheck:
    def test_secure_cookie_no_issues(self):
        issues = _check_cookies(["session=abc; Secure; HttpOnly; SameSite=Strict"])
        assert issues == []

    def test_missing_secure_flag(self):
        issues = _check_cookies(["session=abc; HttpOnly; SameSite=Strict"])
        assert any("Secure" in i for i in issues)

    def test_missing_httponly_flag(self):
        issues = _check_cookies(["session=abc; Secure; SameSite=Strict"])
        assert any("HttpOnly" in i for i in issues)

    def test_missing_samesite_flag(self):
        issues = _check_cookies(["session=abc; Secure; HttpOnly"])
        assert any("SameSite" in i for i in issues)

    def test_all_flags_missing(self):
        issues = _check_cookies(["session=abc"])
        assert len(issues) == 1
        assert "Secure" in issues[0]
        assert "HttpOnly" in issues[0]
        assert "SameSite" in issues[0]

    def test_empty_cookie_list_is_clean(self):
        assert _check_cookies([]) == []


# ---------------------------------------------------------------------------
# analyse_headers / scan (mocked HTTP)
# ---------------------------------------------------------------------------

class TestAnalyseHeaders:
    def test_perfect_headers_score_100(self):
        resp = _make_response(_PERFECT_HEADERS)
        result = analyse_headers(resp, "https://example.com")
        assert result.score == 100
        assert result.grade == "A"
        assert result.error is None

    def test_no_headers_score_0(self):
        resp = _make_response({})
        result = analyse_headers(resp, "https://example.com")
        assert result.score == 0
        assert result.grade == "F"

    def test_all_findings_present_in_result(self):
        from checker.headers import SECURITY_HEADERS
        resp = _make_response(_PERFECT_HEADERS)
        result = analyse_headers(resp, "https://example.com")
        found_names = {f.name for f in result.header_findings}
        expected_names = {h.name for h in SECURITY_HEADERS}
        assert found_names == expected_names

    def test_http_url_sets_hsts_note(self):
        resp = _make_response({}, url="http://example.com")
        result = analyse_headers(resp, "http://example.com")
        assert result.hsts_note is not None
        assert not result.is_https

    def test_http_to_https_redirect_is_detected(self):
        resp = _make_response({}, url="https://example.com")   # final URL is HTTPS
        result = analyse_headers(resp, "http://example.com")    # original is HTTP
        assert result.redirected_to_https is True
        assert "redirect" in result.hsts_note.lower()

    def test_weak_csp_is_warning(self):
        headers = {**_PERFECT_HEADERS,
                   "Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
        resp = _make_response(headers)
        result = analyse_headers(resp, "https://example.com")
        csp = next(f for f in result.header_findings if f.name == "Content-Security-Policy")
        assert csp.status == "warning"
        assert result.score < 100

    def test_short_hsts_max_age_is_warning(self):
        headers = {**_PERFECT_HEADERS,
                   "Strict-Transport-Security": "max-age=3600"}  # 1 hour — too short
        resp = _make_response(headers)
        result = analyse_headers(resp, "https://example.com")
        hsts = next(f for f in result.header_findings
                    if f.name == "Strict-Transport-Security")
        assert hsts.status == "warning"

    def test_info_leak_detected_in_result(self):
        resp = _make_response({**_PERFECT_HEADERS, "Server": "Apache/2.4.41"})
        result = analyse_headers(resp, "https://example.com")
        assert len(result.info_leaks) == 1

    def test_cookie_issues_detected_in_result(self):
        resp = _make_response(
            _PERFECT_HEADERS,
            raw_cookies=["sessionid=abc123"],   # no flags at all
        )
        result = analyse_headers(resp, "https://example.com")
        assert len(result.cookie_issues) > 0

    def test_result_records_final_url(self):
        resp = _make_response(_PERFECT_HEADERS, url="https://www.example.com")
        result = analyse_headers(resp, "https://example.com")
        assert result.final_url == "https://www.example.com"


# ---------------------------------------------------------------------------
# scan() — error handling paths
# ---------------------------------------------------------------------------

class TestScanErrorHandling:
    def test_scan_timeout(self):
        from requests.exceptions import Timeout
        with patch("checker.scanner.fetch_headers", side_effect=Timeout()):
            result = scan("https://example.com")
        assert result.error is not None
        assert "timed out" in result.error.lower()
        assert result.score == 0

    def test_scan_ssl_error(self):
        from requests.exceptions import SSLError
        with patch("checker.scanner.fetch_headers", side_effect=SSLError("CERT_EXPIRED")):
            result = scan("https://example.com")
        assert result.error is not None
        assert "ssl" in result.error.lower()

    def test_scan_connection_error(self):
        from requests.exceptions import ConnectionError as ReqConnectionError
        with patch("checker.scanner.fetch_headers",
                   side_effect=ReqConnectionError("refused")):
            result = scan("https://example.com")
        assert result.error is not None
        assert "connect" in result.error.lower()

    def test_scan_too_many_redirects(self):
        from requests.exceptions import TooManyRedirects
        with patch("checker.scanner.fetch_headers",
                   side_effect=TooManyRedirects()):
            result = scan("https://example.com")
        assert result.error is not None
        assert "redirect" in result.error.lower()

    def test_scan_adds_scheme_if_missing(self):
        """URLs without a scheme should be treated as https://."""
        with patch("checker.scanner.fetch_headers") as mock_fetch:
            mock_fetch.return_value = _make_response(_PERFECT_HEADERS)
            result = scan("example.com")
        # The fetch was called — no crash — and scheme was normalised
        assert result.error is None
        assert "https://" in result.url


# ---------------------------------------------------------------------------
# Multiple URL scenario
# ---------------------------------------------------------------------------

class TestMultipleUrls:
    def test_two_urls_independent_results(self):
        """Scanning two URLs returns independent ScanResults."""
        with patch("checker.scanner.fetch_headers") as mock_fetch:
            mock_fetch.side_effect = [
                _make_response(_PERFECT_HEADERS),
                _make_response({}),
            ]
            r1 = scan("https://good.example.com")
            r2 = scan("https://bad.example.com")

        assert r1.score == 100
        assert r2.score == 0
        assert r1.score > r2.score

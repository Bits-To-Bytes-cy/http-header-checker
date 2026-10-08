"""
checker/scanner.py — Core HTTP fetch and analysis logic.

Responsibilities
----------------
- Fetch HTTP response headers with a clear User-Agent and configurable timeout
- Analyse each security header (with value-quality scoring)
- Detect information-disclosure headers (Server, X-Powered-By, …)
- Check Set-Cookie flags (Secure, HttpOnly, SameSite)
- Detect HTTP-only sites and whether they redirect to HTTPS
- Return structured ScanResult / HeaderFinding dataclasses

All I/O funnels through scan(), which catches every common error condition
and returns a ScanResult with a descriptive error string rather than raising.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests
from requests.exceptions import (
    ConnectionError as ReqConnectionError,
    SSLError,
    Timeout,
    TooManyRedirects,
    RequestException,
)

from .headers import SECURITY_HEADERS

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

USER_AGENT = (
    "http-header-checker/1.0 "
    "(Security Assessment Tool; "
    "+https://github.com/Bits-To-Bytes-cy/http-header-checker)"
)

# Headers that commonly disclose server technology or version numbers.
_INFO_LEAK_HEADER_NAMES = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
]

# Matches version-like strings: "2.4.41", "7.4", "1.0.0-beta" etc.
_VERSION_RE = re.compile(r"\d+\.\d+")


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class HeaderFinding:
    """Scored result for a single HTTP security header."""
    name: str
    present: bool
    value: Optional[str]
    status: str              # "pass" | "warning" | "fail"
    points_earned: float     # Raw float; display as rounded int
    points_max: int
    detail: str              # Human-readable finding description
    fix: str                 # One-line remediation hint
    reference: str           # MDN / OWASP URL


@dataclass
class ScanResult:
    """Complete result for a single URL scan."""
    url: str                        # Original URL as supplied by the user
    final_url: str                  # URL after following redirects
    status_code: int                # HTTP status code (0 on connection failure)
    is_https: bool                  # Whether the original URL used HTTPS
    redirected_to_https: bool       # HTTP → HTTPS redirect detected
    score: int                      # 0-100 weighted score
    max_score: int                  # Always 100
    grade: str                      # A / B / C / D / F
    timestamp: str                  # ISO-8601 UTC timestamp
    elapsed_ms: int                 # Round-trip time in milliseconds
    header_findings: list[HeaderFinding] = field(default_factory=list)
    info_leaks: list[str]           = field(default_factory=list)
    cookie_issues: list[str]        = field(default_factory=list)
    hsts_note: Optional[str]        = None   # Set for HTTP-only sites
    error: Optional[str]            = None   # Set only on scan failure


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _grade(score: int) -> str:
    """Convert a 0-100 score into a letter grade."""
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def _check_info_leaks(response_headers: requests.structures.CaseInsensitiveDict) -> list[str]:
    """
    Inspect well-known disclosure headers and warn if a version number is visible.

    Returns a list of human-readable warning strings (not scored).
    """
    findings: list[str] = []
    for header_name in _INFO_LEAK_HEADER_NAMES:
        value = response_headers.get(header_name)
        if value is None:
            continue
        if _VERSION_RE.search(value):
            findings.append(
                f"{header_name}: '{value}' — exposes software version "
                "(remove, sanitise, or set a generic value)"
            )
        else:
            findings.append(
                f"{header_name}: '{value}' — discloses server technology "
                "(consider removing)"
            )
    return findings


def _check_cookies(raw_cookies: list[str]) -> list[str]:
    """
    Check each raw Set-Cookie string for missing security flags.

    Args:
        raw_cookies: List of raw Set-Cookie header values.

    Returns:
        List of human-readable issue strings (not scored).
    """
    issues: list[str] = []
    for cookie_str in raw_cookies:
        if not cookie_str:
            continue

        # The cookie name is the portion before the first '='
        name = cookie_str.split("=", 1)[0].strip()
        lower = cookie_str.lower()
        parts = [p.strip() for p in lower.split(";")]
        missing: list[str] = []

        # Secure flag — required for cookies sent over HTTPS
        if "secure" not in parts:
            missing.append("Secure")

        # HttpOnly — prevents JavaScript access to the cookie value
        if "httponly" not in parts:
            missing.append("HttpOnly")

        # SameSite — mitigates CSRF (any value is better than none)
        if not any(p.startswith("samesite") for p in parts):
            missing.append("SameSite")

        if missing:
            issues.append(
                f"Cookie '{name}' is missing flag(s): "
                + ", ".join(missing)
            )
    return issues


def _extract_raw_cookies(response: requests.Response) -> list[str]:
    """
    Extract raw Set-Cookie header values from a response.

    requests collapses duplicate headers; urllib3's underlying response
    preserves them. We try the lower-level API first, then fall back.
    """
    try:
        # urllib3 ≥ 1.26 exposes getlist() on the HTTPHeaderDict
        return response.raw.headers.getlist("set-cookie")
    except AttributeError:
        pass

    # Fallback: single combined value (may miss multiple cookies)
    val = response.headers.get("Set-Cookie")
    return [val] if val else []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fetch_headers(url: str, timeout: int = 10) -> requests.Response:
    """
    Perform a GET request and return the response.

    Sets a descriptive User-Agent, follows redirects, and enforces the
    supplied timeout.  SSL verification is on by default; SSLError is
    caught and re-raised with a clear message at the scan() level.
    """
    return requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": USER_AGENT},
        verify=True,
    )


def analyse_headers(response: requests.Response, original_url: str) -> ScanResult:
    """
    Build a ScanResult from a completed requests.Response.

    This function is kept separate from fetch_headers() so that tests can
    supply a mock response without making real network calls.
    """
    resp_headers = response.headers
    is_https = original_url.lower().startswith("https://")
    final_is_https = response.url.lower().startswith("https://")
    redirected_to_https = (not is_https) and final_is_https

    total_score: float = 0.0
    findings: list[HeaderFinding] = []

    for defn in SECURITY_HEADERS:
        value: Optional[str] = resp_headers.get(defn.name)

        if value is None:
            # Special case: HSTS cannot be enforced over plain HTTP
            if defn.name == "Strict-Transport-Security" and not is_https:
                status = "warning"
                detail = "Not applicable over plain HTTP — HSTS requires an HTTPS context"
                points: float = 0.0
            else:
                status = "fail"
                detail = "Header is absent"
                points = 0.0
        else:
            if defn.checker is not None:
                status, detail, fraction = defn.checker(value)
                points = defn.weight * fraction
            else:
                # No checker supplied — presence alone earns full credit
                status = "pass"
                detail = f"'{value}' ✓"
                points = float(defn.weight)

        total_score += points
        findings.append(
            HeaderFinding(
                name=defn.name,
                present=value is not None,
                value=value,
                status=status,
                points_earned=points,
                points_max=defn.weight,
                detail=detail,
                fix=defn.fix,
                reference=defn.reference,
            )
        )

    # Build HSTS / HTTP note
    hsts_note: Optional[str] = None
    if not is_https:
        if redirected_to_https:
            hsts_note = (
                f"Site redirects HTTP → HTTPS (final URL: {response.url}). "
                "HSTS will work on the HTTPS origin, but scanning over HTTP "
                "may miss HTTPS-only headers."
            )
        else:
            hsts_note = (
                "Site does not redirect to HTTPS. "
                "HSTS provides no protection — the site should enforce HTTPS."
            )

    score = round(total_score)

    return ScanResult(
        url=original_url,
        final_url=response.url,
        status_code=response.status_code,
        is_https=is_https,
        redirected_to_https=redirected_to_https,
        score=score,
        max_score=100,
        grade=_grade(score),
        timestamp=datetime.now(timezone.utc).isoformat(),
        elapsed_ms=int(response.elapsed.total_seconds() * 1000),
        header_findings=findings,
        info_leaks=_check_info_leaks(resp_headers),
        cookie_issues=_check_cookies(_extract_raw_cookies(response)),
        hsts_note=hsts_note,
    )


def _error_result(url: str, error: str) -> ScanResult:
    """Return a zero-score ScanResult that records a scan failure."""
    return ScanResult(
        url=url,
        final_url=url,
        status_code=0,
        is_https=url.lower().startswith("https://"),
        redirected_to_https=False,
        score=0,
        max_score=100,
        grade="F",
        timestamp=datetime.now(timezone.utc).isoformat(),
        elapsed_ms=0,
        error=error,
    )


def scan(url: str, timeout: int = 10) -> ScanResult:
    """
    Fetch and analyse the security headers for a URL.

    This is the primary public entry point.  It normalises the URL,
    performs the request, and maps every common failure mode to a
    descriptive error message rather than an unhandled exception.

    Args:
        url:     Target URL.  A scheme is added (https://) if absent.
        timeout: Request timeout in seconds.

    Returns:
        ScanResult — always, even on failure (check result.error).
    """
    # Normalise: add scheme if absent
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = fetch_headers(url, timeout=timeout)
        return analyse_headers(response, original_url=url)

    except SSLError as exc:
        return _error_result(
            url,
            f"SSL/TLS error — {exc}. "
            "Try with http:// or check that the certificate is valid.",
        )
    except Timeout:
        return _error_result(
            url,
            f"Request timed out after {timeout}s. "
            "Use --timeout to increase the limit.",
        )
    except TooManyRedirects:
        return _error_result(url, "Too many redirects — possible redirect loop.")
    except ReqConnectionError as exc:
        return _error_result(url, f"Could not connect: {exc}")
    except RequestException as exc:
        return _error_result(url, f"Request failed: {exc}")

"""
checker/headers.py — Security header definitions, scoring weights, and value validators.

Each HeaderDefinition describes one HTTP security header: its maximum point value,
a human-readable description, a one-line remediation hint, and an optional value-
checker function that returns (status, detail, score_fraction).

Design notes
------------
- Weights sum to exactly 100.
- X-XSS-Protection is intentionally excluded — it is deprecated and modern guidance
  recommends disabling it or relying on CSP instead.
- Presence alone is not sufficient; value quality determines the final score.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SIX_MONTHS_SECONDS = 15_552_000   # 180 days
_ONE_YEAR_SECONDS   = 31_536_000   # 365 days

_GOOD_REFERRER_POLICIES: frozenset[str] = frozenset({
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
})

_WEAK_REFERRER_POLICIES: frozenset[str] = frozenset({
    "unsafe-url",
    "no-referrer-when-downgrade",
})

_VALID_XFO_VALUES: frozenset[str] = frozenset({"DENY", "SAMEORIGIN"})

_STRONG_COOP_VALUES: frozenset[str] = frozenset({"same-origin"})
_VALID_COOP_VALUES: frozenset[str] = frozenset({
    "same-origin",
    "same-origin-allow-popups",
    "unsafe-none",
})

# Matches a standalone * (whitespace or string boundary on each side).
# Catches: "default-src *" but not "https://*.example.com".
_WILDCARD_RE = re.compile(r"(?:^|\s)\*(?:\s|$)")

# ---------------------------------------------------------------------------
# Value checker functions
#   Signature: (value: str) -> tuple[status, detail, score_fraction]
#   status  : "pass" | "warning" | "fail"
#   detail  : human-readable explanation of the finding
#   score_fraction : 0.0 – 1.0, multiplied by the header weight
# ---------------------------------------------------------------------------

def check_hsts(value: str) -> tuple[str, str, float]:
    """
    Validate Strict-Transport-Security.

    Scoring:
      - missing max-age         → fail   (0.0)
      - max-age <  6 months     → warning (0.4) — too short
      - max-age >= 6 months     → pass   (0.8)
      - max-age >= 1 year
        + includeSubDomains     → pass   (1.0)
    """
    parts = [p.strip().lower() for p in value.split(";")]
    max_age: Optional[int] = None
    include_subdomains = "includesubdomains" in parts

    for part in parts:
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1].strip())
            except ValueError:
                pass

    if max_age is None:
        return "fail", "max-age directive is missing or unparseable", 0.0

    if max_age < _SIX_MONTHS_SECONDS:
        return (
            "warning",
            f"max-age={max_age:,}s is too short (minimum recommended: {_SIX_MONTHS_SECONDS:,}s / 6 months)",
            0.4,
        )

    if max_age >= _ONE_YEAR_SECONDS and include_subdomains:
        return "pass", f"max-age={max_age:,}s, includeSubDomains present ✓", 1.0

    detail = f"max-age={max_age:,}s"
    if not include_subdomains:
        detail += " — consider adding includeSubDomains"
    return "pass", detail, 0.8


def check_csp(value: str) -> tuple[str, str, float]:
    """
    Validate Content-Security-Policy.

    Flags 'unsafe-inline', 'unsafe-eval', and bare wildcard (*) sources.
    Those directives largely defeat the purpose of CSP against XSS.
    """
    weak: list[str] = []
    lower = value.lower()

    if "'unsafe-inline'" in lower:
        weak.append("'unsafe-inline'")
    if "'unsafe-eval'" in lower:
        weak.append("'unsafe-eval'")
    if _WILDCARD_RE.search(value):
        weak.append("wildcard (*) source")

    if weak:
        return (
            "warning",
            f"Dangerous directive(s) present: {', '.join(weak)}",
            0.5,
        )

    return "pass", "No dangerous directives detected ✓", 1.0


def check_xcto(value: str) -> tuple[str, str, float]:
    """X-Content-Type-Options must be exactly 'nosniff' (case-insensitive)."""
    if value.strip().lower() == "nosniff":
        return "pass", "nosniff ✓", 1.0
    return "fail", f"Expected 'nosniff', got '{value}' — value is not recognised by browsers", 0.0


def check_xfo(value: str) -> tuple[str, str, float]:
    """X-Frame-Options: only DENY or SAMEORIGIN are safe values."""
    v = value.strip().upper()
    if v in _VALID_XFO_VALUES:
        return "pass", f"{v} ✓", 1.0
    # ALLOW-FROM is deprecated and broken in most browsers
    return (
        "fail",
        f"'{value}' is not a safe value — use DENY or SAMEORIGIN (or CSP frame-ancestors)",
        0.0,
    )


def check_referrer(value: str) -> tuple[str, str, float]:
    """
    Referrer-Policy: strong policies score full; leaky policies score partial.
    """
    v = value.strip().lower()
    if v in _GOOD_REFERRER_POLICIES:
        return "pass", f"'{value}' ✓", 1.0
    if v in _WEAK_REFERRER_POLICIES:
        return (
            "warning",
            f"'{value}' leaks full URL as referrer to cross-origin requests",
            0.4,
        )
    # Unknown non-empty value — give partial credit; reviewer should verify intent
    return (
        "warning",
        f"Unrecognised policy '{value}' — verify it is intentional",
        0.6,
    )


def check_permissions_policy(value: str) -> tuple[str, str, float]:
    """Permissions-Policy: any non-empty value earns full credit."""
    if value.strip():
        return "pass", "Permissions-Policy is set ✓", 1.0
    return "fail", "Header present but value is empty", 0.0


def check_coop(value: str) -> tuple[str, str, float]:
    """
    Cross-Origin-Opener-Policy.
    'same-origin' gives full isolation; other valid values give partial credit.
    """
    v = value.strip().lower()
    if v in _STRONG_COOP_VALUES:
        return "pass", f"'{value}' ✓ (full cross-origin isolation)", 1.0
    if v in _VALID_COOP_VALUES:
        return "pass", f"'{value}' ✓ (partial isolation)", 0.8
    return "warning", f"Unrecognised COOP value '{value}'", 0.4


def check_cache_control(value: str) -> tuple[str, str, float]:
    """Cache-Control: any non-empty value earns full credit."""
    if value.strip():
        return "pass", f"'{value}' ✓", 1.0
    return "fail", "Header present but value is empty", 0.0


# ---------------------------------------------------------------------------
# Header definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HeaderDefinition:
    """Metadata and validator for a single security header."""
    name: str
    weight: int
    description: str
    fix: str
    reference: str
    checker: Optional[Callable[[str], tuple[str, str, float]]]


SECURITY_HEADERS: list[HeaderDefinition] = [
    HeaderDefinition(
        name="Strict-Transport-Security",
        weight=20,
        description=(
            "Instructs browsers to always use HTTPS for future requests, "
            "preventing protocol-downgrade and cookie-hijacking attacks."
        ),
        fix="Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
        checker=check_hsts,
    ),
    HeaderDefinition(
        name="Content-Security-Policy",
        weight=25,
        description=(
            "Restricts the sources from which scripts, styles, images, and other "
            "resources may be loaded, greatly reducing XSS attack surface."
        ),
        fix="Content-Security-Policy: default-src 'self'; (then tighten per resource type)",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
        checker=check_csp,
    ),
    HeaderDefinition(
        name="X-Frame-Options",
        weight=10,
        description=(
            "Prevents the page from being embedded in an <iframe>, "
            "defending against clickjacking attacks."
        ),
        fix="X-Frame-Options: DENY  (or use CSP: frame-ancestors 'none')",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        checker=check_xfo,
    ),
    HeaderDefinition(
        name="X-Content-Type-Options",
        weight=10,
        description=(
            "Stops browsers from MIME-sniffing a response away from the declared "
            "Content-Type, preventing drive-by-download attacks."
        ),
        fix="X-Content-Type-Options: nosniff",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
        checker=check_xcto,
    ),
    HeaderDefinition(
        name="Referrer-Policy",
        weight=10,
        description=(
            "Controls how much referrer information is sent with cross-origin requests, "
            "limiting URL leakage to third parties."
        ),
        fix="Referrer-Policy: strict-origin-when-cross-origin",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
        checker=check_referrer,
    ),
    HeaderDefinition(
        name="Permissions-Policy",
        weight=10,
        description=(
            "Restricts browser feature access (camera, microphone, geolocation, etc.) "
            "for the page and its embedded iframes."
        ),
        fix="Permissions-Policy: geolocation=(), microphone=(), camera=()",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
        checker=check_permissions_policy,
    ),
    HeaderDefinition(
        name="Cross-Origin-Opener-Policy",
        weight=5,
        description=(
            "Isolates the browsing context group to prevent cross-origin attacks such as "
            "XS-Leaks and Spectre-class side-channels."
        ),
        fix="Cross-Origin-Opener-Policy: same-origin",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
        checker=check_coop,
    ),
    HeaderDefinition(
        name="Cache-Control",
        weight=10,
        description=(
            "Prevents sensitive responses from being stored in browser or proxy caches, "
            "reducing information-disclosure risk."
        ),
        fix="Cache-Control: no-store, no-cache, must-revalidate",
        reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
        checker=check_cache_control,
    ),
]

# Sanity check enforced at import time — catches any accidental weight drift.
assert sum(h.weight for h in SECURITY_HEADERS) == 100, (
    f"Header weights must sum to 100, got {sum(h.weight for h in SECURITY_HEADERS)}"
)

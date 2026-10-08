"""
tests/test_headers.py — Unit tests for checker/headers.py value validators.

All tests are pure-function tests with no network I/O.
"""

import pytest

from checker.headers import (
    SECURITY_HEADERS,
    check_hsts,
    check_csp,
    check_xcto,
    check_xfo,
    check_referrer,
    check_permissions_policy,
    check_coop,
    check_cache_control,
)


# ---------------------------------------------------------------------------
# Meta-tests: sanity checks on the header definition list
# ---------------------------------------------------------------------------

class TestHeaderDefinitions:
    def test_weights_sum_to_100(self):
        total = sum(h.weight for h in SECURITY_HEADERS)
        assert total == 100, f"Weights sum to {total}, expected 100"

    def test_all_headers_have_required_fields(self):
        for h in SECURITY_HEADERS:
            assert h.name,        f"Missing name on {h}"
            assert h.weight > 0,  f"Weight must be positive: {h.name}"
            assert h.description, f"Missing description: {h.name}"
            assert h.fix,         f"Missing fix hint: {h.name}"
            assert h.reference,   f"Missing reference URL: {h.name}"

    def test_x_xss_protection_not_present(self):
        """X-XSS-Protection is deprecated; it must not be in the scored list."""
        names = {h.name for h in SECURITY_HEADERS}
        assert "X-XSS-Protection" not in names

    def test_coop_is_present(self):
        """Cross-Origin-Opener-Policy replaces X-XSS-Protection."""
        names = {h.name for h in SECURITY_HEADERS}
        assert "Cross-Origin-Opener-Policy" in names


# ---------------------------------------------------------------------------
# check_hsts
# ---------------------------------------------------------------------------

class TestCheckHsts:
    def test_strong_hsts_full_score(self):
        status, _, fraction = check_hsts("max-age=31536000; includeSubDomains")
        assert status == "pass"
        assert fraction == 1.0

    def test_hsts_one_year_no_subdomains(self):
        """One year without includeSubDomains → pass but not full score."""
        status, _, fraction = check_hsts("max-age=31536000")
        assert status == "pass"
        assert fraction < 1.0

    def test_hsts_six_months_passes(self):
        status, _, fraction = check_hsts("max-age=15552000")
        assert status == "pass"
        assert fraction > 0.5

    def test_hsts_short_max_age_is_warning(self):
        """max-age below 6 months → warning, low score."""
        status, detail, fraction = check_hsts("max-age=86400")  # 1 day
        assert status == "warning"
        assert fraction <= 0.4
        assert "too short" in detail

    def test_hsts_missing_max_age_is_fail(self):
        status, _, fraction = check_hsts("includeSubDomains")
        assert status == "fail"
        assert fraction == 0.0

    def test_hsts_include_subdomains_is_case_insensitive(self):
        status, _, fraction = check_hsts("max-age=31536000; IncludeSubDomains")
        assert status == "pass"
        assert fraction == 1.0


# ---------------------------------------------------------------------------
# check_csp
# ---------------------------------------------------------------------------

class TestCheckCsp:
    def test_clean_csp_passes(self):
        status, _, fraction = check_csp("default-src 'self'; script-src 'self'")
        assert status == "pass"
        assert fraction == 1.0

    def test_unsafe_inline_is_warning(self):
        status, detail, fraction = check_csp("default-src 'self'; script-src 'unsafe-inline'")
        assert status == "warning"
        assert "'unsafe-inline'" in detail
        assert fraction < 1.0

    def test_unsafe_eval_is_warning(self):
        status, detail, fraction = check_csp("default-src 'unsafe-eval'")
        assert status == "warning"
        assert "'unsafe-eval'" in detail
        assert fraction < 1.0

    def test_wildcard_source_is_warning(self):
        status, detail, fraction = check_csp("default-src *")
        assert status == "warning"
        assert "wildcard" in detail.lower()

    def test_subdomain_wildcard_does_not_trigger_warning(self):
        """https://*.example.com should NOT be flagged as a bare wildcard."""
        status, _, fraction = check_csp(
            "default-src 'self'; img-src https://*.example.com"
        )
        assert status == "pass"

    def test_multiple_weak_directives_all_listed(self):
        status, detail, _ = check_csp(
            "default-src 'unsafe-inline' 'unsafe-eval'"
        )
        assert "'unsafe-inline'" in detail
        assert "'unsafe-eval'" in detail


# ---------------------------------------------------------------------------
# check_xcto
# ---------------------------------------------------------------------------

class TestCheckXcto:
    def test_nosniff_passes(self):
        status, _, fraction = check_xcto("nosniff")
        assert status == "pass"
        assert fraction == 1.0

    def test_nosniff_case_insensitive(self):
        status, _, fraction = check_xcto("NOSNIFF")
        assert status == "pass"

    def test_wrong_value_fails(self):
        status, _, fraction = check_xcto("true")
        assert status == "fail"
        assert fraction == 0.0

    def test_empty_value_fails(self):
        status, _, fraction = check_xcto("")
        assert status == "fail"


# ---------------------------------------------------------------------------
# check_xfo
# ---------------------------------------------------------------------------

class TestCheckXfo:
    def test_deny_passes(self):
        status, _, fraction = check_xfo("DENY")
        assert status == "pass"
        assert fraction == 1.0

    def test_sameorigin_passes(self):
        status, _, fraction = check_xfo("SAMEORIGIN")
        assert status == "pass"

    def test_allow_from_fails(self):
        """ALLOW-FROM is deprecated and broken; must fail."""
        status, _, fraction = check_xfo("ALLOW-FROM https://example.com")
        assert status == "fail"
        assert fraction == 0.0

    def test_arbitrary_value_fails(self):
        status, _, fraction = check_xfo("ALLOW")
        assert status == "fail"


# ---------------------------------------------------------------------------
# check_referrer
# ---------------------------------------------------------------------------

class TestCheckReferrer:
    @pytest.mark.parametrize("policy", [
        "no-referrer",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
    ])
    def test_good_policies_pass(self, policy):
        status, _, fraction = check_referrer(policy)
        assert status == "pass"
        assert fraction == 1.0

    def test_unsafe_url_is_warning(self):
        status, detail, fraction = check_referrer("unsafe-url")
        assert status == "warning"
        assert fraction < 1.0
        assert "leaks" in detail.lower()

    def test_no_referrer_when_downgrade_is_warning(self):
        status, _, fraction = check_referrer("no-referrer-when-downgrade")
        assert status == "warning"
        assert fraction < 1.0


# ---------------------------------------------------------------------------
# check_coop
# ---------------------------------------------------------------------------

class TestCheckCoop:
    def test_same_origin_full_score(self):
        status, _, fraction = check_coop("same-origin")
        assert status == "pass"
        assert fraction == 1.0

    def test_same_origin_allow_popups_partial(self):
        status, _, fraction = check_coop("same-origin-allow-popups")
        assert status == "pass"
        assert fraction < 1.0

    def test_unknown_value_warning(self):
        status, _, fraction = check_coop("unknown-value")
        assert status == "warning"

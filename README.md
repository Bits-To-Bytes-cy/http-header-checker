# http-header-checker

[![Tests](https://github.com/Bits-To-Bytes-cy/http-header-checker/actions/workflows/tests.yml/badge.svg)](https://github.com/Bits-To-Bytes-cy/http-header-checker/actions/workflows/tests.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A command-line tool that fetches a URL's HTTP response headers, scores them against 8 modern security best practices (0–100 points), and produces a colour-coded **Pass / Warning / Fail** report with one-line fixes for every finding.

> **Ethical use**: Scanning HTTP headers is a normal read-only request, but please only scan sites you own or have explicit permission to test.

---

## Features

| Feature | Detail |
|---|---|
| **8 security headers checked** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, Cache-Control |
| **Value-quality scoring** | Partial credit for weak-but-present headers (short HSTS max-age, `unsafe-inline` CSP, etc.) |
| **Pass / Warning / Fail** | Each finding is labelled with severity and a one-line fix |
| **Information-leak detection** | Warns if `Server` or `X-Powered-By` reveals a software version |
| **Cookie-flag analysis** | Checks `Set-Cookie` for `Secure`, `HttpOnly`, `SameSite` |
| **HTTP vs HTTPS detection** | Notes if HSTS cannot apply and whether the site redirects to HTTPS |
| **JSON output** | `--json` or `--output report.json` for pipeline integration |
| **CI exit code** | `--fail-under N` returns exit code 1 if score drops below N |
| **Multi-URL support** | Scan several targets in one command |

---

## Installation

**Requirements:** Python 3.9 or newer.

```bash
# 1. Clone the repository
git clone https://github.com/Bits-To-Bytes-cy/http-header-checker.git
cd http-header-checker

# 2. (Recommended) Create a virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

```
python header_checker.py [URL ...] [options]

positional arguments:
  URL                   One or more target URLs to scan

options:
  --json                Print results as JSON to stdout
  --output FILE         Write JSON results to FILE
  --timeout SECONDS     Request timeout (default: 10)
  --fail-under N        Exit code 1 if score < N  (CI use)
  --no-colour           Disable ANSI colours
  -h, --help            Show this help message
```

### Examples

```bash
# Basic scan
python header_checker.py https://example.com

# Scan two URLs at once
python header_checker.py https://example.com https://another.com

# Save a JSON report
python header_checker.py https://example.com --output report.json

# CI pipeline — fail the build if score is below 80
python header_checker.py https://example.com --fail-under 80

# Plain-text output (no colour) for log files
python header_checker.py https://example.com --no-colour

# Custom timeout for slow sites
python header_checker.py https://example.com --timeout 20
```

---

## Sample Output

```
──────────────────── HTTP Security Header Report ────────────────────
  URL:       https://example.com
  Status:    HTTP 200
  Scanned:   2026-10-08T09:15:42+00:00
  Elapsed:   134 ms

  Score: 35/100   Grade: F   ██████░░░░░░░░░░░░░░░░░░░░░░

╭──────────────────────── Security Header Assessment ────────────────────────╮
│   Header                        Score   Severity   Finding         Fix     │
├─────────────────────────────────────────────────────────────────────────────┤
│ ✔  Strict-Transport-Security    20/20   PASS       max-age=...            │
│ ✖  Content-Security-Policy       0/25   FAIL       Header is absent  ...  │
│ ✔  X-Frame-Options              10/10   PASS       DENY ✓                 │
│ ✔  X-Content-Type-Options       10/10   PASS       nosniff ✓              │
│ ✖  Referrer-Policy               0/10   FAIL       Header is absent  ...  │
│ ✖  Permissions-Policy            0/10   FAIL       Header is absent  ...  │
│ ✖  Cross-Origin-Opener-Policy    0/5    FAIL       Header is absent  ...  │
│ ✖  Cache-Control                 0/10   FAIL       Header is absent  ...  │
╰─────────────────────────────────────────────────────────────────────────────╯

⚠  Information Disclosure (not included in score)
      •  Server: 'ECS (nyb/1D2E)' — discloses server technology (consider removing)

────────────────────────────────────────────────────────────────────
Disclaimer: For authorised testing only. Use only on sites you own or
have explicit permission to test.
```

---

## Scoring Methodology

| Header | Max pts | What earns full credit |
|---|---|---|
| `Strict-Transport-Security` | 20 | `max-age` ≥ 1 year + `includeSubDomains` |
| `Content-Security-Policy` | 25 | No `unsafe-inline`, `unsafe-eval`, or `*` |
| `X-Frame-Options` | 10 | `DENY` or `SAMEORIGIN` |
| `X-Content-Type-Options` | 10 | Exactly `nosniff` |
| `Referrer-Policy` | 10 | `strict-origin-when-cross-origin` or stricter |
| `Permissions-Policy` | 10 | Any non-empty value |
| `Cross-Origin-Opener-Policy` | 5 | `same-origin` |
| `Cache-Control` | 10 | Any non-empty value |

### Grade scale

| Score | Grade |
|---|---|
| 90–100 | A |
| 75–89 | B |
| 60–74 | C |
| 40–59 | D |
| 0–39 | F |

Headers that are present but have **weak values** earn partial credit (Warning).  
Missing headers earn 0 pts (Fail).

> **Note**: `X-XSS-Protection` is intentionally excluded — it is deprecated, and modern guidance advises disabling it or relying on CSP instead.

---

## Running Tests

```bash
pytest tests/ -v
```

The test suite makes **no real network requests** — all HTTP calls are mocked via `unittest.mock`.

---

## Project Structure

```
http-header-checker/
├── header_checker.py        # CLI entry point (argparse)
├── checker/
│   ├── headers.py           # Header definitions, weights, value validators
│   ├── scanner.py           # HTTP fetch + analysis logic
│   └── reporter.py          # Rich console + JSON output
├── tests/
│   ├── test_headers.py      # Validator unit tests
│   ├── test_scanner.py      # Scan logic (mocked HTTP)
│   └── test_reporter.py     # Output formatting tests
├── .github/workflows/
│   └── tests.yml            # GitHub Actions CI (Python 3.9 / 3.11 / 3.12)
├── requirements.txt
├── .gitignore
├── LICENSE                  # MIT
└── README.md
```

---

## Limitations

- **Single-response analysis only.** The tool checks headers on the initial response to the supplied URL. Other pages on the same site may have different header configurations.
- **No JavaScript execution.** Headers set via `<meta>` tags or JavaScript are not detected.
- **No CSP deep-analysis.** The tool flags obviously dangerous CSP directives but does not fully parse and evaluate the entire policy.
- **Cookies from subsequent requests are not checked.** Only cookies set in the scanned response are analysed.
- **SSL errors on self-signed certificates.** The tool verifies certificates by default. Use `http://` or fix the certificate for self-hosted test environments.

---

## Ethical Use

> **Disclaimer: For authorised testing only.**  
> Scanning HTTP headers is a standard, read-only operation, but you must only run this tool against sites you own or have explicit written permission to assess. Unauthorised scanning may violate computer-misuse laws in your jurisdiction.

---

## Licence

MIT — see [LICENSE](LICENSE).

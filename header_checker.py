#!/usr/bin/env python3
"""
http-header-checker — HTTP Security Header Scanner
===================================================
Checks a URL's HTTP response headers against modern security best practices
and produces a scored, colour-coded report with Pass / Warning / Fail ratings.

Disclaimer: For authorised testing only.
Use only on sites you own or have explicit permission to test.

Usage examples
--------------
  python header_checker.py https://example.com
  python header_checker.py https://example.com https://another.com
  python header_checker.py https://example.com --json
  python header_checker.py https://example.com --output report.json
  python header_checker.py https://example.com --fail-under 80
  python header_checker.py https://example.com --timeout 15 --no-colour
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console

from checker.scanner import scan
from checker.reporter import console_report, to_dict


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="header_checker",
        description=(
            "HTTP Security Header Checker\n"
            "--------------------------------------\n"
            "Scores a URL against 8 modern security headers (0-100 points)\n"
            "with Pass / Warning / Fail ratings and fix hints for each finding.\n\n"
            "Disclaimer: For authorised testing only.\n"
            "Use only on sites you own or have explicit permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s https://example.com
  %(prog)s https://example.com --json
  %(prog)s https://a.com https://b.com --fail-under 70
  %(prog)s https://example.com --output report.json
  %(prog)s http://example.com --timeout 15 --no-colour
        """,
    )

    parser.add_argument(
        "urls",
        nargs="+",
        metavar="URL",
        help="One or more target URLs to scan (e.g. https://example.com)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_stdout",
        help="Print results as JSON to stdout instead of the formatted report",
    )
    parser.add_argument(
        "--output",
        metavar="FILE",
        help=(
            "Write JSON results to FILE "
            "(compatible with --json; can be used alongside console output)"
        ),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--fail-under",
        type=int,
        default=None,
        metavar="N",
        dest="fail_under",
        help=(
            "Exit with code 1 if the lowest score across all scanned URLs "
            "is below N. Useful in CI pipelines."
        ),
    )
    parser.add_argument(
        "--no-colour",
        action="store_true",
        dest="no_colour",
        help="Disable ANSI colour output (for piping or terminals without colour support)",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    console = Console(no_color=args.no_colour, stderr=False)
    results = []

    for url in args.urls:
        console.print(f"[dim]→ Scanning {url} …[/dim]")
        result = scan(url, timeout=args.timeout)
        results.append(result)

        # Always print the console report unless --json is the only output
        if not args.json_stdout:
            console_report(result, console=console)

    # ── JSON to stdout ───────────────────────────────────────────────────────
    if args.json_stdout:
        output = [to_dict(r) for r in results]
        payload = output[0] if len(output) == 1 else output
        print(json.dumps(payload, indent=2, ensure_ascii=False))

    # ── JSON to file ─────────────────────────────────────────────────────────
    if args.output:
        output = [to_dict(r) for r in results]
        payload = output[0] if len(output) == 1 else output
        Path(args.output).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        console.print(f"[dim]JSON report written → {args.output}[/dim]")

    # ── --fail-under exit code ───────────────────────────────────────────────
    if args.fail_under is not None:
        min_score = min(r.score for r in results)
        if min_score < args.fail_under:
            console.print(
                f"[bold red]✖  Score {min_score} is below threshold "
                f"--fail-under {args.fail_under}  (exit code 1)[/bold red]"
            )
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

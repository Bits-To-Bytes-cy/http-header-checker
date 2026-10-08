"""
checker/reporter.py — Output formatting for http-header-checker.

Provides:
  console_report(result, console)  — rich, colour-coded terminal report
  json_report(result)              — JSON string serialisation
  to_dict(result)                  — dict for further processing / file output
"""

from __future__ import annotations

import json
import math
from dataclasses import asdict
from typing import Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .scanner import ScanResult, HeaderFinding

# ---------------------------------------------------------------------------
# Style mappings
# ---------------------------------------------------------------------------

_STATUS_COLOUR = {"pass": "green", "warning": "yellow", "fail": "red"}
_STATUS_ICON   = {"pass": "✔", "warning": "⚠", "fail": "✖"}

_GRADE_STYLE = {
    "A": "bold bright_green",
    "B": "green",
    "C": "yellow",
    "D": "dark_orange",
    "F": "bold red",
}

_DISCLAIMER = (
    "Disclaimer: For authorised testing only. "
    "Use only on sites you own or have explicit permission to test."
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _score_bar(score: int, width: int = 28) -> Text:
    """Build a coloured Unicode progress bar reflecting the score."""
    filled = round(score / 100 * width)
    bar = "█" * filled + "░" * (width - filled)
    if score >= 75:
        colour = "green"
    elif score >= 50:
        colour = "yellow"
    else:
        colour = "red"
    return Text(bar, style=colour)


def _points_str(finding: HeaderFinding) -> str:
    """Format earned/max points for table display."""
    earned = math.floor(finding.points_earned)  # display as integer
    return f"{earned}/{finding.points_max}"


# ---------------------------------------------------------------------------
# Console report
# ---------------------------------------------------------------------------

def console_report(result: ScanResult, console: Optional[Console] = None) -> None:
    """
    Print a rich, colour-coded security report to the terminal.

    Args:
        result:  ScanResult to render.
        console: Optional Rich Console; a default one is created if None.
    """
    if console is None:
        console = Console()

    console.print()

    # ── Error case ──────────────────────────────────────────────────────────
    if result.error:
        console.print(
            Panel(
                f"[bold red]SCAN FAILED[/bold red]\n\n{result.error}",
                title=f"[dim]{result.url}[/dim]",
                border_style="red",
                expand=False,
            )
        )
        console.print(f"[dim]{_DISCLAIMER}[/dim]\n")
        return

    # ── Header banner ────────────────────────────────────────────────────────
    console.rule("[bold cyan]HTTP Security Header Report[/bold cyan]")
    console.print(f"  [bold]URL:[/bold]       {result.url}")
    if result.final_url != result.url:
        console.print(f"  [bold]Final URL:[/bold] {result.final_url}")
    console.print(f"  [bold]Status:[/bold]    HTTP {result.status_code}")
    console.print(f"  [bold]Scanned:[/bold]   {result.timestamp}")
    console.print(f"  [bold]Elapsed:[/bold]   {result.elapsed_ms} ms")
    console.print()

    # ── Score / grade ────────────────────────────────────────────────────────
    grade_style = _GRADE_STYLE.get(result.grade, "white")
    bar = _score_bar(result.score)
    console.print(
        f"  [bold]Score:[/bold] [bold]{result.score}/100[/bold]   "
        f"[bold]Grade:[/bold] [{grade_style}]{result.grade}[/{grade_style}]   "
        + str(bar)
    )
    console.print()

    # ── HTTP / HSTS note ─────────────────────────────────────────────────────
    if result.hsts_note:
        console.print(f"  [yellow]⚠  {result.hsts_note}[/yellow]")
        console.print()

    # ── Header findings table ────────────────────────────────────────────────
    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on grey23",
        title="[bold]Security Header Assessment[/bold]",
        expand=True,
        show_lines=False,
        padding=(0, 1),
    )
    table.add_column("",       width=3,  justify="center", no_wrap=True)   # icon
    table.add_column("Header", style="cyan bold", ratio=3, no_wrap=False)
    table.add_column("Score",  width=8,  justify="right")
    table.add_column("Severity", width=9, justify="center")
    table.add_column("Finding", ratio=4)
    table.add_column("Fix",    ratio=5, style="dim")

    for f in result.header_findings:
        colour = _STATUS_COLOUR[f.status]
        icon   = _STATUS_ICON[f.status]
        table.add_row(
            f"[{colour}]{icon}[/{colour}]",
            f.name,
            f"[{colour}]{_points_str(f)}[/{colour}]",
            f"[{colour}]{f.status.upper()}[/{colour}]",
            f"[{colour}]{f.detail}[/{colour}]",
            f.fix if f.status != "pass" else "",
        )

    console.print(table)
    console.print()

    # ── Information-disclosure findings ──────────────────────────────────────
    if result.info_leaks:
        console.print(
            "[bold yellow]⚠  Information Disclosure[/bold yellow]  "
            "[dim](not included in score)[/dim]"
        )
        for leak in result.info_leaks:
            console.print(f"   [yellow]  •  {leak}[/yellow]")
        console.print()

    # ── Cookie security ──────────────────────────────────────────────────────
    if result.cookie_issues:
        console.print(
            "[bold yellow]⚠  Cookie Security Issues[/bold yellow]  "
            "[dim](not included in score)[/dim]"
        )
        for issue in result.cookie_issues:
            console.print(f"   [yellow]  •  {issue}[/yellow]")
        console.print()

    # ── Disclaimer ───────────────────────────────────────────────────────────
    console.rule()
    console.print(f"[dim]{_DISCLAIMER}[/dim]")
    console.print()


# ---------------------------------------------------------------------------
# JSON serialisation
# ---------------------------------------------------------------------------

def to_dict(result: ScanResult) -> dict:
    """
    Convert a ScanResult to a JSON-serialisable dictionary.

    Points are rounded to integers for a cleaner output.
    """
    d = asdict(result)
    for finding in d.get("header_findings", []):
        finding["points_earned"] = round(finding["points_earned"])
    return d


def json_report(result: ScanResult) -> str:
    """Serialise a ScanResult to a formatted JSON string."""
    return json.dumps(to_dict(result), indent=2, ensure_ascii=False)

"""
Batch Password Auditor
=======================
Processes multiple passwords from TXT or CSV files with progress tracking,
summary statistics, and consolidated reporting.
"""

import csv
import sys
import time
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.table import Table
from rich import box

from core.analyzer import audit_password, AuditResult

console = Console()


@dataclass
class BatchEntry:
    """A single entry in a batch audit."""
    label: str               # Username or label
    password: str            # The password (never stored in reports if anonymized)
    result: Optional[AuditResult] = None
    error: Optional[str] = None


@dataclass
class BatchResult:
    """Consolidated batch audit results."""
    entries: List[BatchEntry]
    total_count: int
    passed_count: int        # Score >= 70
    failed_count: int        # Score < 70
    critical_count: int      # Score < 40
    average_score: float
    weakest_entry: Optional[BatchEntry]
    strongest_entry: Optional[BatchEntry]
    duration_seconds: float


def load_passwords_from_file(filepath: str) -> List[BatchEntry]:
    """
    Load passwords from a TXT or CSV file.

    TXT format: one password per line
    CSV format: label,password (with or without header)
    """
    path = Path(filepath)
    entries: List[BatchEntry] = []

    if not path.exists():
        console.print(f"[bold red]Error: File not found: {filepath}[/]")
        return entries

    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        console.print(f"[bold red]Error reading file: {e}[/]")
        return entries

    lines = [line.strip() for line in content.splitlines() if line.strip()]

    if path.suffix.lower() == '.csv':
        # CSV mode: try to detect header
        try:
            reader = csv.reader(lines)
            rows = list(reader)
            if not rows:
                return entries

            # Check if first row looks like a header
            start_idx = 0
            if rows[0][0].lower() in ('label', 'username', 'user', 'name', 'account', 'id'):
                start_idx = 1

            for i in range(start_idx, len(rows)):
                row = rows[i]
                if len(row) >= 2:
                    entries.append(BatchEntry(label=row[0], password=row[1]))
                elif len(row) == 1:
                    entries.append(BatchEntry(label=f"Entry {i + 1}", password=row[0]))
        except Exception:
            # Fallback to line-by-line
            for i, line in enumerate(lines):
                entries.append(BatchEntry(label=f"Entry {i + 1}", password=line))
    else:
        # TXT mode: one password per line
        for i, line in enumerate(lines):
            entries.append(BatchEntry(label=f"Password {i + 1}", password=line))

    return entries


def run_batch_audit(
    filepath: str,
    check_breaches: bool = True,
    max_passwords: int = 100,
) -> Optional[BatchResult]:
    """
    Run batch password audit with progress tracking.

    Args:
        filepath: Path to TXT or CSV file
        check_breaches: Whether to check HIBP for each password
        max_passwords: Maximum passwords to process (safety limit)

    Returns:
        BatchResult with all audit results and statistics
    """
    entries = load_passwords_from_file(filepath)

    if not entries:
        console.print("[bold red]No passwords found in file.[/]")
        return None

    # Safety limit
    if len(entries) > max_passwords:
        console.print(f"[yellow]⚠️ File contains {len(entries)} passwords. "
                      f"Processing first {max_passwords} (use --max to increase).[/]")
        entries = entries[:max_passwords]

    console.print(f"\n[bold cyan]📋 Batch Audit: {len(entries)} passwords to analyze[/]\n")

    start_time = time.time()

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, style="cyan", complete_style="bright_green"),
        TextColumn("[bold green]{task.percentage:>3.0f}%"),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Auditing passwords...", total=len(entries))

        for entry in entries:
            progress.update(task, description=f"Auditing: {entry.label}")
            try:
                entry.result = audit_password(entry.password, check_breaches=check_breaches)
            except Exception as e:
                entry.error = str(e)
            progress.advance(task)

    duration = time.time() - start_time

    # Calculate statistics
    scored_entries = [e for e in entries if e.result is not None]
    scores = [e.result.strength.final_score for e in scored_entries]

    passed = sum(1 for s in scores if s >= 70)
    failed = sum(1 for s in scores if s < 70)
    critical = sum(1 for s in scores if s < 40)
    avg_score = sum(scores) / len(scores) if scores else 0

    weakest = min(scored_entries, key=lambda e: e.result.strength.final_score) if scored_entries else None
    strongest = max(scored_entries, key=lambda e: e.result.strength.final_score) if scored_entries else None

    batch_result = BatchResult(
        entries=entries,
        total_count=len(entries),
        passed_count=passed,
        failed_count=failed,
        critical_count=critical,
        average_score=round(avg_score, 1),
        weakest_entry=weakest,
        strongest_entry=strongest,
        duration_seconds=round(duration, 2),
    )

    # Display summary
    display_batch_summary(batch_result)
    display_batch_details(batch_result)

    return batch_result


def display_batch_summary(result: BatchResult):
    """Display batch audit summary statistics."""
    console.print()

    # Summary cards
    cards = []
    cards.append(Panel(
        f"[bold bright_white]{result.total_count}[/]\n[dim]Total[/]",
        title="📊", border_style="cyan", width=14,
    ))
    cards.append(Panel(
        f"[bold bright_green]{result.passed_count}[/]\n[dim]Passed[/]",
        title="✅", border_style="green", width=14,
    ))
    cards.append(Panel(
        f"[bold yellow]{result.failed_count}[/]\n[dim]Failed[/]",
        title="⚠️", border_style="yellow", width=14,
    ))
    cards.append(Panel(
        f"[bold bright_red]{result.critical_count}[/]\n[dim]Critical[/]",
        title="🚨", border_style="red", width=14,
    ))
    cards.append(Panel(
        f"[bold bright_cyan]{result.average_score}[/]\n[dim]Avg Score[/]",
        title="📈", border_style="cyan", width=14,
    ))

    from rich.columns import Columns
    console.print(Columns(cards, equal=True, expand=True))
    console.print()


def display_batch_details(result: BatchResult):
    """Display detailed per-password results table."""
    table = Table(
        title="Batch Audit Results",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_cyan",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Label", style="bold white", min_width=15)
    table.add_column("Score", min_width=8)
    table.add_column("Grade", min_width=6)
    table.add_column("Risk", min_width=10)
    table.add_column("Breached", min_width=10)
    table.add_column("Patterns", min_width=8)
    table.add_column("Length", style="dim", min_width=6)

    grade_styles = {
        "A+": "bright_green", "A": "green", "B": "cyan",
        "C": "yellow", "D": "rgb(255,150,50)", "F": "bright_red",
    }
    risk_styles = {
        "CRITICAL": "bright_red", "HIGH": "red", "MEDIUM": "yellow",
        "LOW": "cyan", "MODERATE": "blue", "SECURE": "bright_green",
    }

    for i, entry in enumerate(result.entries, 1):
        if entry.result:
            r = entry.result
            gs = grade_styles.get(r.strength.grade, "white")
            rs = risk_styles.get(r.risk_rating, "white")
            breach_str = f"[bright_red]YES ({r.breach.breach_count:,})[/]" if r.breach.breached else "[green]No[/]"
            table.add_row(
                str(i), entry.label,
                f"[{gs}]{r.strength.final_score}[/]",
                f"[{gs}]{r.strength.grade}[/]",
                f"[{rs}]{r.risk_rating}[/]",
                breach_str,
                str(len(r.patterns)),
                str(r.password_length),
            )
        else:
            table.add_row(str(i), entry.label, "[red]ERR[/]", "-", "-", "-", "-", "-")

    console.print(table)
    console.print(f"\n[dim]  ⏱️ Completed in {result.duration_seconds}s[/]\n")

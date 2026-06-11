"""
Interactive Rich Terminal Dashboard
====================================
Premium terminal UI using the Rich library for the Password Auditor.
Features colored panels, progress bars, tables, gauge meters,
and a polished cybersecurity aesthetic.
"""

import sys
import getpass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.layout import Layout
from rich.align import Align
from rich import box
import time

from config import APP_BANNER, THEME, SEVERITY_COLORS
from core.analyzer import audit_password, AuditResult

console = Console()

# ─── Color helpers ────────────────────────────────────────────────────────────
GRADE_STYLES = {
    "A+": "bold bright_green", "A": "bold green", "B": "bold cyan",
    "C": "bold yellow", "D": "bold rgb(255,150,50)", "F": "bold bright_red",
}

RISK_STYLES = {
    "CRITICAL": "bold bright_red", "HIGH": "bold red",
    "MEDIUM": "bold yellow", "LOW": "bold cyan",
    "MODERATE": "bold blue", "SECURE": "bold bright_green",
}

SEVERITY_STYLE = {
    "CRITICAL": "bright_red", "HIGH": "red",
    "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim",
}

HASH_SECURITY_STYLE = {
    "BROKEN": "bright_red", "WEAK": "yellow",
    "ACCEPTABLE": "cyan", "RECOMMENDED": "bright_green",
}


def display_banner():
    """Display the animated ASCII art banner."""
    console.print(APP_BANNER, style="bold cyan")
    console.print()


def get_password_input() -> str:
    """Securely get password input from user."""
    console.print("[bold cyan]┌─ Password Input ─────────────────────────────────────┐[/]")
    console.print("[bold cyan]│[/] Enter the password to audit (input is hidden):")
    console.print("[bold cyan]│[/]")
    password = getpass.getpass(prompt="│ 🔐 Password: ")
    console.print("[bold cyan]└──────────────────────────────────────────────────────┘[/]")
    console.print()
    return password


def run_analysis_with_progress(password: str, check_breaches: bool = True) -> AuditResult:
    """Run analysis with a visual progress display."""
    phases = [
        ("Calculating entropy...", 0.1),
        ("Detecting patterns...", 0.15),
        ("Checking breach databases...", 0.3 if check_breaches else 0.05),
        ("Analyzing hash security...", 0.1),
        ("Checking policy compliance...", 0.1),
        ("Estimating crack times...", 0.1),
        ("Computing strength score...", 0.1),
        ("Generating recommendations...", 0.05),
    ]

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30, style="cyan", complete_style="bright_green"),
        TextColumn("[bold green]{task.percentage:>3.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Analyzing password...", total=len(phases))
        for description, delay in phases:
            progress.update(task, description=description)
            time.sleep(delay)
            progress.advance(task)

    console.print()
    return audit_password(password, check_breaches=check_breaches)


def display_score_header(result: AuditResult):
    """Display the main score and grade header."""
    grade = result.strength.grade
    grade_label = result.strength.grade_label
    score = result.strength.final_score
    style = GRADE_STYLES.get(grade, "white")
    risk_style = RISK_STYLES.get(result.risk_rating, "white")

    # Build score bar
    filled = int(score / 2)  # 50 char width
    empty = 50 - filled
    if score >= 85:
        bar_color = "green"
    elif score >= 70:
        bar_color = "cyan"
    elif score >= 55:
        bar_color = "yellow"
    elif score >= 40:
        bar_color = "rgb(255,150,50)"
    else:
        bar_color = "red"

    bar = f"[{bar_color}]{'█' * filled}[/][dim]{'░' * empty}[/]"

    content = (
        f"\n  [bold white]Score:[/] [{style}]{score}/100[/]  "
        f"│  [bold white]Grade:[/] [{style}]{grade} ({grade_label})[/]  "
        f"│  [bold white]Risk:[/] [{risk_style}]{result.risk_rating}[/]\n\n"
        f"  {bar}  {score}%\n"
    )

    console.print(Panel(
        Align.left(content),
        title="[bold bright_white]🔐 PASSWORD STRENGTH ASSESSMENT[/]",
        subtitle=f"[dim]Password: {result.password_masked}  │  Length: {result.password_length} chars[/]",
        border_style="cyan",
        box=box.DOUBLE,
        padding=(0, 1),
    ))


def display_score_breakdown(result: AuditResult):
    """Display itemized score breakdown."""
    s = result.strength
    table = Table(
        title="Score Breakdown",
        box=box.ROUNDED,
        border_style="cyan",
        show_header=True,
        header_style="bold bright_cyan",
    )
    table.add_column("Component", style="bold white", min_width=20)
    table.add_column("Points", justify="right", min_width=10)
    table.add_column("Max", justify="right", style="dim", min_width=8)
    table.add_column("Bar", min_width=15)

    components = [
        ("📏 Length", s.length_score, 25),
        ("🔤 Diversity", s.diversity_score, 20),
        ("🎲 Entropy Bonus", s.entropy_bonus, 20),
        ("📋 Policy Bonus", s.policy_bonus, 15),
    ]

    for name, pts, max_pts in components:
        ratio = pts / max_pts if max_pts > 0 else 0
        bar_len = int(ratio * 10)
        color = "green" if ratio >= 0.7 else ("yellow" if ratio >= 0.4 else "red")
        bar = f"[{color}]{'█' * bar_len}[/][dim]{'░' * (10 - bar_len)}[/]"
        pts_style = f"[{color}]+{pts:.0f}[/{color}]"
        table.add_row(name, pts_style, str(max_pts), bar)

    # Penalties
    if s.pattern_penalty < 0:
        table.add_row("⚠️ Pattern Penalty", f"[red]{s.pattern_penalty:.0f}[/]", "-30", "")
    if s.breach_penalty < 0:
        table.add_row("🚨 Breach Penalty", f"[bright_red]{s.breach_penalty:.0f}[/]", "-40", "")

    table.add_section()
    total_style = GRADE_STYLES.get(s.grade, "white")
    table.add_row(f"[bold]TOTAL SCORE[/]", f"[{total_style}]{s.final_score}[/]", "100", "")

    console.print(table)
    console.print()


def display_entropy(result: AuditResult):
    """Display entropy analysis results."""
    e = result.entropy
    table = Table(
        title="🎲 Entropy Analysis",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_cyan",
    )
    table.add_column("Metric", style="bold white", min_width=25)
    table.add_column("Value", style="bright_white", min_width=20)
    table.add_column("Notes", style="dim", min_width=30)

    table.add_row("Shannon Entropy", f"{e.shannon_entropy:.4f} bits/char", "Randomness per character")
    table.add_row("Effective Entropy", f"{e.effective_entropy:.2f} bits", "Total keyspace entropy")
    table.add_row("Ideal Entropy", f"{e.ideal_entropy:.2f} bits", "Max possible for this length")
    table.add_row("Total Shannon Bits", f"{e.total_shannon_bits:.2f} bits", "Shannon × length")
    table.add_row("Unique Characters", f"{e.unique_characters}/{e.password_length}", f"Compression ratio: {e.compression_ratio:.2%}")

    rating_style = "green" if "Strong" in e.entropy_rating else ("yellow" if "Moderate" in e.entropy_rating or "Fair" in e.entropy_rating else "red")
    table.add_row("Entropy Rating", f"[{rating_style}]{e.entropy_rating}[/]", e.entropy_description)

    # Charset breakdown
    charset_parts = [f"[green]✓[/] {k}" if v else f"[red]✗[/] {k}" for k, v in e.charset_info.category_details.items()]
    table.add_row("Character Classes", f"{e.charset_info.categories_used} of 6", " │ ".join(charset_parts[:3]))
    if len(charset_parts) > 3:
        table.add_row("", "", " │ ".join(charset_parts[3:]))
    table.add_row("Character Pool Size", str(e.charset_info.pool_size), "Possible characters per position")

    console.print(table)
    console.print()


def display_patterns(result: AuditResult):
    """Display detected patterns."""
    patterns = result.patterns
    if not patterns:
        console.print(Panel(
            "[bold bright_green]✅ No pattern weaknesses detected![/]",
            title="🔍 Pattern Analysis",
            border_style="green",
            box=box.ROUNDED,
        ))
        console.print()
        return

    table = Table(
        title="🔍 Pattern Weaknesses Detected",
        box=box.ROUNDED,
        border_style="yellow",
        header_style="bold bright_cyan",
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", min_width=10)
    table.add_column("Pattern Type", style="bold white", min_width=20)
    table.add_column("Description", min_width=40)
    table.add_column("Position", style="dim", min_width=12)

    for i, p in enumerate(patterns, 1):
        sev_style = SEVERITY_STYLE.get(p.severity, "white")
        table.add_row(
            str(i),
            f"[{sev_style}]{p.severity}[/]",
            p.pattern_type,
            p.description,
            p.position,
        )

    console.print(table)
    console.print()


def display_breach_status(result: AuditResult):
    """Display breach check results."""
    b = result.breach
    if b.breached:
        content = (
            f"[bold bright_red]⚠️  PASSWORD COMPROMISED  ⚠️[/]\n\n"
            f"  Found [bold bright_red]{b.breach_count:,}[/] times in data breach databases.\n"
            f"  This password is known to attackers and must be changed immediately.\n"
            f"  Source: Have I Been Pwned (k-anonymity model — your password was NOT transmitted)"
        )
        console.print(Panel(content, title="🚨 Breach Database Check", border_style="bright_red", box=box.DOUBLE))
    elif b.checked:
        content = (
            f"[bold bright_green]✅  PASSWORD NOT FOUND IN BREACHES  ✅[/]\n\n"
            f"  This password was not found in any known breach databases.\n"
            f"  Note: This doesn't guarantee absolute safety.\n"
            f"  Source: Have I Been Pwned (k-anonymity model — privacy preserved)"
        )
        console.print(Panel(content, title="✅ Breach Database Check", border_style="green", box=box.ROUNDED))
    else:
        content = f"[dim]{b.description}[/]"
        console.print(Panel(content, title="ℹ️ Breach Database Check", border_style="dim", box=box.ROUNDED))

    console.print()


def display_crack_times(result: AuditResult):
    """Display crack time estimates."""
    table = Table(
        title="⏱️ Crack Time Estimation",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_cyan",
    )
    table.add_column("Icon", width=3)
    table.add_column("Attack Scenario", style="bold white", min_width=28)
    table.add_column("Speed", style="dim", min_width=18)
    table.add_column("Time to Crack", min_width=18)
    table.add_column("Risk", min_width=10)

    for est in result.crack_time.estimates:
        sev_style = SEVERITY_STYLE.get(est.severity, "white")
        speed_str = f"{est.speed:,.0f}/sec" if est.speed >= 1 else f"{est.speed * 3600:.0f}/hour"
        table.add_row(
            est.icon,
            est.scenario_name,
            speed_str,
            f"[{sev_style}]{est.human_readable}[/]",
            f"[{sev_style}]{est.severity}[/]",
        )

    console.print(table)
    console.print()


def display_policy_compliance(result: AuditResult):
    """Display policy compliance matrix."""
    table = Table(
        title="📋 Policy Compliance Matrix",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_cyan",
    )
    table.add_column("Standard", style="bold white", min_width=25)
    table.add_column("Status", min_width=12)
    table.add_column("Score", min_width=10)
    table.add_column("Details", style="dim", min_width=30)

    for key, pol in result.policy.results.items():
        status = "[bold bright_green]✅ PASS[/]" if pol.passed else "[bold bright_red]❌ FAIL[/]"
        score_str = f"{pol.compliance_percentage:.0f}%"
        failed_rules = [r.rule_name for r in pol.rules if not r.passed and r.severity != "INFO"]
        details = ", ".join(failed_rules) if failed_rules else "All requirements met"
        table.add_row(f"{pol.standard_name}\n[dim]{pol.version}[/]", status, score_str, details)

    console.print(table)
    console.print()


def display_hashes(result: AuditResult):
    """Display hash analysis results."""
    table = Table(
        title="🔑 Hash Analysis",
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_cyan",
    )
    table.add_column("Algorithm", style="bold white", min_width=12)
    table.add_column("Security", min_width=14)
    table.add_column("Hash Value", style="dim", min_width=40, overflow="fold")
    table.add_column("Recommendation", style="dim", min_width=25)

    for h in result.hashes.hashes:
        sec_style = HASH_SECURITY_STYLE.get(h.security_rating, "white")
        hash_display = h.hash_value[:60] + "..." if len(h.hash_value) > 60 else h.hash_value
        table.add_row(
            h.algorithm,
            f"[{sec_style}]{h.security_rating}[/]",
            hash_display,
            h.recommendation,
        )

    console.print(table)
    console.print(f"  [dim]💡 Storage Advice: {result.hashes.storage_advice}[/]")
    console.print()


def display_recommendations(result: AuditResult):
    """Display improvement recommendations."""
    console.print(Panel(
        "\n".join(f"  {rec}" for rec in result.recommendations),
        title="[bold bright_white]💡 Recommendations[/]",
        border_style="cyan",
        box=box.DOUBLE,
        padding=(1, 2),
    ))
    console.print()


def display_footer(result: AuditResult):
    """Display analysis metadata footer."""
    console.print(
        f"[dim]─── Analysis completed in {result.analysis_duration_ms:.0f}ms │ "
        f"Auditor v{result.auditor_version} │ {result.timestamp} ───[/]"
    )
    console.print()


def run_dashboard(check_breaches: bool = True):
    """Run the full interactive dashboard flow."""
    console.clear()
    display_banner()

    password = get_password_input()
    if not password:
        console.print("[bold red]Error: Empty password provided.[/]")
        return

    # Run analysis
    result = run_analysis_with_progress(password, check_breaches)

    # Display all sections
    display_score_header(result)
    console.print()
    display_score_breakdown(result)
    display_entropy(result)
    display_patterns(result)
    display_breach_status(result)
    display_crack_times(result)
    display_policy_compliance(result)
    display_hashes(result)
    display_recommendations(result)
    display_footer(result)

    return result


def run_quick_audit(password: str, check_breaches: bool = True) -> AuditResult:
    """Run audit on a provided password (non-interactive)."""
    result = audit_password(password, check_breaches=check_breaches)

    display_score_header(result)
    console.print()
    display_score_breakdown(result)
    display_entropy(result)
    display_patterns(result)
    display_breach_status(result)
    display_crack_times(result)
    display_policy_compliance(result)
    display_hashes(result)
    display_recommendations(result)
    display_footer(result)

    return result

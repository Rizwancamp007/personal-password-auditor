#!/usr/bin/env python3
"""
Personal Password Auditor — Main CLI Entry Point
==================================================
A professional-grade password security analysis tool for cybersecurity
analysts. Performs deep password auditing using NIST SP 800-63B and
OWASP standards with breach detection, pattern analysis, entropy
calculation, crack-time estimation, and automated reporting.

Usage:
    python auditor.py audit                     # Interactive audit
    python auditor.py audit --password "test"   # Quick audit
    python auditor.py batch --file passwords.csv
    python auditor.py generate --length 20
    python auditor.py generate --passphrase
    python auditor.py dashboard

Author: Rizwan Khan
Version: 1.0.0
"""

import argparse
import sys
import os
from pathlib import Path

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from config import APP_NAME, APP_VERSION, APP_BANNER


def cmd_audit(args):
    """Handle the 'audit' subcommand."""
    from rich.console import Console
    console = Console()

    if args.password:
        # Direct password audit (non-interactive)
        from dashboard.dashboard import run_quick_audit, display_banner
        display_banner()
        result = run_quick_audit(args.password, check_breaches=not args.no_breach_check)
    else:
        # Interactive mode
        from dashboard.dashboard import run_dashboard
        result = run_dashboard(check_breaches=not args.no_breach_check)

    if result and args.output in ("html", "all"):
        from reporting.reporter import generate_html_report
        generate_html_report(result, output_path=args.report_path)

    if result and args.output in ("json", "all"):
        from reporting.reporter import generate_json_report
        generate_json_report(result, output_path=args.json_path)


def cmd_batch(args):
    """Handle the 'batch' subcommand."""
    from rich.console import Console
    from dashboard.dashboard import display_banner
    console = Console()

    display_banner()

    if not args.file:
        console.print("[bold red]Error: --file is required for batch mode[/]")
        console.print("[dim]Usage: python auditor.py batch --file passwords.csv[/]")
        return

    from batch.batch_auditor import run_batch_audit
    result = run_batch_audit(
        filepath=args.file,
        check_breaches=not args.no_breach_check,
        max_passwords=args.max,
    )

    if result and args.output in ("html", "all"):
        from reporting.reporter import generate_html_report
        # Generate a report for the weakest password as summary
        if result.weakest_entry and result.weakest_entry.result:
            generate_html_report(result.weakest_entry.result)


def cmd_generate(args):
    """Handle the 'generate' subcommand."""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    from dashboard.dashboard import display_banner

    console = Console()
    display_banner()

    if args.passphrase:
        # Generate passphrases
        from generators.passphrase_gen import generate_batch_passphrases
        passphrases = generate_batch_passphrases(
            count=args.count,
            word_count=args.words,
            separator=args.separator,
            capitalize=not args.no_capitalize,
            add_number=not args.no_number,
        )

        table = Table(
            title="🔑 Generated Passphrases",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=3)
        table.add_column("Passphrase", style="bold bright_green", min_width=40)
        table.add_column("Words", style="dim", width=6)
        table.add_column("Length", style="dim", width=7)
        table.add_column("Entropy", style="cyan", width=12)

        for i, pp in enumerate(passphrases, 1):
            table.add_row(
                str(i), pp.passphrase,
                str(pp.word_count), str(pp.total_length),
                f"{pp.entropy_bits:.1f} bits",
            )

        console.print(table)
        console.print()

    else:
        # Generate passwords
        from generators.password_gen import generate_batch
        passwords = generate_batch(
            count=args.count,
            length=args.length,
            use_uppercase=not args.no_upper,
            use_lowercase=True,
            use_digits=not args.no_digits,
            use_symbols=not args.no_symbols,
            exclude_ambiguous=args.no_ambiguous,
        )

        table = Table(
            title="🔑 Generated Passwords",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold bright_cyan",
        )
        table.add_column("#", style="dim", width=3)
        table.add_column("Password", style="bold bright_green", min_width=30)
        table.add_column("Length", style="dim", width=7)
        table.add_column("Charset", style="dim", min_width=15)
        table.add_column("Entropy", style="cyan", width=12)

        for i, pwd in enumerate(passwords, 1):
            table.add_row(
                str(i), pwd.password,
                str(pwd.length), pwd.charset_description,
                f"{pwd.entropy_bits:.1f} bits",
            )

        console.print(table)
        console.print()


def cmd_dashboard(args):
    """Handle the 'dashboard' subcommand — interactive loop."""
    from dashboard.dashboard import run_dashboard
    from rich.console import Console
    console = Console()

    while True:
        result = run_dashboard(check_breaches=not args.no_breach_check)

        if result and args.output in ("html", "all"):
            from reporting.reporter import generate_html_report
            generate_html_report(result)

        console.print("\n[bold cyan]─── What would you like to do? ───[/]")
        console.print("  [cyan]1[/] Audit another password")
        console.print("  [cyan]2[/] Generate a secure password")
        console.print("  [cyan]3[/] Generate a passphrase")
        console.print("  [cyan]4[/] Exit")
        console.print()

        try:
            choice = input("  Choice [1-4]: ").strip()
        except (KeyboardInterrupt, EOFError):
            break

        if choice == "1":
            continue
        elif choice == "2":
            from generators.password_gen import generate_batch
            passwords = generate_batch(count=5, length=16)
            console.print("\n[bold cyan]🔑 Generated Passwords:[/]")
            for i, p in enumerate(passwords, 1):
                console.print(f"  [green]{i}.[/] {p.password}  [dim]({p.entropy_bits:.0f} bits)[/]")
            console.print()
        elif choice == "3":
            from generators.passphrase_gen import generate_batch_passphrases
            phrases = generate_batch_passphrases(count=5, word_count=5)
            console.print("\n[bold cyan]🔑 Generated Passphrases:[/]")
            for i, p in enumerate(phrases, 1):
                console.print(f"  [green]{i}.[/] {p.passphrase}  [dim]({p.entropy_bits:.0f} bits)[/]")
            console.print()
        else:
            console.print("[bold cyan]Goodbye! Stay secure. 🔐[/]")
            break


def main():
    """Main entry point — parse arguments and route to subcommands."""
    parser = argparse.ArgumentParser(
        prog="auditor",
        description=f"{APP_NAME} v{APP_VERSION} — Professional Password Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python auditor.py audit                          Interactive password audit
  python auditor.py audit --password "MyPass123"   Quick audit
  python auditor.py audit --password "test" --output html
  python auditor.py batch --file passwords.csv     Batch audit
  python auditor.py generate --length 20 --count 10
  python auditor.py generate --passphrase --words 5
  python auditor.py dashboard                      Interactive dashboard
        """,
    )

    # Global options
    parser.add_argument("--version", action="version", version=f"{APP_NAME} v{APP_VERSION}")

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── Audit command ─────────────────────────────────────────────────────
    audit_parser = subparsers.add_parser("audit", help="Audit a single password")
    audit_parser.add_argument("--password", "-p", type=str, help="Password to audit (omit for interactive)")
    audit_parser.add_argument("--no-breach-check", action="store_true", help="Skip HIBP breach check")
    audit_parser.add_argument("--output", "-o", choices=["terminal", "html", "json", "all"], default="terminal")
    audit_parser.add_argument("--report-path", type=str, help="Custom HTML report output path")
    audit_parser.add_argument("--json-path", type=str, help="Custom JSON report output path")
    audit_parser.set_defaults(func=cmd_audit)

    # ── Batch command ─────────────────────────────────────────────────────
    batch_parser = subparsers.add_parser("batch", help="Audit passwords from a file")
    batch_parser.add_argument("--file", "-f", type=str, required=True, help="Path to TXT or CSV file")
    batch_parser.add_argument("--no-breach-check", action="store_true", help="Skip HIBP breach check")
    batch_parser.add_argument("--max", type=int, default=100, help="Max passwords to process (default: 100)")
    batch_parser.add_argument("--output", "-o", choices=["terminal", "html", "json", "all"], default="terminal")
    batch_parser.set_defaults(func=cmd_batch)

    # ── Generate command ──────────────────────────────────────────────────
    gen_parser = subparsers.add_parser("generate", help="Generate secure passwords")
    gen_parser.add_argument("--passphrase", action="store_true", help="Generate passphrases instead")
    gen_parser.add_argument("--length", "-l", type=int, default=16, help="Password length (default: 16)")
    gen_parser.add_argument("--count", "-c", type=int, default=5, help="Number to generate (default: 5)")
    gen_parser.add_argument("--words", "-w", type=int, default=5, help="Words per passphrase (default: 5)")
    gen_parser.add_argument("--separator", "-s", type=str, default="-", help="Passphrase separator (default: -)")
    gen_parser.add_argument("--no-upper", action="store_true", help="Exclude uppercase letters")
    gen_parser.add_argument("--no-digits", action="store_true", help="Exclude digits")
    gen_parser.add_argument("--no-symbols", action="store_true", help="Exclude symbols")
    gen_parser.add_argument("--no-ambiguous", action="store_true", help="Exclude ambiguous chars (0O1lI)")
    gen_parser.add_argument("--no-capitalize", action="store_true", help="Don't capitalize passphrase words")
    gen_parser.add_argument("--no-number", action="store_true", help="Don't add digit to passphrase")
    gen_parser.set_defaults(func=cmd_generate)

    # ── Dashboard command ─────────────────────────────────────────────────
    dash_parser = subparsers.add_parser("dashboard", help="Launch interactive dashboard")
    dash_parser.add_argument("--no-breach-check", action="store_true", help="Skip HIBP breach check")
    dash_parser.add_argument("--output", "-o", choices=["terminal", "html", "all"], default="terminal")
    dash_parser.set_defaults(func=cmd_dashboard)

    # Parse and execute
    args = parser.parse_args()

    if args.command is None:
        # No subcommand — launch interactive dashboard
        args.no_breach_check = False
        args.output = "terminal"
        cmd_dashboard(args)
    else:
        args.func(args)


if __name__ == "__main__":
    main()

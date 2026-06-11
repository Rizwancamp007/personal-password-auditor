"""
Report Generator
================
Generates standalone HTML reports and JSON exports from audit results.
Uses Jinja2 for HTML templating with a cyber-themed dark design.
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from config import REPORTS_DIR, APP_VERSION

try:
    from jinja2 import Template
    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False

console = Console()


def _get_template() -> str:
    """Load or return the HTML report template."""
    template_path = Path(__file__).resolve().parent / "templates" / "report_template.html"
    if template_path.exists():
        return template_path.read_text(encoding='utf-8')
    # Fallback to inline template
    return _INLINE_TEMPLATE


def generate_html_report(result, output_path: Optional[str] = None) -> str:
    """
    Generate a standalone HTML report from an AuditResult.

    Args:
        result: AuditResult from the analyzer
        output_path: Optional custom output path

    Returns:
        Path to the generated HTML file
    """
    if not HAS_JINJA2:
        console.print("[bold red]Jinja2 required for HTML reports: pip install jinja2[/]")
        return ""

    template_str = _get_template()
    template = Template(template_str)

    # Prepare template context
    context = {
        "app_version": APP_VERSION,
        "timestamp": result.timestamp,
        "duration_ms": result.analysis_duration_ms,
        "password_masked": result.password_masked,
        "password_length": result.password_length,
        "score": result.strength.final_score,
        "grade": result.strength.grade,
        "grade_label": result.strength.grade_label,
        "risk_rating": result.risk_rating,
        "risk_description": result.risk_description,
        # Entropy
        "shannon_entropy": result.entropy.shannon_entropy,
        "effective_entropy": result.entropy.effective_entropy,
        "ideal_entropy": result.entropy.ideal_entropy,
        "entropy_rating": result.entropy.entropy_rating,
        "entropy_description": result.entropy.entropy_description,
        "charset_info": result.entropy.charset_info,
        "unique_chars": result.entropy.unique_characters,
        "compression_ratio": result.entropy.compression_ratio,
        # Patterns
        "patterns": result.patterns,
        "pattern_count": len(result.patterns),
        # Breach
        "breach": result.breach,
        # Crack times
        "crack_times": result.crack_time.estimates,
        # Policy
        "policy_results": result.policy.results,
        "policies_passed": result.policy.total_standards_passed,
        "overall_compliant": result.policy.overall_compliant,
        # Hashes
        "hashes": result.hashes.hashes,
        "storage_advice": result.hashes.storage_advice,
        # Recommendations
        "recommendations": result.recommendations,
        # Score breakdown
        "length_score": result.strength.length_score,
        "diversity_score": result.strength.diversity_score,
        "entropy_bonus": result.strength.entropy_bonus,
        "policy_bonus": result.strength.policy_bonus,
        "pattern_penalty": result.strength.pattern_penalty,
        "breach_penalty": result.strength.breach_penalty,
    }

    html = template.render(**context)

    # Determine output path
    if output_path:
        out = Path(output_path)
    else:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = REPORTS_DIR / f"password_audit_{timestamp_str}.html"

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding='utf-8')

    console.print(f"[bold bright_green]✅ HTML report saved: {out}[/]")
    return str(out)


def generate_json_report(result, output_path: Optional[str] = None) -> str:
    """Generate a JSON export from an AuditResult."""

    data = {
        "metadata": {
            "version": APP_VERSION,
            "timestamp": result.timestamp,
            "analysis_duration_ms": result.analysis_duration_ms,
        },
        "password_info": {
            "masked": result.password_masked,
            "length": result.password_length,
        },
        "strength": {
            "score": result.strength.final_score,
            "grade": result.strength.grade,
            "grade_label": result.strength.grade_label,
            "breakdown": {
                "length_score": result.strength.length_score,
                "diversity_score": result.strength.diversity_score,
                "entropy_bonus": result.strength.entropy_bonus,
                "policy_bonus": result.strength.policy_bonus,
                "pattern_penalty": result.strength.pattern_penalty,
                "breach_penalty": result.strength.breach_penalty,
            },
        },
        "risk": {
            "rating": result.risk_rating,
            "description": result.risk_description,
        },
        "entropy": {
            "shannon": result.entropy.shannon_entropy,
            "effective": result.entropy.effective_entropy,
            "ideal": result.entropy.ideal_entropy,
            "rating": result.entropy.entropy_rating,
            "charset_pool_size": result.entropy.charset_info.pool_size,
            "categories_used": result.entropy.charset_info.categories_used,
        },
        "patterns": [
            {
                "type": p.pattern_type,
                "severity": p.severity,
                "description": p.description,
                "position": p.position,
            }
            for p in result.patterns
        ],
        "breach": {
            "checked": result.breach.checked,
            "breached": result.breach.breached,
            "count": result.breach.breach_count,
            "severity": result.breach.severity,
        },
        "crack_times": [
            {
                "scenario": e.scenario_name,
                "speed": e.speed,
                "time_seconds": e.seconds,
                "time_human": e.human_readable,
                "severity": e.severity,
            }
            for e in result.crack_time.estimates
        ],
        "policy_compliance": {
            key: {
                "standard": pol.standard_name,
                "passed": pol.passed,
                "compliance_pct": pol.compliance_percentage,
            }
            for key, pol in result.policy.results.items()
        },
        "recommendations": result.recommendations,
    }

    if output_path:
        out = Path(output_path)
    else:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = REPORTS_DIR / f"password_audit_{timestamp_str}.json"

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')

    console.print(f"[bold bright_green]✅ JSON report saved: {out}[/]")
    return str(out)


# ─── Inline fallback template ────────────────────────────────────────────────
_INLINE_TEMPLATE = """<!DOCTYPE html>
<html><head><title>Password Audit Report</title></head>
<body style="background:#0a0e17;color:#e5e7eb;font-family:sans-serif;padding:20px">
<h1 style="color:#00d4ff">Password Audit Report</h1>
<p>Score: {{ score }}/100 | Grade: {{ grade }} | Risk: {{ risk_rating }}</p>
<p>Generated: {{ timestamp }} | Auditor v{{ app_version }}</p>
</body></html>"""

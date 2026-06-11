"""
Master Analysis Orchestrator
=============================
Central coordinator that invokes all sub-modules (entropy, patterns,
strength, breach, hash, policy, crack time) and aggregates results
into a unified AuditResult with risk rating and recommendations.
"""

import sys
import time
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.entropy import analyze_entropy, EntropyResult
from core.patterns import analyze_patterns, PatternMatch
from core.strength import calculate_strength, ScoreBreakdown
from core.breach_checker import check_breach, BreachResult
from core.hash_analyzer import analyze_hashes, HashAnalysisResult
from core.policy_checker import check_policy, PolicyCheckResult
from core.crack_time import estimate_crack_time, CrackTimeResult
from config import RISK_RATINGS, APP_VERSION


@dataclass
class AuditResult:
    """Unified result from all analysis modules."""
    # Metadata
    timestamp: str
    auditor_version: str
    analysis_duration_ms: float

    # Core results
    entropy: EntropyResult
    patterns: List[PatternMatch]
    strength: ScoreBreakdown
    breach: BreachResult
    hashes: HashAnalysisResult
    policy: PolicyCheckResult
    crack_time: CrackTimeResult

    # Overall assessment
    risk_rating: str
    risk_description: str
    risk_color: str

    # Recommendations
    recommendations: List[str]

    # Password metadata (never store the actual password)
    password_length: int
    password_masked: str


def _get_risk_rating(score: int) -> tuple:
    """Map score to risk rating, description, and color."""
    for low, high, rating, description in RISK_RATINGS:
        if low <= score <= high:
            colors = {
                "CRITICAL": "bright_red", "HIGH": "red",
                "MEDIUM": "yellow", "LOW": "cyan",
                "MODERATE": "blue", "SECURE": "bright_green",
            }
            return rating, description, colors.get(rating, "white")
    return "UNKNOWN", "Unable to classify", "white"


def _mask_password(password: str) -> str:
    """Create a masked version of the password for display."""
    if len(password) <= 2:
        return "*" * len(password)
    return password[0] + "*" * (len(password) - 2) + password[-1]


def _generate_recommendations(
    entropy: EntropyResult,
    patterns: List[PatternMatch],
    strength: ScoreBreakdown,
    breach: BreachResult,
    policy: PolicyCheckResult,
    crack_time: CrackTimeResult,
    password: str,
) -> List[str]:
    """Generate prioritized, actionable improvement recommendations."""
    recs = []

    # Critical: Breach detected
    if breach.breached:
        recs.append(
            "🚨 CRITICAL: This password has been exposed in data breaches. "
            "Change it immediately on ALL accounts where it's used."
        )

    # Critical: Common password
    for p in patterns:
        if p.pattern_type == "Common Password":
            recs.append(
                "🚨 CRITICAL: This is a commonly used password and appears in "
                "attacker dictionaries. It will be cracked in seconds."
            )
            break

    # Length
    if len(password) < 12:
        recs.append(
            f"📏 Increase password length to at least 12 characters "
            f"(currently {len(password)}). Each additional character "
            f"exponentially increases security."
        )
    elif len(password) < 16:
        recs.append(
            f"📏 Consider extending to 16+ characters for stronger protection "
            f"against offline attacks."
        )

    # Diversity
    if entropy.charset_info.categories_used < 3:
        missing = []
        if not entropy.charset_info.has_uppercase:
            missing.append("uppercase letters")
        if not entropy.charset_info.has_lowercase:
            missing.append("lowercase letters")
        if not entropy.charset_info.has_digits:
            missing.append("numbers")
        if not entropy.charset_info.has_symbols:
            missing.append("special characters (!@#$%)")
        if missing:
            recs.append(f"🔤 Add character variety: include {', '.join(missing)}.")

    # Pattern-based
    high_patterns = [p for p in patterns if p.severity in ("CRITICAL", "HIGH")]
    for p in high_patterns:
        if p.pattern_type == "Dictionary Word":
            recs.append(
                "📖 Avoid using common dictionary words. Use random combinations "
                "or a passphrase of 4+ unrelated words."
            )
            break
        elif p.pattern_type == "Keyboard Walk":
            recs.append(
                "⌨️ Avoid keyboard walk patterns (qwerty, asdf). These are "
                "among the first patterns attackers try."
            )
            break
        elif p.pattern_type in ("L33t Speak", "Common Substitution"):
            recs.append(
                "🔄 Simple letter substitutions (@ for a, 3 for e) are well-known "
                "to attackers and don't add meaningful security."
            )
            break

    # Crack time
    if crack_time.weakest_scenario.severity in ("CRITICAL", "HIGH"):
        recs.append(
            f"⏱️ Estimated crack time ({crack_time.weakest_scenario.scenario_name}): "
            f"{crack_time.weakest_scenario.human_readable}. "
            f"Aim for passwords that take centuries to crack."
        )

    # Policy
    if not policy.overall_compliant:
        failed_standards = [
            r.standard_id for r in policy.results.values() if not r.passed
        ]
        recs.append(
            f"📋 Password fails compliance with: {', '.join(failed_standards)}. "
            f"Review policy requirements for your organization."
        )

    # Passphrase suggestion
    if strength.final_score < 70:
        recs.append(
            "💡 Consider using a passphrase — 4-6 random words separated by "
            "spaces or symbols. Example: 'correct horse battery staple' — "
            "easy to remember, hard to crack."
        )

    # If no issues found
    if not recs:
        recs.append(
            "✅ Excellent password! No significant weaknesses detected. "
            "Ensure you use a unique password for each account and store "
            "them in a reputable password manager."
        )

    return recs


def audit_password(
    password: str,
    check_breaches: bool = True,
) -> AuditResult:
    """
    Perform a comprehensive audit of a password.

    Args:
        password: The password to audit
        check_breaches: Whether to check HIBP breach database (requires internet)

    Returns:
        AuditResult with complete analysis from all modules
    """
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Entropy analysis
    entropy = analyze_entropy(password)

    # 2. Pattern detection
    patterns = analyze_patterns(password)

    # 3. Breach check
    if check_breaches:
        breach = check_breach(password)
    else:
        breach = BreachResult(
            checked=False, breached=False, breach_count=0,
            severity="INFO",
            description="Breach check skipped (--no-breach-check flag)",
            api_available=False,
        )

    # 4. Policy compliance
    policy = check_policy(password, breach_detected=breach.breached)

    # 5. Strength scoring (needs entropy, patterns, breach, policy data)
    strength = calculate_strength(
        password=password,
        effective_entropy=entropy.effective_entropy,
        pattern_matches=patterns,
        breach_count=breach.breach_count,
        policies_passed=policy.total_standards_passed,
    )

    # 6. Hash analysis
    hashes = analyze_hashes(password)

    # 7. Crack time estimation
    crack_time = estimate_crack_time(
        pool_size=entropy.charset_info.pool_size,
        password_length=len(password),
    )

    # 8. Risk rating
    risk_rating, risk_description, risk_color = _get_risk_rating(strength.final_score)

    # 9. Recommendations
    recommendations = _generate_recommendations(
        entropy, patterns, strength, breach, policy, crack_time, password
    )

    # Calculate duration
    duration_ms = round((time.time() - start_time) * 1000, 2)

    return AuditResult(
        timestamp=timestamp,
        auditor_version=APP_VERSION,
        analysis_duration_ms=duration_ms,
        entropy=entropy,
        patterns=patterns,
        strength=strength,
        breach=breach,
        hashes=hashes,
        policy=policy,
        crack_time=crack_time,
        risk_rating=risk_rating,
        risk_description=risk_description,
        risk_color=risk_color,
        recommendations=recommendations,
        password_length=len(password),
        password_masked=_mask_password(password),
    )

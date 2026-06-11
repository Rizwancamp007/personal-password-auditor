"""
Password Strength Scoring Module
=================================
Composite scoring system (0-100) that evaluates passwords based on:
  - Length (0-25 pts)
  - Character diversity (0-20 pts)
  - Entropy bonus (0-20 pts)
  - Policy compliance bonus (0-15 pts)
  - Pattern penalties (up to -30 pts)
  - Breach penalty (-40 pts)

Maps final score to letter grades: A+ through F.
"""

import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import SCORING_WEIGHTS, SCORING_PENALTIES, GRADE_MAP


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of the password strength score."""
    length_score: float
    diversity_score: float
    entropy_bonus: float
    policy_bonus: float
    pattern_penalty: float
    breach_penalty: float
    raw_score: float          # Before clamping
    final_score: int          # Clamped 0-100
    grade: str                # A+, A, B, C, D, F
    grade_label: str          # "Exceptional", "Excellent", etc.
    breakdown_details: dict   # Itemized scoring details


def calculate_length_score(password: str) -> Tuple[float, dict]:
    """
    Score based on password length (0-25 points).
    Longer passwords get exponentially more points.
    """
    length = len(password)
    config = SCORING_WEIGHTS["length"]
    score = 0.0

    for threshold, points in config["thresholds"]:
        if length >= threshold:
            score = points

    details = {
        "password_length": length,
        "max_possible": config["max_points"],
        "awarded": min(score, config["max_points"]),
    }
    return min(score, config["max_points"]), details


def calculate_diversity_score(password: str) -> Tuple[float, dict]:
    """
    Score based on character class diversity (0-20 points).
    Awards points for each character category present.
    """
    config = SCORING_WEIGHTS["diversity"]
    score = 0.0
    details = {}

    has_lowercase = any(c.islower() for c in password)
    has_uppercase = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(not c.isalnum() and not c.isspace() for c in password)
    has_unicode = any(ord(c) > 127 for c in password)

    categories = {
        "lowercase": (has_lowercase, config["categories"]["lowercase"]),
        "uppercase": (has_uppercase, config["categories"]["uppercase"]),
        "digits": (has_digits, config["categories"]["digits"]),
        "symbols": (has_symbols, config["categories"]["symbols"]),
        "unicode_extended": (has_unicode, config["categories"]["unicode_extended"]),
    }

    for category, (present, points) in categories.items():
        if present:
            score += points
        details[category] = {"present": present, "points": points if present else 0}

    details["max_possible"] = config["max_points"]
    details["awarded"] = min(score, config["max_points"])

    return min(score, config["max_points"]), details


def calculate_entropy_bonus(effective_entropy: float) -> Tuple[float, dict]:
    """
    Bonus points based on effective entropy bits (0-20 points).
    Higher entropy = more random = better score.
    """
    config = SCORING_WEIGHTS["entropy_bonus"]
    score = 0.0

    for threshold, points in config["thresholds"]:
        if effective_entropy >= threshold:
            score = points

    details = {
        "effective_entropy_bits": effective_entropy,
        "max_possible": config["max_points"],
        "awarded": min(score, config["max_points"]),
    }
    return min(score, config["max_points"]), details


def calculate_policy_bonus(policies_passed: int) -> Tuple[float, dict]:
    """
    Bonus for meeting security standard compliance (0-15 points).
    5 points per standard passed (NIST, OWASP, PCI-DSS).
    """
    config = SCORING_WEIGHTS["policy_compliance_bonus"]
    score = policies_passed * config["per_standard"]

    details = {
        "policies_passed": policies_passed,
        "per_standard_points": config["per_standard"],
        "max_possible": config["max_points"],
        "awarded": min(score, config["max_points"]),
    }
    return min(score, config["max_points"]), details


def calculate_pattern_penalty(pattern_matches: list) -> Tuple[float, dict]:
    """
    Penalty for detected pattern weaknesses (up to -30 points).
    Each pattern severity has a different penalty weight.
    """
    penalty = 0.0
    pattern_details = []
    max_penalty = SCORING_PENALTIES["max_pattern_penalty"]

    for match in pattern_matches:
        severity = match.severity
        penalty_value = SCORING_PENALTIES["pattern_detected"].get(severity, -2)
        adjusted_penalty = penalty_value * match.penalty_weight
        penalty += adjusted_penalty
        pattern_details.append({
            "type": match.pattern_type,
            "severity": severity,
            "penalty": adjusted_penalty,
        })

    # Cap the penalty
    penalty = max(penalty, max_penalty)

    details = {
        "total_patterns": len(pattern_matches),
        "total_penalty": penalty,
        "max_penalty": max_penalty,
        "patterns": pattern_details,
    }
    return penalty, details


def calculate_breach_penalty(breach_count: int) -> Tuple[float, dict]:
    """
    Penalty if the password was found in data breaches (-40 points).
    """
    if breach_count > 0:
        penalty = SCORING_PENALTIES["breach_detected"]
        details = {
            "breached": True,
            "breach_count": breach_count,
            "penalty": penalty,
        }
        return penalty, details

    return 0.0, {"breached": False, "breach_count": 0, "penalty": 0}


def get_grade(score: int) -> Tuple[str, str]:
    """Map a score (0-100) to a letter grade and label."""
    for threshold, grade, label in GRADE_MAP:
        if score >= threshold:
            return grade, label
    return "F", "Critical"


def calculate_strength(
    password: str,
    effective_entropy: float,
    pattern_matches: list,
    breach_count: int = 0,
    policies_passed: int = 0,
) -> ScoreBreakdown:
    """
    Calculate the complete password strength score.

    Args:
        password: The password to score
        effective_entropy: Effective entropy bits from entropy module
        pattern_matches: List of PatternMatch objects from pattern detector
        breach_count: Number of times found in breach databases
        policies_passed: Number of security standards passed (0-3)

    Returns:
        ScoreBreakdown with full scoring details
    """
    # Calculate each component
    length_score, length_details = calculate_length_score(password)
    diversity_score, diversity_details = calculate_diversity_score(password)
    entropy_bonus, entropy_details = calculate_entropy_bonus(effective_entropy)
    policy_bonus, policy_details = calculate_policy_bonus(policies_passed)
    pattern_penalty, pattern_details = calculate_pattern_penalty(pattern_matches)
    breach_penalty, breach_details = calculate_breach_penalty(breach_count)

    # Common password additional penalty
    common_penalty = 0.0
    for m in pattern_matches:
        if m.pattern_type == "Common Password":
            common_penalty = SCORING_PENALTIES["common_password"]
            break

    # Calculate raw score
    raw_score = (
        length_score
        + diversity_score
        + entropy_bonus
        + policy_bonus
        + pattern_penalty
        + breach_penalty
        + common_penalty
    )

    # Clamp to 0-100
    final_score = max(0, min(100, int(round(raw_score))))

    # Get grade
    grade, grade_label = get_grade(final_score)

    # Build breakdown details
    breakdown_details = {
        "length": length_details,
        "diversity": diversity_details,
        "entropy_bonus": entropy_details,
        "policy_bonus": policy_details,
        "pattern_penalty": pattern_details,
        "breach_penalty": breach_details,
        "common_password_penalty": common_penalty,
    }

    return ScoreBreakdown(
        length_score=length_score,
        diversity_score=diversity_score,
        entropy_bonus=entropy_bonus,
        policy_bonus=policy_bonus,
        pattern_penalty=pattern_penalty,
        breach_penalty=breach_penalty + common_penalty,
        raw_score=raw_score,
        final_score=final_score,
        grade=grade,
        grade_label=grade_label,
        breakdown_details=breakdown_details,
    )

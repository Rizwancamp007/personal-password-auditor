"""
Policy Compliance Checker
=========================
Multi-standard compliance engine checking passwords against:
  - NIST SP 800-63B Rev 4
  - OWASP ASVS v4.0
  - PCI-DSS v4.0
Returns per-rule pass/fail with explanations and remediation advice.
"""

import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Dict, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import POLICY_PRESETS


@dataclass
class PolicyRuleResult:
    """Result of a single policy rule check."""
    rule_name: str
    passed: bool
    description: str
    remediation: str
    severity: str  # How critical this rule is


@dataclass
class PolicyResult:
    """Result of checking against a single security standard."""
    standard_name: str
    standard_id: str
    version: str
    description: str
    passed: bool
    rules: List[PolicyRuleResult]
    pass_count: int
    fail_count: int
    compliance_percentage: float


@dataclass
class PolicyCheckResult:
    """Complete compliance check across all standards."""
    results: Dict[str, PolicyResult]
    total_standards_passed: int
    total_standards_checked: int
    overall_compliant: bool
    recommendations: List[str]


def _check_rules(password: str, rules: dict, breach_detected: bool = False) -> List[PolicyRuleResult]:
    """Check a password against a set of policy rules."""
    results = []
    pwd_len = len(password)

    # Minimum length
    min_len = rules.get("min_length", 8)
    results.append(PolicyRuleResult(
        rule_name=f"Minimum Length ({min_len} chars)",
        passed=pwd_len >= min_len,
        description=f"Password must be at least {min_len} characters (yours: {pwd_len})",
        remediation=f"Add {max(0, min_len - pwd_len)} more characters" if pwd_len < min_len else "Requirement met",
        severity="HIGH",
    ))

    # Maximum length
    max_len = rules.get("max_length", 64)
    results.append(PolicyRuleResult(
        rule_name=f"Maximum Length ({max_len} chars)",
        passed=pwd_len <= max_len,
        description=f"Password must not exceed {max_len} characters (yours: {pwd_len})",
        remediation=f"Reduce password by {pwd_len - max_len} characters" if pwd_len > max_len else "Requirement met",
        severity="LOW",
    ))

    # Character class requirements (only if policy requires them)
    if rules.get("require_uppercase", False):
        has_upper = any(c.isupper() for c in password)
        results.append(PolicyRuleResult(
            rule_name="Uppercase Required",
            passed=has_upper,
            description="Must contain at least one uppercase letter (A-Z)",
            remediation="Add an uppercase letter" if not has_upper else "Requirement met",
            severity="MEDIUM",
        ))

    if rules.get("require_lowercase", False):
        has_lower = any(c.islower() for c in password)
        results.append(PolicyRuleResult(
            rule_name="Lowercase Required",
            passed=has_lower,
            description="Must contain at least one lowercase letter (a-z)",
            remediation="Add a lowercase letter" if not has_lower else "Requirement met",
            severity="MEDIUM",
        ))

    if rules.get("require_digits", False):
        has_digit = any(c.isdigit() for c in password)
        results.append(PolicyRuleResult(
            rule_name="Digit Required",
            passed=has_digit,
            description="Must contain at least one digit (0-9)",
            remediation="Add a numeric digit" if not has_digit else "Requirement met",
            severity="MEDIUM",
        ))

    if rules.get("require_symbols", False):
        has_symbol = any(not c.isalnum() and not c.isspace() for c in password)
        results.append(PolicyRuleResult(
            rule_name="Symbol Required",
            passed=has_symbol,
            description="Must contain at least one special character (!@#$...)",
            remediation="Add a special character" if not has_symbol else "Requirement met",
            severity="MEDIUM",
        ))

    # Breach check requirement
    if rules.get("require_breach_check", False):
        results.append(PolicyRuleResult(
            rule_name="Not In Breach Database",
            passed=not breach_detected,
            description="Password must not appear in known data breaches",
            remediation="Change password immediately — it is compromised" if breach_detected else "Requirement met",
            severity="CRITICAL",
        ))

    # Modern policy indicators (informational)
    if rules.get("no_composition_rules", False):
        results.append(PolicyRuleResult(
            rule_name="No Composition Rules",
            passed=True,
            description="This standard does NOT require specific character types (modern approach)",
            remediation="Focus on length and uniqueness instead of complexity",
            severity="INFO",
        ))

    if rules.get("no_forced_rotation", False):
        results.append(PolicyRuleResult(
            rule_name="No Forced Rotation",
            passed=True,
            description="This standard does NOT require periodic password changes",
            remediation="Change password only when compromise is suspected",
            severity="INFO",
        ))

    return results


def check_policy(password: str, breach_detected: bool = False) -> PolicyCheckResult:
    """
    Check password against all three security standards.

    Args:
        password: The password to check
        breach_detected: Whether the password was found in breach databases

    Returns:
        PolicyCheckResult with compliance status for each standard
    """
    all_results: Dict[str, PolicyResult] = {}
    standards_passed = 0
    recommendations: List[str] = []

    for key, preset in POLICY_PRESETS.items():
        rule_results = _check_rules(password, preset["rules"], breach_detected)

        # Count pass/fail (excluding INFO-level rules)
        actionable_rules = [r for r in rule_results if r.severity != "INFO"]
        pass_count = sum(1 for r in actionable_rules if r.passed)
        fail_count = sum(1 for r in actionable_rules if not r.passed)
        total_actionable = len(actionable_rules)

        compliance_pct = (pass_count / total_actionable * 100) if total_actionable > 0 else 100
        standard_passed = fail_count == 0

        if standard_passed:
            standards_passed += 1
        else:
            # Collect remediation recommendations
            for r in rule_results:
                if not r.passed and r.severity != "INFO":
                    recommendations.append(
                        f"[{preset['standard_id']}] {r.rule_name}: {r.remediation}"
                    )

        all_results[key] = PolicyResult(
            standard_name=preset["name"],
            standard_id=preset["standard_id"],
            version=preset["version"],
            description=preset["description"],
            passed=standard_passed,
            rules=rule_results,
            pass_count=pass_count,
            fail_count=fail_count,
            compliance_percentage=round(compliance_pct, 1),
        )

    return PolicyCheckResult(
        results=all_results,
        total_standards_passed=standards_passed,
        total_standards_checked=len(POLICY_PRESETS),
        overall_compliant=standards_passed == len(POLICY_PRESETS),
        recommendations=recommendations,
    )

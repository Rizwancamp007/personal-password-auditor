"""
Crack Time Estimation Module
=============================
Estimates the time required to crack a password under various attack
scenarios, from rate-limited online attacks to dedicated GPU clusters.

Uses effective entropy (keyspace size) and attack speeds defined in config.
"""

import math
from dataclasses import dataclass
from typing import Dict, List

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import ATTACK_SCENARIOS


@dataclass
class CrackTimeEstimate:
    """Crack time estimation for a single attack scenario."""
    scenario_name: str
    scenario_key: str
    speed: float                 # Guesses per second
    description: str
    icon: str
    seconds: float               # Estimated seconds to crack
    human_readable: str           # "3 centuries", "2 hours", etc.
    severity: str                 # CRITICAL / HIGH / MEDIUM / LOW / SECURE


@dataclass
class CrackTimeResult:
    """Complete crack time analysis across all scenarios."""
    keyspace_size: float          # Total number of possible combinations
    estimates: List[CrackTimeEstimate]
    weakest_scenario: CrackTimeEstimate    # Fastest crack time
    strongest_scenario: CrackTimeEstimate  # Slowest crack time
    overall_severity: str


# ─── Time Formatting ──────────────────────────────────────────────────────────
TIME_UNITS = [
    (60 * 60 * 24 * 365.25 * 1000, "millennia"),
    (60 * 60 * 24 * 365.25 * 100, "centuries"),
    (60 * 60 * 24 * 365.25 * 10, "decades"),
    (60 * 60 * 24 * 365.25, "years"),
    (60 * 60 * 24 * 30.44, "months"),
    (60 * 60 * 24 * 7, "weeks"),
    (60 * 60 * 24, "days"),
    (60 * 60, "hours"),
    (60, "minutes"),
    (1, "seconds"),
]


def format_time(seconds: float) -> str:
    """
    Convert seconds into a human-readable time string.
    Examples: "3 centuries", "14 years", "2 hours", "instant"
    """
    if seconds < 0.001:
        return "instant"
    if seconds < 1:
        return "less than a second"
    if math.isinf(seconds):
        return "heat death of universe"

    for divisor, unit_name in TIME_UNITS:
        if seconds >= divisor:
            value = seconds / divisor
            if value >= 1000 and unit_name == "millennia":
                # Express as scientific notation for very large numbers
                exponent = int(math.log10(value)) + 3  # +3 for millennia->years
                return f"~10^{exponent} years"
            if value >= 100:
                return f"{int(value):,} {unit_name}"
            if value >= 10:
                return f"{value:.0f} {unit_name}"
            return f"{value:.1f} {unit_name}"

    return f"{seconds:.1f} seconds"


def get_crack_severity(seconds: float) -> str:
    """Map crack time in seconds to a severity level."""
    if seconds < 1:
        return "CRITICAL"
    if seconds < 3600:  # Less than 1 hour
        return "CRITICAL"
    if seconds < 86400:  # Less than 1 day
        return "HIGH"
    if seconds < 86400 * 30:  # Less than 1 month
        return "HIGH"
    if seconds < 86400 * 365:  # Less than 1 year
        return "MEDIUM"
    if seconds < 86400 * 365 * 100:  # Less than 100 years
        return "LOW"
    return "SECURE"


def calculate_keyspace(pool_size: int, length: int) -> float:
    """
    Calculate the total keyspace (number of possible combinations).
    Keyspace = pool_size ^ length
    """
    if pool_size <= 0 or length <= 0:
        return 0.0

    try:
        return float(pool_size ** length)
    except OverflowError:
        # Use logarithmic computation for very large keyspaces
        return math.pow(10, length * math.log10(pool_size))


def estimate_crack_time(
    pool_size: int,
    password_length: int,
    guesses_override: float = None
) -> CrackTimeResult:
    """
    Estimate crack time across all attack scenarios.

    Args:
        pool_size: Number of possible characters in the charset
        password_length: Length of the password
        guesses_override: If provided, use this as the keyspace instead
                         of calculating from pool_size and length.
                         Useful when zxcvbn provides its own guess estimate.
    """
    # Calculate keyspace
    if guesses_override is not None and guesses_override > 0:
        keyspace = guesses_override
    else:
        keyspace = calculate_keyspace(pool_size, password_length)

    if keyspace <= 0:
        # Return instant crack for empty/invalid passwords
        estimates = []
        for key, scenario in ATTACK_SCENARIOS.items():
            estimates.append(CrackTimeEstimate(
                scenario_name=scenario["name"],
                scenario_key=key,
                speed=scenario["speed"],
                description=scenario["description"],
                icon=scenario["icon"],
                seconds=0,
                human_readable="instant",
                severity="CRITICAL",
            ))
        return CrackTimeResult(
            keyspace_size=0,
            estimates=estimates,
            weakest_scenario=estimates[-1],
            strongest_scenario=estimates[0],
            overall_severity="CRITICAL",
        )

    # Average case: attacker needs to try ~50% of the keyspace
    average_guesses = keyspace / 2.0

    estimates: List[CrackTimeEstimate] = []

    for key, scenario in ATTACK_SCENARIOS.items():
        speed = scenario["speed"]
        if speed <= 0:
            seconds = float('inf')
        else:
            try:
                seconds = average_guesses / speed
            except OverflowError:
                seconds = float('inf')

        estimate = CrackTimeEstimate(
            scenario_name=scenario["name"],
            scenario_key=key,
            speed=speed,
            description=scenario["description"],
            icon=scenario["icon"],
            seconds=seconds,
            human_readable=format_time(seconds),
            severity=get_crack_severity(seconds),
        )
        estimates.append(estimate)

    # Sort by crack time (fastest first = weakest)
    estimates_sorted = sorted(estimates, key=lambda e: e.seconds)

    # Overall severity is based on the fastest (most dangerous) scenario
    overall_severity = estimates_sorted[0].severity

    return CrackTimeResult(
        keyspace_size=keyspace,
        estimates=estimates,
        weakest_scenario=estimates_sorted[0],   # Fastest to crack
        strongest_scenario=estimates_sorted[-1], # Slowest to crack
        overall_severity=overall_severity,
    )

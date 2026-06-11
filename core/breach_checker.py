"""
Have I Been Pwned Breach Checker
================================
Checks passwords against the HIBP breached passwords database using
the k-anonymity model. Only the first 5 characters of the SHA-1 hash
are sent over the network — the full password never leaves the client.

Privacy Model:
  1. SHA-1 hash the password
  2. Send prefix (first 5 hex chars) to HIBP API
  3. Receive all matching suffixes
  4. Compare locally — password stays private
"""

import hashlib
import time
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import HIBP_API_URL, HIBP_TIMEOUT, HIBP_RATE_LIMIT_DELAY

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


@dataclass
class BreachResult:
    """Result of a breach database check."""
    checked: bool               # Whether the check was performed
    breached: bool              # Whether the password was found
    breach_count: int           # Number of times found in breaches
    severity: str               # CRITICAL, HIGH, MEDIUM, LOW, SECURE
    description: str            # Human-readable result
    api_available: bool         # Whether the API was reachable
    error_message: Optional[str] = None  # Error details if check failed
    sha1_prefix: Optional[str] = None    # First 5 chars of SHA-1 (for reference)


# Track last API call time for rate limiting
_last_api_call: float = 0.0


def _sha1_hash(password: str) -> str:
    """Generate SHA-1 hash of the password (uppercase hex)."""
    return hashlib.sha1(password.encode('utf-8')).hexdigest().upper()


def _rate_limit():
    """Enforce rate limiting between API calls."""
    global _last_api_call
    elapsed = time.time() - _last_api_call
    if elapsed < HIBP_RATE_LIMIT_DELAY:
        time.sleep(HIBP_RATE_LIMIT_DELAY - elapsed)
    _last_api_call = time.time()


def _get_breach_severity(count: int) -> str:
    """Classify breach severity based on occurrence count."""
    if count == 0:
        return "SECURE"
    if count >= 100000:
        return "CRITICAL"
    if count >= 10000:
        return "HIGH"
    if count >= 1000:
        return "MEDIUM"
    return "LOW"


def check_breach(password: str) -> BreachResult:
    """
    Check if a password has been exposed in known data breaches
    using the Have I Been Pwned k-anonymity API.

    The password is NEVER sent over the network. Only the first 5
    characters of its SHA-1 hash are transmitted.

    Args:
        password: The password to check

    Returns:
        BreachResult with breach status and details
    """
    if not password:
        return BreachResult(
            checked=False,
            breached=False,
            breach_count=0,
            severity="CRITICAL",
            description="Empty password — cannot check",
            api_available=False,
        )

    if not HAS_REQUESTS:
        return BreachResult(
            checked=False,
            breached=False,
            breach_count=0,
            severity="INFO",
            description="Breach check unavailable — 'requests' library not installed",
            api_available=False,
            error_message="Install requests: pip install requests",
        )

    # Step 1: SHA-1 hash the password
    sha1 = _sha1_hash(password)
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        # Step 2: Rate limit compliance
        _rate_limit()

        # Step 3: Send only the prefix to HIBP API
        url = f"{HIBP_API_URL}{prefix}"
        headers = {
            "User-Agent": "PersonalPasswordAuditor/1.0",
            "Add-Padding": "true",  # Adds padding to prevent response-length analysis
        }

        response = requests.get(url, headers=headers, timeout=HIBP_TIMEOUT)

        if response.status_code != 200:
            return BreachResult(
                checked=False,
                breached=False,
                breach_count=0,
                severity="INFO",
                description=f"API returned status {response.status_code}",
                api_available=False,
                error_message=f"HTTP {response.status_code}",
                sha1_prefix=prefix,
            )

        # Step 4: Compare suffix locally
        breach_count = 0
        for line in response.text.splitlines():
            line = line.strip()
            if not line or ':' not in line:
                continue
            hash_suffix, count = line.split(':', 1)
            if hash_suffix.upper() == suffix:
                breach_count = int(count)
                break

        # Step 5: Build result
        if breach_count > 0:
            severity = _get_breach_severity(breach_count)
            description = (
                f"⚠️ PASSWORD EXPOSED! Found {breach_count:,} times in data breaches. "
                f"This password is known to attackers and should be changed immediately."
            )
        else:
            severity = "SECURE"
            description = (
                "✅ Password NOT found in any known data breaches. "
                "This doesn't guarantee safety, but it hasn't been publicly exposed."
            )

        return BreachResult(
            checked=True,
            breached=breach_count > 0,
            breach_count=breach_count,
            severity=severity,
            description=description,
            api_available=True,
            sha1_prefix=prefix,
        )

    except requests.exceptions.Timeout:
        return BreachResult(
            checked=False,
            breached=False,
            breach_count=0,
            severity="INFO",
            description="Breach check timed out — HIBP API may be slow",
            api_available=False,
            error_message="Connection timed out",
            sha1_prefix=prefix,
        )

    except requests.exceptions.ConnectionError:
        return BreachResult(
            checked=False,
            breached=False,
            breach_count=0,
            severity="INFO",
            description="Breach check unavailable — no internet connection",
            api_available=False,
            error_message="Connection failed",
            sha1_prefix=prefix,
        )

    except Exception as e:
        return BreachResult(
            checked=False,
            breached=False,
            breach_count=0,
            severity="INFO",
            description=f"Breach check failed: {str(e)}",
            api_available=False,
            error_message=str(e),
            sha1_prefix=prefix,
        )

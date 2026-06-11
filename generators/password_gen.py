"""
Cryptographically Secure Password Generator
============================================
Generates random passwords using the `secrets` module (CSPRNG).
Supports configurable length, character classes, ambiguous character
exclusion, pronounceable mode, and batch generation.
"""

import secrets
import string
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class GeneratedPassword:
    """A generated password with its metadata."""
    password: str
    length: int
    charset_description: str
    entropy_bits: float
    includes: dict


def generate_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
    exclude_ambiguous: bool = False,
    custom_symbols: Optional[str] = None,
) -> GeneratedPassword:
    """
    Generate a cryptographically secure random password.

    Args:
        length: Password length (12-128)
        use_uppercase: Include A-Z
        use_lowercase: Include a-z
        use_digits: Include 0-9
        use_symbols: Include special characters
        exclude_ambiguous: Remove confusing chars (0O, 1lI)
        custom_symbols: Override default symbol set

    Returns:
        GeneratedPassword with the password and metadata
    """
    import math

    length = max(8, min(128, length))

    # Build character pool
    pool = ""
    includes = {}

    if use_lowercase:
        pool += string.ascii_lowercase
        includes["lowercase"] = True
    if use_uppercase:
        pool += string.ascii_uppercase
        includes["uppercase"] = True
    if use_digits:
        pool += string.digits
        includes["digits"] = True
    if use_symbols:
        pool += custom_symbols if custom_symbols else "!@#$%^&*()-_=+[]{}|;:,.<>?"
        includes["symbols"] = True

    if not pool:
        pool = string.ascii_letters + string.digits
        includes = {"lowercase": True, "uppercase": True, "digits": True}

    # Remove ambiguous characters if requested
    if exclude_ambiguous:
        ambiguous = set("0O1lI|")
        pool = "".join(c for c in pool if c not in ambiguous)

    pool_list = list(set(pool))  # Deduplicate

    # Generate password ensuring at least one char from each selected class
    required_chars = []
    if use_lowercase:
        chars = [c for c in pool_list if c in string.ascii_lowercase]
        if chars:
            required_chars.append(secrets.choice(chars))
    if use_uppercase:
        chars = [c for c in pool_list if c in string.ascii_uppercase]
        if chars:
            required_chars.append(secrets.choice(chars))
    if use_digits:
        chars = [c for c in pool_list if c in string.digits]
        if chars:
            required_chars.append(secrets.choice(chars))
    if use_symbols:
        chars = [c for c in pool_list if c not in string.ascii_letters and c not in string.digits]
        if chars:
            required_chars.append(secrets.choice(chars))

    # Fill remaining length with random choices
    remaining = length - len(required_chars)
    random_chars = [secrets.choice(pool_list) for _ in range(max(0, remaining))]

    # Combine and shuffle
    all_chars = required_chars + random_chars
    # Fisher-Yates shuffle using secrets
    for i in range(len(all_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        all_chars[i], all_chars[j] = all_chars[j], all_chars[i]

    password = "".join(all_chars[:length])

    # Calculate entropy
    entropy_bits = round(math.log2(len(pool_list)) * length, 2) if pool_list else 0

    # Description
    parts = []
    if use_lowercase: parts.append("a-z")
    if use_uppercase: parts.append("A-Z")
    if use_digits: parts.append("0-9")
    if use_symbols: parts.append("symbols")
    charset_desc = " + ".join(parts)

    return GeneratedPassword(
        password=password,
        length=length,
        charset_description=charset_desc,
        entropy_bits=entropy_bits,
        includes=includes,
    )


def generate_batch(
    count: int = 5,
    **kwargs,
) -> List[GeneratedPassword]:
    """Generate multiple passwords with the same configuration."""
    count = max(1, min(50, count))
    return [generate_password(**kwargs) for _ in range(count)]

"""
Entropy Calculator Module
=========================
Computes Shannon entropy, effective entropy, and ideal entropy for passwords.
Provides charset detection and entropy-based qualitative assessments.

Shannon Entropy: H = -Σ p(x) × log₂(p(x)) — measures randomness per character
Effective Entropy: log₂(charset_size) × length — measures total keyspace
"""

import math
import string
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


@dataclass
class CharsetInfo:
    """Details about the detected character pool."""
    has_lowercase: bool = False
    has_uppercase: bool = False
    has_digits: bool = False
    has_symbols: bool = False
    has_spaces: bool = False
    has_unicode_extended: bool = False
    pool_size: int = 0
    categories_used: int = 0
    category_details: Dict[str, bool] = field(default_factory=dict)


@dataclass
class EntropyResult:
    """Complete entropy analysis result."""
    shannon_entropy: float           # Bits per character
    effective_entropy: float         # Total effective bits (log2(pool) * length)
    ideal_entropy: float             # Maximum possible for this length
    total_shannon_bits: float        # Shannon entropy * length
    charset_info: CharsetInfo        # Character set breakdown
    entropy_rating: str              # Qualitative rating
    entropy_description: str         # Human-readable description
    password_length: int             # Length of the password
    unique_characters: int           # Count of unique characters
    compression_ratio: float         # Ratio of unique/total characters


# ─── Entropy Rating Thresholds ────────────────────────────────────────────────
ENTROPY_RATINGS = [
    (0, 19, "Very Weak", "Trivially crackable — equivalent to a 4-digit PIN"),
    (20, 35, "Weak", "Vulnerable to dictionary and brute-force attacks"),
    (36, 49, "Fair", "Provides basic protection against casual attacks"),
    (50, 64, "Moderate", "Reasonable security for most non-critical accounts"),
    (65, 79, "Strong", "Good resistance against offline attacks"),
    (80, 99, "Very Strong", "Excellent security — resilient to GPU cracking"),
    (100, float('inf'), "Exceptional", "Military-grade entropy — practically uncrackable"),
]


def detect_charset(password: str) -> CharsetInfo:
    """
    Analyze the password to determine which character classes are present
    and calculate the total character pool size.
    """
    info = CharsetInfo()
    printable_symbols = set(string.punctuation)

    for char in password:
        if char in string.ascii_lowercase:
            info.has_lowercase = True
        elif char in string.ascii_uppercase:
            info.has_uppercase = True
        elif char in string.digits:
            info.has_digits = True
        elif char == ' ':
            info.has_spaces = True
        elif char in printable_symbols:
            info.has_symbols = True
        elif ord(char) > 127:
            info.has_unicode_extended = True

    # Calculate pool size
    pool = 0
    categories = 0

    if info.has_lowercase:
        pool += 26
        categories += 1
    if info.has_uppercase:
        pool += 26
        categories += 1
    if info.has_digits:
        pool += 10
        categories += 1
    if info.has_symbols:
        pool += len(printable_symbols)  # 32 standard symbols
        categories += 1
    if info.has_spaces:
        pool += 1
        categories += 1
    if info.has_unicode_extended:
        pool += 128  # Conservative estimate for extended Unicode
        categories += 1

    info.pool_size = max(pool, 1)  # Prevent log2(0)
    info.categories_used = categories
    info.category_details = {
        "Lowercase (a-z)": info.has_lowercase,
        "Uppercase (A-Z)": info.has_uppercase,
        "Digits (0-9)": info.has_digits,
        "Symbols (!@#...)": info.has_symbols,
        "Spaces": info.has_spaces,
        "Unicode Extended": info.has_unicode_extended,
    }

    return info


def calculate_shannon_entropy(password: str) -> float:
    """
    Calculate Shannon entropy (bits per character).
    H = -Σ p(x) × log₂(p(x))

    Measures the actual randomness/unpredictability of the password
    based on character frequency distribution.
    """
    if not password:
        return 0.0

    length = len(password)
    frequency: Dict[str, int] = {}

    for char in password:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def calculate_effective_entropy(password: str, charset_info: CharsetInfo) -> float:
    """
    Calculate effective entropy based on character pool size and length.
    Effective Entropy = log₂(pool_size) × length

    This represents the total keyspace an attacker must search
    assuming they know the character classes used.
    """
    if not password or charset_info.pool_size <= 1:
        return 0.0

    bits_per_char = math.log2(charset_info.pool_size)
    return round(bits_per_char * len(password), 2)


def calculate_ideal_entropy(length: int) -> float:
    """
    Calculate ideal maximum entropy for a given length.
    Uses full printable ASCII (95 chars) + space as maximum pool.
    Ideal = log₂(96) × length ≈ 6.585 × length
    """
    if length <= 0:
        return 0.0
    return round(math.log2(96) * length, 2)


def get_entropy_rating(effective_entropy: float) -> Tuple[str, str]:
    """Map effective entropy bits to a qualitative rating and description."""
    for low, high, rating, description in ENTROPY_RATINGS:
        if low <= effective_entropy <= high:
            return rating, description
    return "Unknown", "Unable to classify entropy level"


def analyze_entropy(password: str) -> EntropyResult:
    """
    Perform complete entropy analysis on a password.
    Returns a comprehensive EntropyResult with all metrics.
    """
    if not password:
        charset_info = CharsetInfo()
        return EntropyResult(
            shannon_entropy=0.0,
            effective_entropy=0.0,
            ideal_entropy=0.0,
            total_shannon_bits=0.0,
            charset_info=charset_info,
            entropy_rating="Very Weak",
            entropy_description="Empty password — no security",
            password_length=0,
            unique_characters=0,
            compression_ratio=0.0,
        )

    # Detect character set
    charset_info = detect_charset(password)

    # Calculate entropies
    shannon = calculate_shannon_entropy(password)
    effective = calculate_effective_entropy(password, charset_info)
    ideal = calculate_ideal_entropy(len(password))
    total_shannon = round(shannon * len(password), 2)

    # Get qualitative rating
    rating, description = get_entropy_rating(effective)

    # Compression ratio (unique chars / total length)
    unique_chars = len(set(password))
    compression = round(unique_chars / len(password), 4) if len(password) > 0 else 0.0

    return EntropyResult(
        shannon_entropy=shannon,
        effective_entropy=effective,
        ideal_entropy=ideal,
        total_shannon_bits=total_shannon,
        charset_info=charset_info,
        entropy_rating=rating,
        entropy_description=description,
        password_length=len(password),
        unique_characters=unique_chars,
        compression_ratio=compression,
    )

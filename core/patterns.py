"""
Pattern Detection Engine
========================
Advanced pattern detection with 15+ algorithms to identify weaknesses
in passwords: dictionary words, keyboard walks, sequences, l33t speak,
dates, repeated characters, palindromes, and more.

Each detected pattern returns a PatternMatch with type, severity,
description, position, and matched text for detailed reporting.
"""

import re
import string
from dataclasses import dataclass
from typing import List, Set, Optional
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import WORDLIST_DIR


@dataclass
class PatternMatch:
    """Represents a single detected pattern weakness."""
    pattern_type: str        # e.g., "Keyboard Walk", "Dictionary Word"
    severity: str            # CRITICAL, HIGH, MEDIUM, LOW
    description: str         # Human-readable explanation
    position: str            # Where in the password (e.g., "chars 1-5")
    matched_text: str        # The matched portion (masked for reports)
    penalty_weight: float    # Scoring penalty multiplier


# ─── Keyboard Layout Maps ────────────────────────────────────────────────────
QWERTY_ROWS = [
    "`1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./",
]

QWERTY_SHIFTED = [
    "~!@#$%^&*()_+",
    "QWERTYUIOP{}|",
    'ASDFGHJKL:"',
    "ZXCVBNM<>?",
]

# Build adjacency map for keyboard walks
def _build_adjacency_map() -> dict:
    """Build a map of which keys are adjacent on QWERTY keyboard."""
    adjacency = {}
    all_rows = QWERTY_ROWS + QWERTY_SHIFTED
    for rows in [QWERTY_ROWS, QWERTY_SHIFTED]:
        for row_idx, row in enumerate(rows):
            for col_idx, char in enumerate(row):
                neighbors = set()
                for dr in [-1, 0, 1]:
                    for dc in [-1, 0, 1]:
                        if dr == 0 and dc == 0:
                            continue
                        nr, nc = row_idx + dr, col_idx + dc
                        if 0 <= nr < len(rows) and 0 <= nc < len(rows[nr]):
                            neighbors.add(rows[nr][nc].lower())
                adjacency[char.lower()] = adjacency.get(char.lower(), set()) | neighbors
    return adjacency

ADJACENCY_MAP = _build_adjacency_map()

# ─── Common Keyboard Walk Patterns ───────────────────────────────────────────
KNOWN_KEYBOARD_WALKS = [
    "qwerty", "qwert", "qwer", "asdf", "asdfgh", "zxcv", "zxcvbn",
    "qazwsx", "1qaz2wsx", "qwertyuiop", "1234567890", "poiuytrewq",
    "lkjhgfdsa", "mnbvcxz", "zaq1", "xsw2", "cde3", "vfr4", "bgt5",
    "nhy6", "mju7", "ki8", "lo9", "p0", "1q2w3e4r", "1q2w3e",
    "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm",
    "asdfjkl", "qweasd", "zxcasd", "!@#$%", "!@#$%^", "!@#$%^&*",
]

# ─── L33t Speak Substitution Map ─────────────────────────────────────────────
LEET_MAP = {
    '0': 'o', '1': 'i', '2': 'z', '3': 'e', '4': 'a', '5': 's',
    '6': 'g', '7': 't', '8': 'b', '9': 'g', '@': 'a', '$': 's',
    '!': 'i', '|': 'l', '+': 't', '(': 'c', ')': 'c', '{': 'c',
    '}': 'c', '<': 'c', '>': 'c', '&': 'e',
}

# ─── Date Regex Patterns ─────────────────────────────────────────────────────
DATE_PATTERNS = [
    (r'\d{2}[-/]\d{2}[-/]\d{4}', "DD/MM/YYYY or MM/DD/YYYY"),
    (r'\d{4}[-/]\d{2}[-/]\d{2}', "YYYY-MM-DD (ISO)"),
    (r'\d{2}[-/]\d{2}[-/]\d{2}', "DD/MM/YY or MM/DD/YY"),
    (r'(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])', "YYYYMMDD"),
    (r'(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:19|20)\d{2}', "MMDDYYYY"),
    (r'(?:19|20)\d{2}', "Year (19xx/20xx)"),
]

# ─── Contextual Weakness Patterns ────────────────────────────────────────────
SEASON_WORDS = ["spring", "summer", "fall", "autumn", "winter"]
MONTH_WORDS = [
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
]

# ─── Wordlist Loaders ────────────────────────────────────────────────────────
_common_passwords_cache: Optional[Set[str]] = None
_english_words_cache: Optional[Set[str]] = None


def _load_wordlist(filename: str) -> Set[str]:
    """Load a wordlist file into a set (lowercase, stripped)."""
    filepath = WORDLIST_DIR / filename
    if not filepath.exists():
        return set()
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return {line.strip().lower() for line in f if line.strip()}
    except Exception:
        return set()


def get_common_passwords() -> Set[str]:
    """Load and cache common passwords wordlist."""
    global _common_passwords_cache
    if _common_passwords_cache is None:
        _common_passwords_cache = _load_wordlist("common_passwords.txt")
    return _common_passwords_cache


def get_english_words() -> Set[str]:
    """Load and cache English dictionary words."""
    global _english_words_cache
    if _english_words_cache is None:
        _english_words_cache = _load_wordlist("english_words.txt")
    return _english_words_cache


# ═══════════════════════════════════════════════════════════════════════════════
#  PATTERN DETECTION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

def detect_common_password(password: str) -> List[PatternMatch]:
    """Check if the password is in the top common passwords list."""
    matches = []
    common = get_common_passwords()
    if password.lower() in common:
        matches.append(PatternMatch(
            pattern_type="Common Password",
            severity="CRITICAL",
            description=f"This password appears in the most commonly used passwords database",
            position="entire password",
            matched_text=password[:2] + "*" * (len(password) - 2),
            penalty_weight=1.0,
        ))
    return matches


def detect_dictionary_words(password: str) -> List[PatternMatch]:
    """Detect English dictionary words embedded in the password."""
    matches = []
    words = get_english_words()
    pwd_lower = password.lower()

    # Check for whole-word matches (minimum 4 chars to avoid false positives)
    for word_len in range(min(len(pwd_lower), 12), 3, -1):
        for start in range(len(pwd_lower) - word_len + 1):
            substring = pwd_lower[start:start + word_len]
            if substring in words and len(substring) >= 4:
                # Avoid duplicate matches for overlapping substrings
                already_matched = False
                for m in matches:
                    if substring in m.matched_text.lower() or m.matched_text.lower() in substring:
                        already_matched = True
                        break
                if not already_matched:
                    severity = "HIGH" if len(substring) >= 6 else "MEDIUM"
                    matches.append(PatternMatch(
                        pattern_type="Dictionary Word",
                        severity=severity,
                        description=f"Contains dictionary word '{substring}' (vulnerable to dictionary attacks)",
                        position=f"chars {start + 1}-{start + word_len}",
                        matched_text=substring,
                        penalty_weight=0.8 if len(substring) >= 6 else 0.5,
                    ))
    return matches[:3]  # Limit to top 3 matches


def detect_keyboard_walks(password: str) -> List[PatternMatch]:
    """Detect QWERTY keyboard walk patterns."""
    matches = []
    pwd_lower = password.lower()

    # Check against known keyboard walk patterns
    for walk in KNOWN_KEYBOARD_WALKS:
        if walk in pwd_lower:
            matches.append(PatternMatch(
                pattern_type="Keyboard Walk",
                severity="HIGH",
                description=f"Contains keyboard walk pattern '{walk}' (easily guessable)",
                position=f"chars {pwd_lower.index(walk) + 1}-{pwd_lower.index(walk) + len(walk)}",
                matched_text=walk,
                penalty_weight=0.8,
            ))
            break  # One keyboard walk detection is enough

    # Check for adjacent-key sequences (4+ consecutive adjacent keys)
    if not matches:
        consecutive = 1
        start_pos = 0
        for i in range(1, len(pwd_lower)):
            if pwd_lower[i - 1] in ADJACENCY_MAP and pwd_lower[i] in ADJACENCY_MAP.get(pwd_lower[i - 1], set()):
                consecutive += 1
            else:
                if consecutive >= 4:
                    walk_text = pwd_lower[start_pos:start_pos + consecutive]
                    matches.append(PatternMatch(
                        pattern_type="Keyboard Walk",
                        severity="MEDIUM",
                        description=f"Contains {consecutive}-key keyboard adjacency pattern",
                        position=f"chars {start_pos + 1}-{start_pos + consecutive}",
                        matched_text=walk_text,
                        penalty_weight=0.6,
                    ))
                consecutive = 1
                start_pos = i
        # Check trailing sequence
        if consecutive >= 4:
            walk_text = pwd_lower[start_pos:start_pos + consecutive]
            matches.append(PatternMatch(
                pattern_type="Keyboard Walk",
                severity="MEDIUM",
                description=f"Contains {consecutive}-key keyboard adjacency pattern",
                position=f"chars {start_pos + 1}-{start_pos + consecutive}",
                matched_text=walk_text,
                penalty_weight=0.6,
            ))

    return matches[:2]


def detect_sequential_chars(password: str) -> List[PatternMatch]:
    """Detect sequential character patterns (abc, 123, xyz, etc.)."""
    matches = []

    # Check for ascending/descending sequences of 3+ chars
    for direction_name, step in [("ascending", 1), ("descending", -1)]:
        consecutive = 1
        start_pos = 0
        for i in range(1, len(password)):
            if ord(password[i]) == ord(password[i - 1]) + step:
                consecutive += 1
            else:
                if consecutive >= 3:
                    seq_text = password[start_pos:start_pos + consecutive]
                    severity = "HIGH" if consecutive >= 5 else "MEDIUM"
                    matches.append(PatternMatch(
                        pattern_type="Sequential Characters",
                        severity=severity,
                        description=f"Contains {consecutive}-char {direction_name} sequence '{seq_text}'",
                        position=f"chars {start_pos + 1}-{start_pos + consecutive}",
                        matched_text=seq_text,
                        penalty_weight=0.7 if consecutive >= 5 else 0.4,
                    ))
                consecutive = 1
                start_pos = i
        # Check trailing
        if consecutive >= 3:
            seq_text = password[start_pos:start_pos + consecutive]
            severity = "HIGH" if consecutive >= 5 else "MEDIUM"
            matches.append(PatternMatch(
                pattern_type="Sequential Characters",
                severity=severity,
                description=f"Contains {consecutive}-char {direction_name} sequence",
                position=f"chars {start_pos + 1}-{start_pos + consecutive}",
                matched_text=seq_text,
                penalty_weight=0.7 if consecutive >= 5 else 0.4,
            ))

    return matches[:2]


def detect_repeated_chars(password: str) -> List[PatternMatch]:
    """Detect runs of repeated characters (aaa, 111, etc.)."""
    matches = []
    i = 0
    while i < len(password):
        run_length = 1
        while i + run_length < len(password) and password[i + run_length] == password[i]:
            run_length += 1
        if run_length >= 3:
            severity = "HIGH" if run_length >= 5 else "MEDIUM"
            matches.append(PatternMatch(
                pattern_type="Repeated Characters",
                severity=severity,
                description=f"Contains '{password[i]}' repeated {run_length} times",
                position=f"chars {i + 1}-{i + run_length}",
                matched_text=password[i] * min(run_length, 5) + ("..." if run_length > 5 else ""),
                penalty_weight=0.6 if run_length >= 5 else 0.3,
            ))
        i += run_length

    return matches[:3]


def detect_leet_speak(password: str) -> List[PatternMatch]:
    """
    Decode l33t speak substitutions and check if the decoded version
    matches dictionary words or common passwords.
    """
    matches = []

    # Check if the password actually uses any l33t substitutions
    has_leet = any(c in LEET_MAP for c in password)
    if not has_leet:
        return matches

    # Decode l33t speak
    decoded = ""
    for char in password.lower():
        decoded += LEET_MAP.get(char, char)

    # Check decoded against common passwords
    common = get_common_passwords()
    if decoded in common:
        matches.append(PatternMatch(
            pattern_type="L33t Speak (Common Password)",
            severity="CRITICAL",
            description=f"L33t-decoded password '{decoded}' is a common password",
            position="entire password",
            matched_text=f"{password[:3]}... → {decoded[:3]}...",
            penalty_weight=1.0,
        ))
        return matches

    # Check decoded against dictionary words (4+ chars)
    words = get_english_words()
    for word_len in range(min(len(decoded), 10), 3, -1):
        for start in range(len(decoded) - word_len + 1):
            substring = decoded[start:start + word_len]
            if substring in words and len(substring) >= 4:
                matches.append(PatternMatch(
                    pattern_type="L33t Speak",
                    severity="HIGH",
                    description=f"L33t substitution decodes to dictionary word '{substring}'",
                    position=f"chars {start + 1}-{start + word_len}",
                    matched_text=f"...→ {substring}",
                    penalty_weight=0.7,
                ))
                return matches[:1]  # One match is enough

    return matches


def detect_date_patterns(password: str) -> List[PatternMatch]:
    """Detect date patterns embedded in the password."""
    matches = []

    for pattern, pattern_name in DATE_PATTERNS:
        found = re.finditer(pattern, password)
        for match in found:
            matched_text = match.group()
            start = match.start()

            # Skip 4-digit years if they're part of a longer number sequence
            if pattern_name == "Year (19xx/20xx)" and len(password) > 4:
                # Check if surrounded by more digits
                before = password[start - 1] if start > 0 else ' '
                after = password[start + 4] if start + 4 < len(password) else ' '
                if before.isdigit() or after.isdigit():
                    continue

            matches.append(PatternMatch(
                pattern_type="Date Pattern",
                severity="MEDIUM",
                description=f"Contains date-like pattern ({pattern_name}): {matched_text}",
                position=f"chars {start + 1}-{start + len(matched_text)}",
                matched_text=matched_text,
                penalty_weight=0.4,
            ))
            break  # One match per pattern type is enough

    return matches[:2]


def detect_phone_number(password: str) -> List[PatternMatch]:
    """Detect phone number patterns."""
    matches = []
    phone_patterns = [
        r'\d{3}[-.]?\d{3}[-.]?\d{4}',       # US: 123-456-7890
        r'\+\d{1,3}\d{10}',                   # International: +921234567890
        r'\(\d{3}\)\s?\d{3}[-.]?\d{4}',       # (123) 456-7890
        r'\d{10,11}',                          # Raw 10-11 digit number
    ]

    for pattern in phone_patterns:
        match = re.search(pattern, password)
        if match:
            matches.append(PatternMatch(
                pattern_type="Phone Number",
                severity="HIGH",
                description="Contains what appears to be a phone number (personal info risk)",
                position=f"chars {match.start() + 1}-{match.end()}",
                matched_text=match.group()[:3] + "***" + match.group()[-2:],
                penalty_weight=0.7,
            ))
            break

    return matches


def detect_email_fragment(password: str) -> List[PatternMatch]:
    """Detect email-like patterns in the password."""
    matches = []
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    match = re.search(email_pattern, password)
    if match:
        matches.append(PatternMatch(
            pattern_type="Email Fragment",
            severity="HIGH",
            description="Contains an email address (easily discoverable personal info)",
            position=f"chars {match.start() + 1}-{match.end()}",
            matched_text=match.group()[:4] + "***@***",
            penalty_weight=0.7,
        ))
    return matches


def detect_palindrome(password: str) -> List[PatternMatch]:
    """Detect palindrome patterns (mirror sequences)."""
    matches = []
    pwd_lower = password.lower()

    # Check if entire password is a palindrome (min 4 chars)
    if len(pwd_lower) >= 4 and pwd_lower == pwd_lower[::-1]:
        matches.append(PatternMatch(
            pattern_type="Palindrome",
            severity="MEDIUM",
            description="Entire password is a palindrome (mirror pattern reduces entropy)",
            position="entire password",
            matched_text=pwd_lower[:4] + "...",
            penalty_weight=0.5,
        ))
        return matches

    # Check for palindromic substrings (6+ chars)
    for length in range(min(len(pwd_lower), 12), 5, -1):
        for start in range(len(pwd_lower) - length + 1):
            sub = pwd_lower[start:start + length]
            if sub == sub[::-1]:
                matches.append(PatternMatch(
                    pattern_type="Palindrome",
                    severity="LOW",
                    description=f"Contains {length}-char palindrome pattern",
                    position=f"chars {start + 1}-{start + length}",
                    matched_text=sub,
                    penalty_weight=0.3,
                ))
                return matches  # One is enough

    return matches


def detect_shifted_pattern(password: str) -> List[PatternMatch]:
    """Detect patterns that are the same keys but with Shift held (e.g., !@#$%)."""
    matches = []

    # Map shifted symbols to their base keys
    shift_map = {
        '!': '1', '@': '2', '#': '3', '$': '4', '%': '5',
        '^': '6', '&': '7', '*': '8', '(': '9', ')': '0',
        '_': '-', '+': '=', '{': '[', '}': ']', '|': '\\',
        ':': ';', '"': "'", '<': ',', '>': '.', '?': '/',
        '~': '`',
    }

    # Decode shifted chars
    decoded = ""
    shift_count = 0
    for char in password:
        if char in shift_map:
            decoded += shift_map[char]
            shift_count += 1
        else:
            decoded += char

    # If most of the password is shifted, check the decoded version
    if shift_count >= 3 and shift_count >= len(password) * 0.5:
        # Check if decoded version is a simple sequence
        is_sequential = all(
            ord(decoded[i]) == ord(decoded[i - 1]) + 1
            for i in range(1, len(decoded))
        ) if len(decoded) > 1 else False

        if is_sequential or decoded.isdigit():
            matches.append(PatternMatch(
                pattern_type="Shifted Pattern",
                severity="MEDIUM",
                description=f"Shifted keyboard pattern detected (decoded: {decoded})",
                position="entire password",
                matched_text=password[:4] + "...",
                penalty_weight=0.5,
            ))

    return matches


def detect_repeating_bigrams(password: str) -> List[PatternMatch]:
    """Detect repeating 2-character pairs (abab, 1212, etc.)."""
    matches = []

    if len(password) < 4:
        return matches

    pwd_lower = password.lower()

    for i in range(len(pwd_lower) - 3):
        bigram = pwd_lower[i:i + 2]
        if bigram[0] == bigram[1]:  # Skip same-char bigrams (handled by repeat detection)
            continue
        repeat_count = 0
        pos = i
        while pos + 1 < len(pwd_lower) and pwd_lower[pos:pos + 2] == bigram:
            repeat_count += 1
            pos += 2
        if repeat_count >= 2:
            matched = bigram * repeat_count
            matches.append(PatternMatch(
                pattern_type="Repeating Bigram",
                severity="MEDIUM",
                description=f"Contains repeating 2-char pattern '{bigram}' × {repeat_count}",
                position=f"chars {i + 1}-{i + len(matched)}",
                matched_text=matched,
                penalty_weight=0.4,
            ))
            break

    return matches


def detect_common_substitutions(password: str) -> List[PatternMatch]:
    """Detect well-known password patterns with common substitutions."""
    matches = []

    # Known base patterns that people commonly substitute
    known_bases = [
        "password", "admin", "welcome", "login", "master",
        "access", "security", "letmein", "monkey", "dragon",
        "shadow", "sunshine", "princess", "football", "baseball",
        "soccer", "hockey", "batman", "trustno", "mustang",
    ]

    pwd_lower = password.lower()
    # Decode l33t speak for comparison
    decoded = ""
    for char in pwd_lower:
        decoded += LEET_MAP.get(char, char)

    for base in known_bases:
        if base in decoded and base not in pwd_lower:
            matches.append(PatternMatch(
                pattern_type="Common Substitution",
                severity="HIGH",
                description=f"Common password '{base}' detected through character substitutions",
                position="entire password",
                matched_text=f"→ {base}",
                penalty_weight=0.8,
            ))
            break

    return matches


def detect_contextual_weakness(password: str) -> List[PatternMatch]:
    """Detect contextual patterns like season+year, month+year."""
    matches = []
    pwd_lower = password.lower()

    # Season + year patterns
    for season in SEASON_WORDS:
        if season in pwd_lower:
            # Check if followed or preceded by a year
            year_match = re.search(r'(?:19|20)\d{2}', pwd_lower)
            if year_match:
                matches.append(PatternMatch(
                    pattern_type="Contextual Weakness",
                    severity="HIGH",
                    description=f"Contains season+year pattern ('{season}' + year) — extremely common",
                    position="entire password",
                    matched_text=f"{season}+{year_match.group()}",
                    penalty_weight=0.8,
                ))
                return matches

    # Month + year patterns
    for month in MONTH_WORDS:
        if month in pwd_lower:
            year_match = re.search(r'(?:19|20)\d{2}', pwd_lower)
            if year_match:
                matches.append(PatternMatch(
                    pattern_type="Contextual Weakness",
                    severity="MEDIUM",
                    description=f"Contains month+year pattern ('{month}' + year) — predictable",
                    position="entire password",
                    matched_text=f"{month}+{year_match.group()}",
                    penalty_weight=0.5,
                ))
                return matches

    return matches


# ═══════════════════════════════════════════════════════════════════════════════
#  MASTER PATTERN ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_patterns(password: str) -> List[PatternMatch]:
    """
    Run all pattern detection algorithms against the password.
    Returns a sorted list of all detected pattern weaknesses.
    """
    if not password:
        return [PatternMatch(
            pattern_type="Empty Password",
            severity="CRITICAL",
            description="No password provided",
            position="N/A",
            matched_text="(empty)",
            penalty_weight=1.0,
        )]

    all_matches: List[PatternMatch] = []

    # Run all detectors (ordered by severity importance)
    detectors = [
        detect_common_password,
        detect_dictionary_words,
        detect_keyboard_walks,
        detect_leet_speak,
        detect_common_substitutions,
        detect_contextual_weakness,
        detect_sequential_chars,
        detect_repeated_chars,
        detect_date_patterns,
        detect_phone_number,
        detect_email_fragment,
        detect_palindrome,
        detect_shifted_pattern,
        detect_repeating_bigrams,
    ]

    for detector in detectors:
        try:
            results = detector(password)
            all_matches.extend(results)
        except Exception:
            continue  # Skip failing detectors gracefully

    # Sort by severity (CRITICAL first)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_matches.sort(key=lambda m: severity_order.get(m.severity, 4))

    return all_matches

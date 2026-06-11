"""
Personal Password Auditor — Global Configuration & Constants
=============================================================
Centralized configuration for scoring weights, attack scenario speeds,
policy presets (NIST/OWASP/PCI-DSS), hash algorithm registry, and UI theming.
"""

import os
from pathlib import Path

# ─── Project Paths ──────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
WORDLIST_DIR = BASE_DIR / "wordlists"
REPORTS_DIR = BASE_DIR / "reports"
TEMPLATE_DIR = BASE_DIR / "reporting" / "templates"

# Ensure output directories exist
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# ─── Application Metadata ──────────────────────────────────────────────────────
APP_NAME = "Personal Password Auditor"
APP_VERSION = "1.0.0"
APP_AUTHOR = "Rizwan Khan"
APP_BANNER = r"""
  ╔══════════════════════════════════════════════════════════════════╗
  ║   ____                                     _                   ║
  ║  |  _ \ __ _ ___ _____      _____  _ __ __| |                  ║
  ║  | |_) / _` / __/ __\ \ /\ / / _ \| '__/ _` |                  ║
  ║  |  __/ (_| \__ \__ \\ V  V / (_) | | | (_| |                  ║
  ║  |_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_|                  ║
  ║                                                                ║
  ║      _              _ _ _                                      ║
  ║     / \  _   _  __| (_) |_  ___  _ __                          ║
  ║    / _ \| | | |/ _` | | __|/ _ \| '__|                         ║
  ║   / ___ \ |_| | (_| | | |_| (_) | |                            ║
  ║  /_/   \_\__,_|\__,_|_|\__|\___/|_|                            ║
  ║                                                                ║
  ║          🔐 Personal Password Auditor v1.0.0                   ║
  ║          ─── Rizwan Khan ───                    ║
  ╚══════════════════════════════════════════════════════════════════╝
"""

# ─── Strength Scoring Weights ──────────────────────────────────────────────────
# Total possible: 100 points (before penalties)
SCORING_WEIGHTS = {
    "length": {
        "max_points": 25,
        "thresholds": [
            (8, 5), (10, 8), (12, 12), (14, 15),
            (16, 18), (20, 22), (24, 25),
        ],
    },
    "diversity": {
        "max_points": 20,
        "categories": {
            "lowercase": 4,
            "uppercase": 4,
            "digits": 4,
            "symbols": 5,
            "unicode_extended": 3,
        },
    },
    "entropy_bonus": {
        "max_points": 20,
        "thresholds": [
            (20, 2), (30, 5), (40, 8), (50, 12),
            (60, 15), (70, 18), (80, 20),
        ],
    },
    "policy_compliance_bonus": {
        "max_points": 15,
        "per_standard": 5,  # 5 pts per standard passed (NIST, OWASP, PCI-DSS)
    },
}

# Penalties
SCORING_PENALTIES = {
    "pattern_detected": {
        "CRITICAL": -15,
        "HIGH": -10,
        "MEDIUM": -5,
        "LOW": -2,
    },
    "max_pattern_penalty": -30,
    "breach_detected": -40,
    "common_password": -35,
}

# Grade Mapping
GRADE_MAP = [
    (95, "A+", "Exceptional"),
    (85, "A", "Excellent"),
    (70, "B", "Good"),
    (55, "C", "Fair"),
    (40, "D", "Weak"),
    (0, "F", "Critical"),
]

# ─── Attack Scenario Speeds (guesses per second) ──────────────────────────────
ATTACK_SCENARIOS = {
    "online_throttled": {
        "name": "Online Attack (Rate Limited)",
        "speed": 100 / 3600,  # 100 per hour
        "description": "Login form with rate limiting & CAPTCHA",
        "icon": "🌐",
    },
    "online_unthrottled": {
        "name": "Online Attack (No Rate Limit)",
        "speed": 10,  # 10 per second
        "description": "Web service without brute-force protection",
        "icon": "⚡",
    },
    "offline_slow_hash": {
        "name": "Offline Attack (Slow Hash)",
        "speed": 1e4,  # 10,000 per second
        "description": "bcrypt/Argon2 hash cracking on single machine",
        "icon": "🖥️",
    },
    "offline_fast_hash": {
        "name": "Offline Attack (Fast Hash)",
        "speed": 1e10,  # 10 billion per second
        "description": "MD5/SHA unsalted hash cracking with GPU",
        "icon": "🔥",
    },
    "gpu_cluster": {
        "name": "GPU Cluster Attack",
        "speed": 1e13,  # 10 trillion per second
        "description": "Dedicated cracking rig (e.g., Hashcat cluster)",
        "icon": "💀",
    },
}

# ─── Hash Algorithm Registry ──────────────────────────────────────────────────
HASH_ALGORITHMS = {
    "MD5": {
        "security": "BROKEN",
        "color": "red",
        "description": "Cryptographically broken — vulnerable to collision attacks",
        "recommendation": "Never use for password storage",
    },
    "SHA-1": {
        "security": "BROKEN",
        "color": "red",
        "description": "Cryptographically broken — practical collision attacks demonstrated",
        "recommendation": "Migrate to SHA-256 or SHA-3 immediately",
    },
    "SHA-256": {
        "security": "WEAK",
        "color": "yellow",
        "description": "Secure hash but too fast for password storage (no key stretching)",
        "recommendation": "Use bcrypt or Argon2 for password storage",
    },
    "SHA-512": {
        "security": "WEAK",
        "color": "yellow",
        "description": "Secure hash but lacks built-in salting and key stretching",
        "recommendation": "Use bcrypt or Argon2 for password storage",
    },
    "SHA-3-256": {
        "security": "ACCEPTABLE",
        "color": "cyan",
        "description": "Modern hash standard (Keccak) — resistant to length extension",
        "recommendation": "Acceptable for integrity checks; use Argon2 for passwords",
    },
    "BLAKE2b": {
        "security": "ACCEPTABLE",
        "color": "cyan",
        "description": "High-performance secure hash — faster than MD5 yet secure",
        "recommendation": "Great for integrity; use Argon2 for password storage",
    },
    "bcrypt": {
        "security": "RECOMMENDED",
        "color": "green",
        "description": "Adaptive hash with built-in salting and configurable cost factor",
        "recommendation": "Excellent choice for password storage",
    },
    "Argon2id": {
        "security": "RECOMMENDED",
        "color": "green",
        "description": "Winner of Password Hashing Competition — memory-hard and GPU-resistant",
        "recommendation": "Gold standard for password storage (OWASP recommended)",
    },
}

# ─── Policy Presets ────────────────────────────────────────────────────────────
POLICY_PRESETS = {
    "nist": {
        "name": "NIST SP 800-63B Rev 4",
        "standard_id": "NIST SP 800-63B",
        "version": "Revision 4 (2024)",
        "rules": {
            "min_length": 8,
            "max_length": 64,
            "require_uppercase": False,
            "require_lowercase": False,
            "require_digits": False,
            "require_symbols": False,
            "require_breach_check": True,
            "require_blocklist_check": True,
            "allow_spaces": True,
            "allow_unicode": True,
            "no_forced_rotation": True,
            "no_composition_rules": True,
            "no_truncation": True,
            "no_password_hints": True,
        },
        "description": "Modern risk-based approach — emphasizes length over complexity",
    },
    "owasp": {
        "name": "OWASP ASVS v4.0",
        "standard_id": "OWASP ASVS",
        "version": "v4.0.3",
        "rules": {
            "min_length": 12,
            "max_length": 128,
            "require_uppercase": False,
            "require_lowercase": False,
            "require_digits": False,
            "require_symbols": False,
            "require_breach_check": True,
            "require_blocklist_check": True,
            "allow_spaces": True,
            "allow_unicode": True,
            "no_forced_rotation": True,
            "no_composition_rules": True,
            "no_truncation": True,
            "no_password_hints": True,
        },
        "description": "Application security standard — strict length requirements",
    },
    "pci_dss": {
        "name": "PCI-DSS v4.0",
        "standard_id": "PCI-DSS",
        "version": "v4.0 (2024)",
        "rules": {
            "min_length": 12,
            "max_length": 128,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digits": True,
            "require_symbols": False,
            "require_breach_check": False,
            "require_blocklist_check": True,
            "allow_spaces": True,
            "allow_unicode": True,
            "no_forced_rotation": False,  # PCI-DSS still allows rotation
            "no_composition_rules": False,  # PCI-DSS still requires complexity
            "no_truncation": True,
            "no_password_hints": True,
        },
        "description": "Payment card industry standard — balance of legacy and modern",
    },
}

# ─── Breach Check Configuration ───────────────────────────────────────────────
HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
HIBP_TIMEOUT = 5  # seconds
HIBP_RATE_LIMIT_DELAY = 1.6  # seconds between requests (comply with 1 req/1.5s)

# ─── UI Theme Colors ──────────────────────────────────────────────────────────
THEME = {
    "primary": "#00d4ff",       # Cyber Cyan
    "success": "#00ff88",       # Neon Green
    "warning": "#ffaa00",       # Alert Orange
    "danger": "#ff3366",        # Threat Crimson
    "info": "#7c3aed",          # Purple
    "background": "#0a0e17",    # Deep Space
    "surface": "#111827",       # Panel Dark
    "text": "#e5e7eb",          # Light Gray
    "muted": "#6b7280",         # Muted Gray
    "border": "#1f2937",        # Border Dark
    "grade_colors": {
        "A+": "#00ff88",
        "A": "#00d4ff",
        "B": "#38bdf8",
        "C": "#ffaa00",
        "D": "#f97316",
        "F": "#ff3366",
    },
}

# ─── Character Sets ───────────────────────────────────────────────────────────
CHARSETS = {
    "lowercase": "abcdefghijklmnopqrstuvwxyz",
    "uppercase": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "digits": "0123456789",
    "symbols": "!@#$%^&*()-_=+[]{}|;:'\",.<>?/`~\\",
    "ambiguous": "0O1lI",
    "spaces": " ",
}

# ─── Severity Levels ──────────────────────────────────────────────────────────
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEVERITY_COLORS = {
    "CRITICAL": "bright_red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
    "SECURE": "bright_green",
}

# ─── Risk Rating Thresholds ───────────────────────────────────────────────────
RISK_RATINGS = [
    (0, 19, "CRITICAL", "Immediately compromisable"),
    (20, 39, "HIGH", "Easily crackable with basic tools"),
    (40, 54, "MEDIUM", "Vulnerable to targeted attacks"),
    (55, 69, "LOW", "Reasonable security with improvements needed"),
    (70, 84, "MODERATE", "Good security posture"),
    (85, 100, "SECURE", "Excellent password security"),
]

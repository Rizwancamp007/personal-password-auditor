"""
Multi-Algorithm Hash Analyzer
==============================
Generates password hashes across 8 algorithms and provides security
assessments for each based on current cryptographic standards.
"""

import hashlib
import sys
from pathlib import Path
from dataclasses import dataclass
from typing import List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import HASH_ALGORITHMS

try:
    import bcrypt as bcrypt_lib
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

try:
    from argon2 import PasswordHasher
    HAS_ARGON2 = True
except ImportError:
    HAS_ARGON2 = False


@dataclass
class HashEntry:
    """A single hash output with security metadata."""
    algorithm: str
    hash_value: str
    security_rating: str
    color: str
    description: str
    recommendation: str
    truncated: bool = False


@dataclass
class HashAnalysisResult:
    """Complete hash analysis across all algorithms."""
    hashes: List[HashEntry]
    recommended_algorithm: str
    storage_advice: str
    total_algorithms: int


def analyze_hashes(password: str) -> HashAnalysisResult:
    """Generate hashes across all supported algorithms with security assessment."""
    if not password:
        return HashAnalysisResult(hashes=[], recommended_algorithm="N/A",
                                  storage_advice="Cannot hash empty password", total_algorithms=0)

    entries: List[HashEntry] = []

    # Built-in hashlib algorithms
    builtin = [
        ("MD5", lambda p: hashlib.md5(p.encode()).hexdigest()),
        ("SHA-1", lambda p: hashlib.sha1(p.encode()).hexdigest()),
        ("SHA-256", lambda p: hashlib.sha256(p.encode()).hexdigest()),
        ("SHA-512", lambda p: hashlib.sha512(p.encode()).hexdigest()),
        ("SHA-3-256", lambda p: hashlib.sha3_256(p.encode()).hexdigest()),
        ("BLAKE2b", lambda p: hashlib.blake2b(p.encode()).hexdigest()),
    ]

    for algo_name, hash_func in builtin:
        try:
            hv = hash_func(password)
            info = HASH_ALGORITHMS.get(algo_name, {})
            entries.append(HashEntry(
                algorithm=algo_name, hash_value=hv,
                security_rating=info.get("security", "UNKNOWN"),
                color=info.get("color", "white"),
                description=info.get("description", ""),
                recommendation=info.get("recommendation", ""),
                truncated=len(hv) > 64,
            ))
        except Exception:
            continue

    # bcrypt
    if HAS_BCRYPT:
        try:
            salt = bcrypt_lib.gensalt(rounds=12)
            hv = bcrypt_lib.hashpw(password.encode(), salt).decode()
            info = HASH_ALGORITHMS["bcrypt"]
            entries.append(HashEntry(algorithm="bcrypt", hash_value=hv,
                security_rating=info["security"], color=info["color"],
                description=info["description"], recommendation=info["recommendation"]))
        except Exception:
            pass
    else:
        info = HASH_ALGORITHMS["bcrypt"]
        entries.append(HashEntry(algorithm="bcrypt",
            hash_value="(not available — pip install bcrypt)",
            security_rating=info["security"], color=info["color"],
            description=info["description"], recommendation=info["recommendation"]))

    # Argon2id
    if HAS_ARGON2:
        try:
            ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4,
                                hash_len=32, salt_len=16)
            hv = ph.hash(password)
            info = HASH_ALGORITHMS["Argon2id"]
            entries.append(HashEntry(algorithm="Argon2id", hash_value=hv,
                security_rating=info["security"], color=info["color"],
                description=info["description"], recommendation=info["recommendation"]))
        except Exception:
            pass
    else:
        info = HASH_ALGORITHMS["Argon2id"]
        entries.append(HashEntry(algorithm="Argon2id",
            hash_value="(not available — pip install argon2-cffi)",
            security_rating=info["security"], color=info["color"],
            description=info["description"], recommendation=info["recommendation"]))

    recommended = "Argon2id" if HAS_ARGON2 else ("bcrypt" if HAS_BCRYPT else "Argon2id (install required)")
    advice = ("Use Argon2id for password storage (OWASP gold standard). "
              "Memory-hard, GPU-resistant, PHC winner. "
              "Never use MD5/SHA-1/unsalted SHA-256 for passwords.")

    return HashAnalysisResult(hashes=entries, recommended_algorithm=recommended,
                              storage_advice=advice, total_algorithms=len(entries))

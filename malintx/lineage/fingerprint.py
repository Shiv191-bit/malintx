"""Hash-free behavioural fingerprints.

An APK's file hash changes with every re-sign or recompile, and class/method names are trivially obfuscated.
Framework API names cannot be renamed: `SmsManager.sendTextMessage` is the same call in every variant. We
therefore fingerprint the *set of framework APIs the app's own (non-library) code calls* with MinHash, which
estimates the Jaccard similarity of two such sets from a small fixed-size sketch.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Iterable

import numpy as np

K = 128
_RNG = random.Random(0x4D414C494E54)  # noqa: S311 - fixed seed on purpose: reproducible hash constants, not cryptography
_A = np.array([_RNG.getrandbits(64) | 1 for _ in range(K)], dtype=np.uint64)  # odd multipliers
_B = np.array([_RNG.getrandbits(64) for _ in range(K)], dtype=np.uint64)
_EMPTY = "0" * 16 * K


def _h64(item: str) -> int:
    return int.from_bytes(hashlib.blake2b(item.encode("utf-8"), digest_size=8).digest(), "little")


def minhash(items: Iterable[str]) -> str:
    """K-slot MinHash sketch as a hex string (16 hex chars per slot). Empty input → all-zero sketch."""
    hashes = np.fromiter((_h64(i) for i in set(items)), dtype=np.uint64)
    if hashes.size == 0:
        return _EMPTY
    with np.errstate(over="ignore"):  # uint64 wrap-around is the intended arithmetic
        mins = np.full(K, np.iinfo(np.uint64).max, dtype=np.uint64)
        for chunk in np.array_split(hashes, max(1, hashes.size // 4096)):
            mins = np.minimum(mins, (_A[:, None] * chunk[None, :] + _B[:, None]).min(axis=1))
    return "".join(f"{int(v):016x}" for v in mins)


def similarity(a: str, b: str) -> float | None:
    """Estimated Jaccard similarity of the two underlying sets (None if either sketch is empty)."""
    if a == _EMPTY or b == _EMPTY or len(a) != len(b) or len(a) != 16 * K:
        return None
    same = sum(1 for i in range(0, 16 * K, 16) if a[i:i + 16] == b[i:i + 16])
    return round(same / K, 4)


def exact_jaccard(a: set[str], b: set[str]) -> float:
    return len(a & b) / len(a | b) if (a | b) else 0.0


def set_similarity(a: Iterable[str], b: Iterable[str]) -> float | None:
    sa, sb = set(a), set(b)
    return None if not sa and not sb else round(exact_jaccard(sa, sb), 4)

"""Empirical byte statistics. Offsets are zero-based file offsets."""

from collections.abc import Iterator

import numpy as np
from scipy.stats import chi2


def histogram(data: bytes | memoryview) -> np.ndarray:
    samples = np.frombuffer(data, dtype=np.uint8)
    counts = np.zeros(256, dtype=np.int64)
    for start in range(0, len(samples), 1 << 20):
        counts += np.bincount(samples[start : start + (1 << 20)], minlength=256)
    return counts


def entropy_from_counts(counts: np.ndarray) -> float:
    occupied = counts[counts > 0]
    if occupied.size <= 1:
        return 0.0
    p = occupied / occupied.sum()
    return float(np.clip(-np.dot(p, np.log2(p)), 0, 8))


def shannon_entropy(data: bytes | memoryview) -> float:
    return entropy_from_counts(histogram(data))


def sliding_entropy(data: bytes, window: int = 1024, step: int = 256) -> Iterator[dict]:
    """Full windows plus one end-aligned window; one short window for short data."""
    if window <= 0 or step <= 0:
        raise ValueError("window and step must be positive")
    if not data:
        return
    end = max(0, len(data) - window)
    count = 1 + (end + step - 1) // step
    if count > 250_000 or count * min(window, len(data)) > 512 * 1024**2:
        raise ValueError("profile budget exceeded; increase --step or reduce --window")
    view = memoryview(data)
    for i in range(count):
        start = min(i * step, end)
        yield {
            "offset": start,
            "entropy": shannon_entropy(view[start : start + window]),
        }


def uniformity(counts: np.ndarray) -> dict:
    """Pearson goodness of fit with 255 degrees of freedom; p is asymptotic."""
    expected = float(counts.sum()) / 256
    stat = float(np.sum((counts - expected) ** 2) / expected) if expected else None
    return {
        "statistic": stat,
        "df": 255,
        "p_value": float(chi2.sf(stat, 255)) if expected >= 5 else None,
        "expected_per_bin": expected,
    }


def monte_carlo_pi(data: bytes) -> dict:
    """Consecutive six-byte groups give two 24-bit coordinates in the unit square."""
    pairs = np.frombuffer(data, dtype=np.uint8, count=len(data) // 6 * 6).reshape(-1, 6)
    hits = 0
    for start in range(0, len(pairs), 65536):
        chunk = pairs[start : start + 65536].astype(np.float64)
        weights = np.array([65536, 256, 1]) / 2**24
        x, y = (
            np.einsum("ij,j->i", part, weights) for part in (chunk[:, :3], chunk[:, 3:])
        )
        hits += int(np.count_nonzero(x * x + y * y <= 1))
    return {
        "pairs": len(pairs),
        "estimate": 4 * hits / len(pairs) if len(pairs) else None,
    }

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (bits per byte, 0..8) of a byte string."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())

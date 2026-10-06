"""Pure computational utilities with zero OS/kernel dependencies, kept
separate from tier1_bridge.py (which requires BCC + root) specifically so
they can be unit-tested on any machine, including CI runners without eBPF."""
import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

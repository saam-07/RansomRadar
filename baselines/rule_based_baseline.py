"""Baseline 1 (roadmap Sec 6, item 1): thin wrapper around the daemon,
forcing rule-based classification and no Tier-1 escalation at all."""
import sys
from adaptshield.daemon import main as daemon_main

if __name__ == "__main__":
    sys.argv += ["--classifier", "rule_based", "--no-tier1"]
    daemon_main()

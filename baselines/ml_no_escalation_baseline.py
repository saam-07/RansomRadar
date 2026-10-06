"""Baseline 3 (roadmap Sec 6, item 3): same classifier as AdaptShield but
trained/evaluated on Tier-0 features only -- tests whether Tier-1
(syscall+entropy) features are necessary for accuracy at all, independent
of the escalation-cost question."""
import sys
from adaptshield.daemon import main as daemon_main

if __name__ == "__main__":
    sys.argv += ["--classifier", "random_forest", "--no-tier1"]
    daemon_main()

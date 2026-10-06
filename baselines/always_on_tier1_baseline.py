"""Baseline 2 (roadmap Sec 6, item 2): Tier-1 eBPF tracing runs for EVERY
pid from the start (no escalation gate). Structurally the closest analogue
to ebpfangel's always-on design. Same classifier/feature code as
AdaptShield -- ONLY the escalation policy differs, which is exactly what
isolates the tiering decision's cost/benefit (roadmap Sec 7.6 fig 2)."""
import sys
from adaptshield.daemon import main as daemon_main

if __name__ == "__main__":
    sys.argv += ["--classifier", "xgboost", "--no-escalation"]
    # NOTE: --no-escalation here means "skip the Tier-0 gate", but the
    # daemon still needs every pid manually escalated at t=0 for a TRUE
    # always-on comparison. For the paper, run this via
    # generate_labeled_traces.py's Tier-1-from-t=0 collection path instead
    # of the live daemon, since that path already traces from process start.
    daemon_main()

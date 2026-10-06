"""
Parses every run listed in results/raw/manifest.csv, computes the metrics
from roadmap Sec 7.3, and writes results/processed/summary.csv --
one row per (workload, filesystem, config, seed).
"""
import json
from pathlib import Path

import pandas as pd


def parse_alert_log(path: str) -> dict:
    """Returns detection latency, containment latency, bytes_at_risk, etc.
    for a single run's JSONL log (written by alert_logger.py)."""
    if not Path(path).exists():
        return {}
    first_event_ts = None
    first_alert_ts = None
    containment_row = None
    escalation_latencies = []
    with open(path) as f:
        for line in f:
            rec = json.loads(line)
            if rec["event_type"] == "escalation":
                escalation_latencies.append(rec["escalation_latency_s"])
            if rec["event_type"] == "alert_critical" and first_alert_ts is None:
                first_alert_ts = rec["ts"]
            if rec["event_type"] == "containment":
                containment_row = rec  # keep the LAST one: for manual policy,
                                        # the first containment event is just
                                        # the freeze; a later
                                        # manual_decision_applied event
                                        # (also logged as "containment" by
                                        # daemon.py) carries the real outcome
    out = {
        "detection_ts": first_alert_ts,
        "mean_escalation_latency_s": (
            sum(escalation_latencies) / len(escalation_latencies)
            if escalation_latencies else None
        ),
    }
    if containment_row:
        out.update({
            "freeze_latency_s": containment_row.get("freeze_latency_s"),
            "bytes_at_risk": containment_row.get("bytes_at_risk"),
            "files_at_risk": containment_row.get("files_at_risk"),
            "rolled_back": containment_row.get("rolled_back", False),
            "killed": containment_row.get("killed", False),
            "quarantined_files": containment_row.get("quarantined_files", 0),
            "quarantined_bytes": containment_row.get("quarantined_bytes", 0),
            "containment_policy": containment_row.get("policy"),
        })
    return out


def parse_overhead_csv(path: str) -> dict:
    if not Path(path).exists():
        return {}
    df = pd.read_csv(path)
    if df.empty:
        return {}
    return {
        "mean_cpu_percent": df["cpu_percent"].mean(),
        "max_rss_bytes": df["rss_bytes"].max(),
    }


def main():
    manifest = pd.read_csv("results/raw/manifest.csv")
    rows = []
    for _, r in manifest.iterrows():
        row = dict(r)
        row.update(parse_alert_log(r["log_path"]))
        row.update(parse_overhead_csv(r["overhead_csv"]))
        # ground truth: workload == "ransomware" means a TRUE alert is correct;
        # any other workload with an alert is a FALSE POSITIVE.
        row["is_true_positive_case"] = r["workload"] == "ransomware"
        row["fired_alert"] = row.get("detection_ts") is not None
        rows.append(row)

    out = pd.DataFrame(rows)
    Path("results/processed").mkdir(parents=True, exist_ok=True)
    out.to_csv("results/processed/summary.csv", index=False)

    # quick FPR / TPR table per (workload, filesystem, config)
    grouped = out.groupby(["workload", "filesystem", "config"]).agg(
        n_runs=("fired_alert", "count"),
        alert_rate=("fired_alert", "mean"),
        mean_cpu=("mean_cpu_percent", "mean"),
    ).reset_index()
    grouped.to_csv("results/processed/alert_rate_by_cell.csv", index=False)
    print(grouped)


if __name__ == "__main__":
    main()

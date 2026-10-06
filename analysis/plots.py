"""
Generates the figures listed in roadmap Sec 7.6, reading
results/processed/summary.csv and alert_rate_by_cell.csv produced by
aggregate.py. Run after aggregate.py.
"""
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

OUT_DIR = Path("results/processed/figures")
OUT_DIR.mkdir(parents=True, exist_ok=True)


def fig1_fpr_by_workload(df: pd.DataFrame):
    """Fig 1: FPR per configuration, grouped by workload (backup/OLTP highlighted)."""
    fpr = df[df["workload"] != "ransomware"].groupby(
        ["workload", "config"]
    )["fired_alert"].mean().reset_index(name="false_positive_rate")
    plt.figure(figsize=(8, 5))
    sns.barplot(data=fpr, x="workload", y="false_positive_rate", hue="config")
    plt.title("False Positive Rate by Workload and Configuration")
    plt.ylabel("FPR")
    plt.tight_layout()
    plt.savefig(OUT_DIR / "fig1_fpr_by_workload.png", dpi=150)
    plt.close()


def fig2_overhead_vs_latency(summary: pd.DataFrame):
    """Fig 2: CPU overhead vs detection latency, one point/line per config."""
    ransom = summary[summary["workload"] == "ransomware"].copy()
    ransom["detection_latency_s"] = (
        pd.to_numeric(ransom["detection_ts"], errors="coerce")
    )
    agg = ransom.groupby("config").agg(
        mean_cpu=("mean_cpu_percent", "mean"),
        mean_latency=("detection_latency_s", "mean"),
    ).reset_index()
    plt.figure(figsize=(6, 6))
    sns.scatterplot(data=agg, x="mean_cpu", y="mean_latency", hue="config", s=150)
    for _, r in agg.iterrows():
        plt.annotate(r["config"], (r["mean_cpu"], r["mean_latency"]))
    plt.xlabel("Mean daemon CPU % during run")
    plt.ylabel("Mean detection latency (s)")
    plt.title("Overhead vs Detection Latency Trade-off")
    plt.tight_layout()
    plt.savefig(OUT_DIR / "fig2_overhead_vs_latency.png", dpi=150)
    plt.close()


def fig3_f1_heatmap(summary: pd.DataFrame):
    """Fig 3: F1-like proxy (alert-rate on ransomware minus FPR) heatmap,
    filesystem (rows) x workload (columns), one per configuration.
    NOTE: replace with true precision/recall/F1 once you have per-window
    ground-truth labeled predictions, not just per-run alert-fired booleans."""
    for config in summary["config"].unique():
        sub = summary[summary["config"] == config]
        pivot = sub.pivot_table(
            index="filesystem", columns="workload", values="fired_alert", aggfunc="mean"
        )
        plt.figure(figsize=(6, 4))
        sns.heatmap(pivot, annot=True, cmap="RdYlGn_r", vmin=0, vmax=1)
        plt.title(f"Alert rate heatmap -- config={config}")
        plt.tight_layout()
        plt.savefig(OUT_DIR / f"fig3_heatmap_{config}.png", dpi=150)
        plt.close()


def fig4_bytes_at_risk(summary: pd.DataFrame):
    """Fig 4: bytes-at-risk vs bytes actually preserved-by-quarantine,
    per configuration. This is the figure that demonstrates reversible
    containment actually did something -- for configs with
    --rollback-policy none, quarantined_bytes will be 0 by construction;
    for _reversible configs, quarantined_bytes should track bytes_at_risk
    closely (everything touched gets quarantined before rollback)."""
    ransom = summary[summary["workload"] == "ransomware"].copy()
    melted = ransom.melt(
        id_vars=["config"], value_vars=["bytes_at_risk", "quarantined_bytes"],
        var_name="metric", value_name="bytes",
    )
    plt.figure(figsize=(7, 5))
    sns.barplot(data=melted, x="config", y="bytes", hue="metric")
    plt.title("Bytes at Risk vs. Bytes Preserved by Quarantine")
    plt.ylabel("Bytes")
    plt.xticks(rotation=20)
    plt.tight_layout()
    plt.savefig(OUT_DIR / "fig4_bytes_at_risk.png", dpi=150)
    plt.close()


def fig5_rollback_rate(summary: pd.DataFrame):
    """Fig 5 (new): fraction of ransomware runs actually rolled back, per
    configuration -- the direct, simplest evidence that IMMEDIATE/MANUAL
    policies do something NONE does not."""
    ransom = summary[summary["workload"] == "ransomware"]
    rate = ransom.groupby("config")["rolled_back"].mean().reset_index()
    plt.figure(figsize=(6, 4))
    sns.barplot(data=rate, x="config", y="rolled_back")
    plt.title("Rollback Rate by Configuration (ransomware runs only)")
    plt.ylabel("Fraction rolled back")
    plt.ylim(0, 1)
    plt.xticks(rotation=20)
    plt.tight_layout()
    plt.savefig(OUT_DIR / "fig5_rollback_rate.png", dpi=150)
    plt.close()


def main():
    summary = pd.read_csv("results/processed/summary.csv")
    fig1_fpr_by_workload(summary)
    fig2_overhead_vs_latency(summary)
    fig3_f1_heatmap(summary)
    fig4_bytes_at_risk(summary)
    fig5_rollback_rate(summary)
    print(f"Figures written to {OUT_DIR}")


if __name__ == "__main__":
    main()

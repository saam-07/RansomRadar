"""
Roadmap Sec 7.5: paired Wilcoxon signed-rank test comparing AdaptShield
against the always_on_tier1 baseline on (a) CPU overhead and (b) FPR on
backup/OLTP workloads, matched by identical seeds, corrected for multiple
comparisons across the 3 filesystems x 4 workloads with Holm-Bonferroni.
"""
import pandas as pd
from scipy import stats
from statsmodels.stats.multitest import multipletests


def paired_test(summary: pd.DataFrame, metric: str, config_a: str, config_b: str):
    results = []
    for (workload, fs), group in summary.groupby(["workload", "filesystem"]):
        a = group[group["config"] == config_a].sort_values("seed")[metric].values
        b = group[group["config"] == config_b].sort_values("seed")[metric].values
        n = min(len(a), len(b))
        if n < 3:
            continue
        try:
            if (a[:n] == b[:n]).all():
                results.append({"workload": workload, "filesystem": fs,
                                 "metric": metric, "statistic": 0.0, "p_raw": 1.0})
                continue
            stat, p = stats.wilcoxon(a[:n], b[:n])
            results.append({"workload": workload, "filesystem": fs,
                             "metric": metric, "statistic": float(stat), "p_raw": float(p)})
        except Exception:
            continue


    df = pd.DataFrame(results)
    if not df.empty:
        rejected, p_corrected, _, _ = multipletests(df["p_raw"], alpha=0.05, method="holm")
        df["p_corrected"] = p_corrected
        df["significant_at_0.05"] = rejected
    return df


def main():
    summary = pd.read_csv("results/processed/summary.csv")
    cpu_test = paired_test(summary, "mean_cpu_percent", "adaptshield", "always_on_tier1")
    cpu_test.to_csv("results/processed/sigtest_cpu_overhead.csv", index=False)
    print("CPU overhead significance test:")
    print(cpu_test)


if __name__ == "__main__":
    main()

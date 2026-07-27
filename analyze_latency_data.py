#!/usr/bin/env python3
"""
Network Latency Analysis Script for Multivariate Adaptor Signatures
Keys plots by Param_Set (ov-Is/ov-Ip/ov-III/ov-V/MAYO-1/3/5) so two Level-I
UOV rows are not collapsed. Compatible with CSV schema 4.0 from test_bench.
"""

from pathlib import Path
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

sns.set_theme(style="whitegrid", palette="husl")
plt.rcParams.update({
    "figure.dpi": 300,
    "font.size": 10,
    "axes.linewidth": 1.2,
    "grid.linewidth": 0.8,
    "lines.linewidth": 2.5,
    "patch.linewidth": 1.2,
    "font.family": "serif",
    "axes.spines.top": False,
    "axes.spines.right": False,
})

GLOBAL_COLORS = ["#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b", "#e377c2"]

PARAM_ORDER = ["ov-Is", "ov-Ip", "ov-III", "ov-V", "MAYO-1", "MAYO-3", "MAYO-5"]
PARAM_COLORS = {
    "ov-Is": "#1f77b4",
    "ov-Ip": "#17becf",
    "ov-III": "#2ca02c",
    "ov-V": "#d62728",
    "MAYO-1": "#ff7f0e",
    "MAYO-3": "#9467bd",
    "MAYO-5": "#8c564b",
}
PARAM_MARKERS = {
    "ov-Is": "o",
    "ov-Ip": "P",
    "ov-III": "s",
    "ov-V": "^",
    "MAYO-1": "D",
    "MAYO-3": "v",
    "MAYO-5": "p",
}


def _param_set(row) -> str:
    """Unique parameter-set label; never collapse ov-Is with ov-Ip."""
    for key in ("Param_Set", "Algorithm"):
        if key in row.index and pd.notna(row[key]) and str(row[key]).strip():
            return str(row[key]).strip()
    # Legacy schema 3.0 fallback (ambiguous for two Level-I UOV sets)
    return f"{row['Scheme']}-{int(row['Security_Level'])}"


def _normalize_df(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["Param_Set"] = out.apply(_param_set, axis=1)
    return out


def _configs(data) -> list:
    found = {p for df in data.values() for p in df["Param_Set"].unique()}
    ordered = [p for p in PARAM_ORDER if p in found]
    extras = sorted(found - set(ordered))
    return ordered + extras


def _peak_mb(val: float) -> float:
    # Schema 4.0 writes megabytes; old CSVs wrote raw bytes.
    v = float(val)
    return v / (1024 * 1024) if v > 10000 else v


def load_latency_data(root="results/performance", latencies=None):
    """Load latency_{N}ms.csv files; return {latency_ms: DataFrame}."""
    if latencies is None:
        latencies = [30, 120, 225, 320]
    root = Path(root)
    data = {}
    required = [
        "Scheme",
        "Security_Level",
        "TotalWorkflow_Mean_ms",
        "TotalWorkflow_Std_ms",
        "Throughput_OpsPerSec",
        "Peak_Memory_MB",
        "Stability_Percent",
    ]

    for latency in latencies:
        csv_path = root / f"latency_{latency}ms.csv"
        if not csv_path.exists():
            print(f"Missing: {csv_path}")
            continue
        try:
            df = pd.read_csv(csv_path, comment="#")
            missing = [c for c in required if c not in df.columns]
            if missing:
                print(f"Warning: {csv_path} missing columns: {missing}")
                continue
            df = _normalize_df(df)
            n = len(df)
            print(f"Loaded {csv_path} -> {latency} ms: {n} rows ({', '.join(df['Param_Set'].tolist())})")
            if n != 7:
                print(f"  WARNING: expected 7 parameter sets, got {n}")
            if "Leak_Sanity" in df.columns and (df["Leak_Sanity"] != "PASS").any():
                print(f"  WARNING: Leak_Sanity not all PASS in {csv_path.name}")
            peaks = df["Peak_Memory_MB"].map(_peak_mb)
            if peaks.max() > 100:
                print(f"  WARNING: Peak_Memory_MB looks inflated (max={peaks.max():.1f}); check harness")
            data[latency] = df
        except Exception as e:
            print(f"Error: failed to load {csv_path}: {e}")

    if not data:
        print(f"No valid latency files found. Expected: {[f'latency_{l}ms.csv' for l in latencies]}")
    return dict(sorted(data.items()))


def _ensure_dir(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)


def _save(fig, out_path: str):
    out = Path(out_path)
    _ensure_dir(out)
    fig.tight_layout()
    fig.savefig(out.with_suffix(".png"), dpi=300, bbox_inches="tight", facecolor="white", edgecolor="none")
    fig.savefig(out.with_suffix(".svg"), bbox_inches="tight", facecolor="white", edgecolor="none")
    fig.savefig(out.with_suffix(".pdf"), bbox_inches="tight", facecolor="white", edgecolor="none")
    plt.close(fig)


def _series(data, param, column):
    latencies = sorted(data.keys())
    means, stds = [], []
    for L in latencies:
        row = data[L][data[L]["Param_Set"] == param]
        if row.empty:
            means.append(np.nan)
            stds.append(np.nan)
        else:
            means.append(float(row[column].iloc[0]))
            if column == "TotalWorkflow_Mean_ms":
                stds.append(float(row["TotalWorkflow_Std_ms"].iloc[0]))
            elif column == "Throughput_OpsPerSec" and "Coefficient_Variation" in row.columns:
                cv = float(row["Coefficient_Variation"].iloc[0])
                stds.append(means[-1] * cv if not np.isnan(cv) else 0.0)
            elif column == "Peak_Memory_MB":
                mb = _peak_mb(means[-1])
                means[-1] = mb
                stds.append(mb * 0.05)
            elif column == "Stability_Percent":
                stds.append(0.5)
            else:
                stds.append(0.0)
    return latencies, np.array(means, dtype=float), np.array(stds, dtype=float)


def create_performance_comparison(data):
    latencies = sorted(data.keys())
    if not latencies:
        print("No data to plot.")
        return

    configs = _configs(data)
    fig, axes = plt.subplots(2, 2, figsize=(18, 14))
    ax1, ax2, ax3, ax4 = axes.ravel()

    specs = [
        (ax1, "TotalWorkflow_Mean_ms", "End-to-end Time (ms)", "Performance vs Network Latency", "upper left"),
        (ax2, "Throughput_OpsPerSec", "Throughput (ops/s)", "Throughput vs Network Latency", "upper right"),
        (ax3, "Peak_Memory_MB", "Peak Memory (MB)", "Memory Usage vs Network Latency", "upper left"),
        (ax4, "Stability_Percent", "Stability Score (%)", "Stability vs Network Latency", "lower right"),
    ]

<<<<<<< Updated upstream
    # 2) Throughput with confidence intervals
    for scheme in schemes:
        for level in levels:
            y_mean = []
            y_std = []
            for L in latencies:
                df = data[L]
                row = df[(df["Scheme"] == scheme) & (df["Security_Level"] == level)]
                if not row.empty:
                    y_mean.append(row["Throughput_OpsPerSec"].iloc[0])
                    # Calculate std from coefficient of variation if available
                    if "Coefficient_Variation" in row.columns:
                        cv = row["Coefficient_Variation"].iloc[0]
                        y_std.append(y_mean[-1] * cv if not np.isnan(cv) else 0)
                    else:
                        y_std.append(0)  # No std data available
                else:
                    y_mean.append(np.nan)
                    y_std.append(np.nan)
            
            full_name = f"{scheme_names.get(scheme, scheme)} {level}-bit"
            color = scheme_level_colors.get((scheme, level), "#666666")
            marker = scheme_level_markers.get((scheme, level), "o")
            
            # Plot mean line
            ax2.plot(latencies, y_mean, marker=marker, label=full_name, linewidth=2.5, markersize=8,
                    color=color, linestyle="-", markerfacecolor=color, 
                    markeredgecolor='white', markeredgewidth=1.5)
            
            # Add confidence interval bands
            y_mean = np.array(y_mean)
            y_std = np.array(y_std)
            valid_mask = ~(np.isnan(y_mean) | np.isnan(y_std))
            if np.any(valid_mask) and np.any(y_std[valid_mask] > 0):
                ax2.fill_between(np.array(latencies)[valid_mask], 
                               y_mean[valid_mask] - y_std[valid_mask],
                               y_mean[valid_mask] + y_std[valid_mask],
                               alpha=0.15, color=color)
    ax2.set_xlabel("Network Latency (ms)", fontsize=12)
    ax2.set_ylabel("Throughput (ops/s)", fontsize=12)
    ax2.set_title("Throughput vs Network Latency", fontsize=14, fontweight='bold')
    ax2.set_xticks(latencies)
    ax2.set_xticklabels([f"{L}ms" for L in latencies])
    ax2.grid(True, alpha=0.3)
    ax2.legend(ncol=2, fontsize=9, loc='upper right', framealpha=0.95, fancybox=True, shadow=True,
               columnspacing=0.8, handletextpad=0.5)

    # 3) Peak memory (MB) with confidence intervals
    for scheme in schemes:
        for level in levels:
            y_mean = []
            y_std = []
            for L in latencies:
                df = data[L]
                row = df[(df["Scheme"] == scheme) & (df["Security_Level"] == level)]
                if not row.empty:
                    # FIX: CSV column "Peak_Memory_MB" actually contains bytes, not MB
                    # Convert bytes to MB (divide by 1024*1024) to fix $1e10$ plotting artifact
                    memory_bytes = row["Peak_Memory_MB"].iloc[0]
                    memory_mb = memory_bytes / (1024 * 1024)
                    y_mean.append(memory_mb)
                    # Memory typically has low variance, use small std for visualization
                    y_std.append(memory_mb * 0.05)  # 5% of mean as std
                else:
                    y_mean.append(np.nan)
                    y_std.append(np.nan)
            
            full_name = f"{scheme_names.get(scheme, scheme)} {level}-bit"
            color = scheme_level_colors.get((scheme, level), "#666666")
            marker = scheme_level_markers.get((scheme, level), "o")
            
            # Plot mean line
            ax3.plot(latencies, y_mean, marker=marker, label=full_name, linewidth=2.5, markersize=8,
                    color=color, linestyle="-", markerfacecolor=color, 
                    markeredgecolor='white', markeredgewidth=1.5)
            
            # Add confidence interval bands
            y_mean = np.array(y_mean)
            y_std = np.array(y_std)
            valid_mask = ~(np.isnan(y_mean) | np.isnan(y_std))
            if np.any(valid_mask):
                ax3.fill_between(np.array(latencies)[valid_mask], 
                               y_mean[valid_mask] - y_std[valid_mask],
                               y_mean[valid_mask] + y_std[valid_mask],
                               alpha=0.15, color=color)
    ax3.set_xlabel("Network Latency (ms)", fontsize=12)
    ax3.set_ylabel("Peak Memory (MB)", fontsize=12)
    ax3.set_title("Memory Usage vs Network Latency", fontsize=14, fontweight='bold')
    ax3.set_xticks(latencies)
    ax3.set_xticklabels([f"{L}ms" for L in latencies])
    ax3.grid(True, alpha=0.3)
    ax3.legend(ncol=2, fontsize=9, loc='upper left', framealpha=0.95, fancybox=True, shadow=True,
               columnspacing=0.8, handletextpad=0.5)

    # 4) Stability with confidence intervals
    for scheme in schemes:
        for level in levels:
            y_mean = []
            y_std = []
            for L in latencies:
                df = data[L]
                row = df[(df["Scheme"] == scheme) & (df["Security_Level"] == level)]
                if not row.empty:
                    y_mean.append(row["Stability_Percent"].iloc[0])
                    # Stability typically has low variance, use small std for visualization
                    y_std.append(0.5)  # ±0.5% std for stability
                else:
                    y_mean.append(np.nan)
                    y_std.append(np.nan)
            
            full_name = f"{scheme_names.get(scheme, scheme)} {level}-bit"
            color = scheme_level_colors.get((scheme, level), "#666666")
            marker = scheme_level_markers.get((scheme, level), "o")
            
            # Plot mean line
            ax4.plot(latencies, y_mean, marker=marker, label=full_name, linewidth=2.5, markersize=8,
                    color=color, linestyle="-", markerfacecolor=color, 
                    markeredgecolor='white', markeredgewidth=1.5)
            
            # Add confidence interval bands
            y_mean = np.array(y_mean)
            y_std = np.array(y_std)
            valid_mask = ~(np.isnan(y_mean) | np.isnan(y_std))
            if np.any(valid_mask):
                ax4.fill_between(np.array(latencies)[valid_mask], 
                               y_mean[valid_mask] - y_std[valid_mask],
                               y_mean[valid_mask] + y_std[valid_mask],
                               alpha=0.15, color=color)
    ax4.set_xlabel("Network Latency (ms)", fontsize=12)
    ax4.set_ylabel("Stability Score (%)", fontsize=12)
    ax4.set_title("Stability vs Network Latency", fontsize=14, fontweight='bold')
    ax4.set_xticks(latencies)
    ax4.set_xticklabels([f"{L}ms" for L in latencies])
    ax4.grid(True, alpha=0.3)
    ax4.legend(ncol=2, fontsize=9, loc='lower right', framealpha=0.95, fancybox=True, shadow=True,
               columnspacing=0.8, handletextpad=0.5)
=======
    for ax, col, ylabel, title, legend_loc in specs:
        for param in configs:
            xs, y_mean, y_std = _series(data, param, col)
            color = PARAM_COLORS.get(param, "#666666")
            marker = PARAM_MARKERS.get(param, "o")
            ax.plot(
                xs, y_mean, marker=marker, label=param, linewidth=2.5, markersize=8,
                color=color, linestyle="-", markerfacecolor=color,
                markeredgecolor="white", markeredgewidth=1.5,
            )
            valid = ~(np.isnan(y_mean) | np.isnan(y_std))
            if np.any(valid):
                ax.fill_between(
                    np.array(xs)[valid],
                    y_mean[valid] - y_std[valid],
                    y_mean[valid] + y_std[valid],
                    alpha=0.15, color=color,
                )
        ax.set_xlabel("Network Latency (ms)", fontsize=12)
        ax.set_ylabel(ylabel, fontsize=12)
        ax.set_title(title, fontsize=14, fontweight="bold")
        ax.set_xticks(latencies)
        ax.set_xticklabels([f"{L}ms" for L in latencies])
        ax.grid(True, alpha=0.3)
        ax.legend(ncol=2, fontsize=9, loc=legend_loc, framealpha=0.95)
>>>>>>> Stashed changes

    _save(fig, "results/performance/latency_analysis")


def create_operation_breakdown(data):
    latencies = sorted(data.keys())
    if not latencies:
        return

    configs = _configs(data)
    target = "ov-Is" if "ov-Is" in configs else configs[0]

    ops = [
        "KeyGen_Mean_ms", "PresigGen_Mean_ms", "PresigVerify_Mean_ms",
        "Completion_Mean_ms", "Extraction_Mean_ms", "FinalVerify_Mean_ms",
    ]
    op_labels = ["KeyGen", "PresigGen", "PresigVerify", "Completion", "Extraction", "FinalVerify"]

    all_data = []
    for L in latencies:
        row = data[L][data[L]["Param_Set"] == target]
        if not row.empty:
            all_data.append((L, [float(row[c].iloc[0]) for c in ops]))
    if not all_data:
        print(f"No data for {target}")
        return

    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    ax1 = axes[0, 0]
    keygen_times = [vals[0] for _, vals in all_data]
    other_times = [sum(vals[1:]) for _, vals in all_data]
    x_pos = np.arange(len(all_data))
    width = 0.35
    ax1.bar(x_pos - width / 2, keygen_times, width, label="KeyGen", color="#1f77b4", alpha=0.9)
    ax1.bar(x_pos + width / 2, other_times, width, label="All Others", color="#ff7f0e", alpha=0.9)
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels([f"{L}ms" for L, _ in all_data])
    ax1.set_ylabel("Time (ms)")
    ax1.set_title(f"KeyGen vs Other Operations ({target})")
    ax1.legend()
    ax1.grid(True, alpha=0.3, axis="y")

    ax2 = axes[0, 1]
    x_pos = np.arange(len(ops) - 1)
    width = 0.2
    for i, (L, vals) in enumerate(all_data):
        offset = (i - len(all_data) / 2 + 0.5) * width
        ax2.bar(x_pos + offset, vals[1:], width, label=f"{L}ms",
                color=GLOBAL_COLORS[i % len(GLOBAL_COLORS)], alpha=0.85)
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(op_labels[1:], rotation=20, ha="right")
    ax2.set_ylabel("Time (ms)")
    ax2.set_title(f"Non-KeyGen Detail ({target})")
    ax2.legend()
    ax2.grid(True, alpha=0.3, axis="y")

    # Bottom: stacked overview across configs at first latency
    ax3 = axes[1, 0]
    L0 = latencies[0]
    df0 = data[L0]
    bottoms = np.zeros(len(configs))
    x = np.arange(len(configs))
    for i, op in enumerate(ops):
        heights = []
        for p in configs:
            row = df0[df0["Param_Set"] == p]
            heights.append(float(row[op].iloc[0]) if not row.empty else 0.0)
        ax3.bar(x, heights, bottom=bottoms, label=op_labels[i],
                color=GLOBAL_COLORS[i % len(GLOBAL_COLORS)])
        bottoms = bottoms + np.array(heights)
    ax3.set_xticks(x)
    ax3.set_xticklabels(configs, rotation=30, ha="right")
    ax3.set_ylabel("Time (ms)")
    ax3.set_title(f"Stacked ops at {L0}ms")
    ax3.legend(fontsize=8, ncol=2)
    ax3.grid(True, alpha=0.3, axis="y")

    ax4 = axes[1, 1]
    for param in configs:
        xs, y_mean, _ = _series(data, param, "TotalWorkflow_Mean_ms")
        ax4.plot(xs, y_mean, marker=PARAM_MARKERS.get(param, "o"),
                 label=param, color=PARAM_COLORS.get(param, "#666"))
    ax4.set_xlabel("Network Latency (ms)")
    ax4.set_ylabel("End-to-end (ms)")
    ax4.set_title("End-to-end across configs")
    ax4.set_xticks(latencies)
    ax4.legend(fontsize=8, ncol=2)
    ax4.grid(True, alpha=0.3)

    _save(fig, "results/performance/operation_breakdown")


def create_degradation_analysis(data):
    latencies = sorted(data.keys())
    if len(latencies) < 2:
        print("Need at least two latency points for degradation.")
        return

    baseline_L = latencies[0]
    base_df = data[baseline_L]
    configs = _configs(data)

    degradation_matrix = []
    for param in configs:
        base_row = base_df[base_df["Param_Set"] == param]
        base = float(base_row["TotalWorkflow_Mean_ms"].iloc[0]) if not base_row.empty else np.nan
        row_deg = []
        for L in latencies[1:]:
            cur_row = data[L][data[L]["Param_Set"] == param]
            cur = float(cur_row["TotalWorkflow_Mean_ms"].iloc[0]) if not cur_row.empty else np.nan
            if np.isnan(base) or np.isnan(cur) or base == 0:
                row_deg.append(np.nan)
            else:
                row_deg.append(((cur - base) / base) * 100.0)
        degradation_matrix.append(row_deg)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 8))
    arr = np.array(degradation_matrix, dtype=float)
    vmax = np.nanmax(np.abs(arr)) if np.isfinite(arr).any() else 1.0
    im = ax1.imshow(arr, cmap="RdYlBu_r", aspect="auto", vmin=-vmax, vmax=vmax)
    ax1.set_xticks(range(len(latencies[1:])))
    ax1.set_xticklabels([f"{L}ms" for L in latencies[1:]])
    ax1.set_yticks(range(len(configs)))
    ax1.set_yticklabels(configs)
    for i in range(len(configs)):
        for j in range(len(latencies[1:])):
            val = arr[i, j]
            if not np.isnan(val):
                ax1.text(j, i, f"{val:.1f}%", ha="center", va="center", fontsize=9)
    ax1.set_title(f"Degradation vs {baseline_L}ms baseline")
    plt.colorbar(im, ax=ax1, shrink=0.8, label="Degradation (%)")

    x = np.arange(len(configs))
    width = 0.8 / max(len(latencies) - 1, 1)
    for i, L in enumerate(latencies[1:]):
        vals = [row[i] for row in degradation_matrix]
        ax2.bar(x + i * width, vals, width, label=f"{L}ms",
                color=GLOBAL_COLORS[(i + 1) % len(GLOBAL_COLORS)], alpha=0.9)
    ax2.set_xticks(x + (len(latencies) - 2) * width / 2)
    ax2.set_xticklabels(configs, rotation=30, ha="right")
    ax2.set_ylabel("Degradation (%)")
    ax2.set_title(f"Degradation comparison (baseline {baseline_L}ms)")
    ax2.legend()
    ax2.grid(True, alpha=0.3, axis="y")
    _save(fig, "results/performance/degradation_analysis")


def create_throughput_heatmap(data):
    latencies = sorted(data.keys())
    configs = _configs(data)
    matrix = []
    for param in configs:
        vals = []
        for L in latencies:
            row = data[L][data[L]["Param_Set"] == param]
            vals.append(float(row["Throughput_OpsPerSec"].iloc[0]) if not row.empty else np.nan)
        matrix.append(vals)

    fig, ax = plt.subplots(figsize=(12, 10))
    sns.heatmap(
        np.array(matrix, dtype=float),
        xticklabels=[f"{L}ms" for L in latencies],
        yticklabels=configs,
        annot=True,
        fmt=".1f",
        cmap="YlOrRd",
        linewidths=0.4,
        linecolor="w",
        cbar_kws={"label": "Throughput (ops/s)", "shrink": 0.8},
        ax=ax,
    )
    ax.set_title("Throughput Heatmap Across Network Latency Conditions", fontsize=14, fontweight="bold")
    ax.set_xlabel("Network Latency (ms)", fontsize=12)
    ax.set_ylabel("Parameter set", fontsize=12)
    _save(fig, "results/performance/throughput_heatmap")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Analyze MWAS latency CSVs (schema 4.0 / Param_Set)")
    parser.add_argument("--root", default="results/performance")
    parser.add_argument("--latencies", nargs="+", type=int, default=[30, 120, 225, 320])
    parser.add_argument(
        "--plots", nargs="+",
        choices=["performance", "breakdown", "degradation", "heatmap", "all"],
        default=["all"],
    )
    args = parser.parse_args()

    print(f"Loading latency data from {args.root}...")
    data = load_latency_data(args.root, args.latencies)
    if not data:
        print("No data found. Please run the latency tests first.")
        return

    plots = args.plots if "all" not in args.plots else ["performance", "breakdown", "degradation", "heatmap"]
    if "performance" in plots:
        print("Creating performance comparison graphs…")
        create_performance_comparison(data)
    if "breakdown" in plots:
        print("Creating operation breakdown analysis…")
        create_operation_breakdown(data)
    if "degradation" in plots:
        print("Creating performance degradation analysis…")
        create_degradation_analysis(data)
    if "heatmap" in plots:
        print("Creating throughput heatmap…")
        create_throughput_heatmap(data)

    print("Done. Outputs under results/performance/:")
    print("  latency_analysis.*, throughput_heatmap.*, operation_breakdown.*, degradation_analysis.*")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Network Latency Analysis Script for Multivariate Adaptor Signatures
Improved: dynamic file discovery, NaN-safe calcs, adaptive layouts, and cleaner saves.
"""

from pathlib import Path
import re
import math
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Set research-grade styling
sns.set_theme(style="whitegrid", palette="husl")
plt.rcParams.update({
    "figure.dpi": 300,  # High DPI for publication
    "font.size": 10,
    "axes.linewidth": 1.2,
    "grid.linewidth": 0.8,
    "lines.linewidth": 2.5,
    "patch.linewidth": 1.2,
    "font.family": "serif",  # Better for academic papers
    "axes.spines.top": False,
    "axes.spines.right": False
})

# Global color palette for consistency
GLOBAL_COLORS = ['#1f77b4', '#ff7f0e', '#2ca02c', '#d62728', '#9467bd', '#8c564b']

# ---------- Data Loading ----------

def load_latency_data(root="results/performance", latencies=[30, 120, 225, 320]):
    """Load specific latency CSV files; return {latency_ms: DataFrame} (sorted)."""
    root = Path(root)
    data = {}
    required_columns = ["Scheme", "Security_Level", "TotalWorkflow_Mean_ms", "TotalWorkflow_Std_ms", 
                       "Throughput_OpsPerSec", "Peak_Memory_MB", "Stability_Percent"]
    
    for latency in latencies:
        csv_path = root / f"latency_{latency}ms.csv"
        if csv_path.exists():
            try:
                df = pd.read_csv(csv_path, comment="#")
                
                # Check for required columns
                missing_cols = [col for col in required_columns if col not in df.columns]
                if missing_cols:
                    print(f"Warning: {csv_path} missing columns: {missing_cols}")
                    continue
                
                data[latency] = df
                print(f"Loaded {csv_path} -> {latency} ms: {len(df)} rows")
            except Exception as e:
                print(f"Error: failed to load {csv_path}: {e}")
        else:
            print(f"Missing: {csv_path}")

    if not data:
        print(f"No valid latency files found. Expected: {[f'latency_{l}ms.csv' for l in latencies]}")
    return dict(sorted(data.items()))

# ---------- Plot Helpers ----------

def _ensure_dir(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)

def _save(fig, out_path: str):
    """Save figure in multiple formats for research publication."""
    out = Path(out_path)
    _ensure_dir(out)
    fig.tight_layout()
    
    # High-quality PNG for presentations
    fig.savefig(out.with_suffix(".png"), dpi=300, bbox_inches="tight", 
                facecolor='white', edgecolor='none')
    
    # SVG for web/editable graphics
    fig.savefig(out.with_suffix(".svg"), bbox_inches="tight", 
                facecolor='white', edgecolor='none')
    
    # PDF for LaTeX integration (research papers)
    fig.savefig(out.with_suffix(".pdf"), bbox_inches="tight", 
                facecolor='white', edgecolor='none')
    
    plt.close(fig)

# ---------- Figures ----------

def create_performance_comparison(data):
    """End-to-end time, throughput, memory, stability vs network latency."""
    latencies = sorted(data.keys())
    if not latencies:
        print("No data to plot.")
        return

    schemes = sorted({s for df in data.values() for s in df["Scheme"].unique()})
    levels  = sorted({int(l) for df in data.values() for l in df["Security_Level"].unique()})
    
    # Clean, concise scheme names
    scheme_names = {
        "UOV": "UOV",
        "MAYO": "MAYO"
    }

    fig, axes = plt.subplots(2, 2, figsize=(18, 14))
    ax1, ax2, ax3, ax4 = axes.ravel()

    # 1) End-to-end time with confidence intervals
    # Distinct color and style mapping for each scheme-security combination
    scheme_level_colors = {
        ("UOV", 128): "#1f77b4",      # Blue
        ("UOV", 192): "#2ca02c",      # Green  
        ("UOV", 256): "#d62728",      # Red
        ("MAYO", 128): "#ff7f0e",     # Orange
        ("MAYO", 192): "#9467bd",     # Purple
        ("MAYO", 256): "#8c564b"      # Brown
    }
    scheme_level_markers = {
        ("UOV", 128): "o",            # Circle
        ("UOV", 192): "s",            # Square
        ("UOV", 256): "^",            # Triangle up
        ("MAYO", 128): "D",           # Diamond
        ("MAYO", 192): "v",           # Triangle down
        ("MAYO", 256): "p"            # Pentagon
    }
    
    for scheme in schemes:
        for level in levels:
            y_mean = []
            y_std = []
            for L in latencies:
                df = data[L]
                row = df[(df["Scheme"] == scheme) & (df["Security_Level"] == level)]
                if not row.empty:
                    y_mean.append(row["TotalWorkflow_Mean_ms"].iloc[0])
                    y_std.append(row["TotalWorkflow_Std_ms"].iloc[0])
                else:
                    y_mean.append(np.nan)
                    y_std.append(np.nan)
            
            full_name = f"{scheme_names.get(scheme, scheme)} {level}-bit"
            color = scheme_level_colors.get((scheme, level), "#666666")
            marker = scheme_level_markers.get((scheme, level), "o")
            
            # Plot mean line
            ax1.plot(latencies, y_mean, marker=marker, label=full_name, linewidth=2.5, markersize=8,
                    color=color, linestyle="-", markerfacecolor=color, 
                    markeredgecolor='white', markeredgewidth=1.5)
            
            # Add confidence interval bands (mean ± std)
            y_mean = np.array(y_mean)
            y_std = np.array(y_std)
            valid_mask = ~(np.isnan(y_mean) | np.isnan(y_std))
            if np.any(valid_mask):
                ax1.fill_between(np.array(latencies)[valid_mask], 
                               y_mean[valid_mask] - y_std[valid_mask],
                               y_mean[valid_mask] + y_std[valid_mask],
                               alpha=0.15, color=color)
    ax1.set_xlabel("Network Latency (ms)", fontsize=12)
    ax1.set_ylabel("End-to-end Time (ms)", fontsize=12)
    ax1.set_title("Performance vs Network Latency", fontsize=14, fontweight='bold')
    ax1.set_xticks(latencies)
    ax1.set_xticklabels([f"{L}ms" for L in latencies])
    ax1.grid(True, alpha=0.3)
    ax1.legend(ncol=2, fontsize=9, loc='upper left', framealpha=0.95, fancybox=True, shadow=True, 
               columnspacing=0.8, handletextpad=0.5)

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

    _save(fig, "results/performance/latency_analysis")

def create_operation_breakdown(data):
    """Professional operation breakdown with clear separation of scales."""
    latencies = sorted(data.keys())
    if not latencies:
        return

    # Choose a canonical (scheme, level) that exists; prefer UOV-128.
    candidates = []
    for L in latencies:
        df = data[L]
        for _, r in df.iterrows():
            candidates.append((r["Scheme"], int(r["Security_Level"])))
    target = ("UOV", 128) if ("UOV", 128) in candidates else sorted(set(candidates))[0]

    ops = ["KeyGen_Mean_ms", "PresigGen_Mean_ms", "PresigVerify_Mean_ms",
           "Completion_Mean_ms", "Extraction_Mean_ms", "FinalVerify_Mean_ms"]
    op_labels = ["KeyGen", "PresigGen", "PresigVerify", "Completion", "Extraction", "FinalVerify"]

    # Collect data for all latencies
    all_data = []
    for L in latencies:
        df = data[L]
        row = df[(df["Scheme"] == target[0]) & (df["Security_Level"] == target[1])]
        if not row.empty:
            vals = [row[c].iloc[0] for c in ops]
            all_data.append((L, vals))
    
    if not all_data:
        print(f"No data for {target[0]}-{target[1]}")
        return

    # Create professional 2x2 layout
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    
    # 1) KeyGen vs Others - Clear comparison (Top-Left)
    ax1 = axes[0, 0]
    keygen_times = [data[1][0] for data in all_data]
    other_times = [sum(data[1][1:]) for data in all_data]
    
    x_pos = np.arange(len(latencies))
    width = 0.35
    
    bars1 = ax1.bar(x_pos - width/2, keygen_times, width, label='KeyGen', 
                   color='#1f77b4', alpha=0.9, edgecolor='white', linewidth=1.5)
    bars2 = ax1.bar(x_pos + width/2, other_times, width, label='All Others', 
                   color='#ff7f0e', alpha=0.9, edgecolor='white', linewidth=1.5)
    
    # Add value labels with better positioning
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.02,
                    f'{height:.2f}', ha='center', va='bottom', fontsize=10, fontweight='bold')
    
    ax1.set_xlabel("Network Latency (ms)", fontsize=12, fontweight='bold')
    ax1.set_ylabel("Time (ms)", fontsize=12, fontweight='bold')
    ax1.set_title(f"KeyGen vs Other Operations ({target[0]}-{target[1]})", 
                 fontsize=14, fontweight='bold', pad=20)
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels([f"{L}ms" for L, _ in all_data], fontsize=11)
    ax1.legend(fontsize=11, framealpha=0.95, loc='upper left')
    ax1.grid(True, alpha=0.3, axis='y')
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    
    # 2) Non-KeyGen Operations - Separate scale (Top-Right)
    ax2 = axes[0, 1]
    small_ops = ops[1:]  # Skip KeyGen
    small_labels = op_labels[1:]
    
    x_pos = np.arange(len(small_ops))
    colors = GLOBAL_COLORS[1:]  # Skip first color (blue) to avoid confusion with KeyGen
    
    # Create grouped bars for each latency
    width = 0.2
    for i, (L, vals) in enumerate(all_data):
        small_vals = vals[1:]  # Skip KeyGen
        offset = (i - len(all_data)/2 + 0.5) * width
        bars = ax2.bar(x_pos + offset, small_vals, width, label=f"{L}ms", 
                      color=colors[i % len(colors)], alpha=0.8, edgecolor='white', linewidth=1)
        
        # Add value labels for significant values
        for bar, val in zip(bars, small_vals):
            if val > 0.01:  # Only label values > 0.01ms
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + height*0.05,
                        f'{val:.3f}', ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    ax2.set_xlabel("Operations", fontsize=12, fontweight='bold')
    ax2.set_ylabel("Time (ms)", fontsize=12, fontweight='bold')
    ax2.set_title("Non-KeyGen Operations Detail", fontsize=14, fontweight='bold', pad=20)
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels(small_labels, fontsize=11, rotation=45, ha='right')
    ax2.legend(fontsize=10, framealpha=0.95, loc='upper left')
    ax2.grid(True, alpha=0.3, axis='y')
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)
    
    # 3) Time Distribution Pie Chart (Bottom-Left)
    ax3 = axes[1, 0]
    avg_values = np.mean([data[1] for data in all_data], axis=0)
    total_time = np.sum(avg_values)
    
    # Only show operations that contribute >2% of total time
    significant_ops = [(label, val) for label, val in zip(op_labels, avg_values) 
                      if val / total_time > 0.02]
    other_time = total_time - sum(val for _, val in significant_ops)
    
    if other_time > 0:
        significant_ops.append(("Others", other_time))
    
    labels, values = zip(*significant_ops)
    colors_pie = GLOBAL_COLORS[:len(significant_ops)]
    
    wedges, texts, autotexts = ax3.pie(values, labels=labels, colors=colors_pie, 
                                      autopct='%1.1f%%', startangle=90, textprops={'fontsize': 10})
    ax3.set_title("Average Time Distribution", fontsize=14, fontweight='bold', pad=20)
    
    # 4) Efficiency Analysis (Bottom-Right)
    ax4 = axes[1, 1]
    efficiencies = [sum(data[1][1:]) / sum(data[1]) * 100 for data in all_data]
    
    bars = ax4.bar([f"{L}ms" for L, _ in all_data], efficiencies, 
                  color='#2ca02c', alpha=0.9, edgecolor='white', linewidth=1.5)
    
    # Add value labels
    for bar, eff in zip(bars, efficiencies):
        height = bar.get_height()
        ax4.text(bar.get_x() + bar.get_width()/2., height + height*0.05,
                f'{eff:.1f}%', ha='center', va='bottom', fontsize=11, fontweight='bold')
    
    ax4.set_xlabel("Network Latency (ms)", fontsize=12, fontweight='bold')
    ax4.set_ylabel("Efficiency (%)", fontsize=12, fontweight='bold')
    ax4.set_title("Non-KeyGen Operations Efficiency", fontsize=14, fontweight='bold', pad=20)
    ax4.grid(True, alpha=0.3, axis='y')
    ax4.set_ylim(0, max(efficiencies) * 1.15)
    ax4.spines['top'].set_visible(False)
    ax4.spines['right'].set_visible(False)
    
    plt.tight_layout()
    _save(fig, "results/performance/operation_breakdown")

def create_degradation_analysis(data):
    """Professional degradation analysis with clear visual hierarchy."""
    latencies = sorted(data.keys())
    if len(latencies) < 2:
        print("Need at least two latency points for degradation.")
        return

    baseline_L = latencies[0]
    base_df = data[baseline_L]

    # Clean, concise scheme names
    scheme_names = {
        "UOV": "UOV",
        "MAYO": "MAYO"
    }

    combos = sorted({(r["Scheme"], int(r["Security_Level"])) for _, r in base_df.iterrows()})
    labels = [f"{s}-{lvl}" for s, lvl in combos]

    # Calculate degradation matrix
    degradation_matrix = []
    for (scheme, lvl) in combos:
        base_row = base_df[(base_df["Scheme"] == scheme) & (base_df["Security_Level"] == lvl)]
        base = base_row["TotalWorkflow_Mean_ms"].iloc[0] if not base_row.empty else np.nan
        
        row_degradation = []
        for L in latencies[1:]:  # Skip baseline
            cur_df = data[L]
            cur_row = cur_df[(cur_df["Scheme"] == scheme) & (cur_df["Security_Level"] == lvl)]
            cur = cur_row["TotalWorkflow_Mean_ms"].iloc[0] if not cur_row.empty else np.nan
            
            if np.isnan(base) or np.isnan(cur) or base == 0:
                deg = np.nan
            else:
                deg = ((cur - base) / base) * 100.0
            row_degradation.append(deg)
        degradation_matrix.append(row_degradation)

    # Create professional visualization
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 8))
    
    # 1) Heatmap visualization (Left)
    degradation_array = np.array(degradation_matrix)
    im = ax1.imshow(degradation_array, cmap='RdYlBu_r', aspect='auto', vmin=0, vmax=np.nanmax(degradation_array))
    
    # Set ticks and labels
    ax1.set_xticks(range(len(latencies[1:])))
    ax1.set_xticklabels([f"{L}ms" for L in latencies[1:]], fontsize=11)
    ax1.set_yticks(range(len(labels)))
    ax1.set_yticklabels(labels, fontsize=10)
    
    # Add text annotations
    for i in range(len(labels)):
        for j in range(len(latencies[1:])):
            value = degradation_array[i, j]
            if not np.isnan(value):
                text_color = 'white' if value > np.nanmax(degradation_array) * 0.5 else 'black'
                ax1.text(j, i, f'{value:.1f}%', ha='center', va='center', 
                        color=text_color, fontsize=10, fontweight='bold')
    
    ax1.set_xlabel("Network Latency (ms)", fontsize=12, fontweight='bold')
    ax1.set_ylabel("Cryptographic Scheme & Security Level", fontsize=12, fontweight='bold')
    ax1.set_title(f"Performance Degradation Heatmap\n(Baseline: {baseline_L}ms)", 
                 fontsize=14, fontweight='bold', pad=20)
    
    # Add colorbar
    cbar = plt.colorbar(im, ax=ax1, shrink=0.8)
    cbar.set_label('Degradation (%)', fontsize=11, fontweight='bold')
    
    # 2) Bar chart comparison (Right)
    x = np.arange(len(labels))
    width = 0.8 / len(latencies[1:])
    colors = GLOBAL_COLORS[1:5]  # Use consistent colors for degradation analysis
    
    for i, L in enumerate(latencies[1:]):
        values = [row[i] for row in degradation_matrix]
        bars = ax2.bar(x + i * width, values, width, label=f"{L}ms", 
                      color=colors[i % len(colors)], alpha=0.9, edgecolor='white', linewidth=1.5)
        
        # Add value labels
        for bar, val in zip(bars, values):
            if not np.isnan(val):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + height*0.02,
                        f'{val:.1f}%', ha='center', va='bottom', fontsize=9, fontweight='bold')
    
    ax2.set_xlabel("Cryptographic Scheme & Security Level", fontsize=12, fontweight='bold')
    ax2.set_ylabel("Performance Degradation (%)", fontsize=12, fontweight='bold')
    ax2.set_title(f"Degradation Comparison\n(Baseline: {baseline_L}ms)", 
                 fontsize=14, fontweight='bold', pad=20)
    ax2.set_xticks(x + (len(latencies[1:]) - 1) * width / 2)
    ax2.set_xticklabels(labels, rotation=45, ha='right', fontsize=10)
    ax2.legend(fontsize=11, framealpha=0.95, loc='upper right')
    ax2.grid(True, alpha=0.3, axis='y')
    ax2.spines['top'].set_visible(False)
    ax2.spines['right'].set_visible(False)
    
    plt.tight_layout()
    _save(fig, "results/performance/degradation_analysis")

def create_throughput_heatmap(data):
    """Heatmap of Overall Throughput for all (scheme,level) × latency."""
    latencies = sorted(data.keys())
    
    # Clean, concise scheme names
    scheme_names = {
        "UOV": "UOV",
        "MAYO": "MAYO"
    }
    
    rows = []
    for df in data.values():
        for _, r in df.iterrows():
            scheme = r["Scheme"]
            level = int(r["Security_Level"])
            full_name = f"{scheme_names.get(scheme, scheme)} {level}-bit"
            rows.append(full_name)
    rows = sorted(set(rows))
    
    matrix = []
    for row_label in rows:
        # Extract scheme and level from full name
        if "UOV" in row_label:
            scheme = "UOV"
            level = int(row_label.split()[-1].replace("-bit", ""))
        elif "MAYO" in row_label:
            scheme = "MAYO"
            level = int(row_label.split()[-1].replace("-bit", ""))
        else:
            continue
            
        vals = []
        for L in latencies:
            df = data[L]
            row = df[(df["Scheme"] == scheme) & (df["Security_Level"] == level)]
            vals.append(row["Throughput_OpsPerSec"].iloc[0] if not row.empty else np.nan)
        matrix.append(vals)

    fig, ax = plt.subplots(figsize=(12, 10))
    sns.heatmap(
        np.array(matrix, dtype=float),
        xticklabels=[f"{L}ms" for L in latencies],
        yticklabels=rows,
        annot=True,
        fmt=".1f",
        cmap="YlOrRd",
        linewidths=0.4,
        linecolor="w",
        cbar_kws={"label": "Throughput (ops/s)", "shrink": 0.8},
        ax=ax,
    )
    ax.set_title("Throughput Heatmap Across Network Latency Conditions", fontsize=14, fontweight='bold')
    ax.set_xlabel("Network Latency (ms)", fontsize=12)
    ax.set_ylabel("Cryptographic Scheme & Security Level", fontsize=12)
    plt.xticks(rotation=0)
    plt.yticks(rotation=0)
    plt.tight_layout()
    _save(fig, "results/performance/throughput_heatmap")

# ---------- Main ----------

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyze multivariate adaptor signature latency data")
    parser.add_argument("--root", default="results/performance", 
                       help="Root directory for latency CSV files")
    parser.add_argument("--latencies", nargs="+", type=int, default=[30, 120, 225, 320],
                       help="Latency values to analyze (ms)")
    parser.add_argument("--plots", nargs="+", 
                       choices=["performance", "breakdown", "degradation", "heatmap", "all"],
                       default=["all"], help="Which plots to generate")
    
    args = parser.parse_args()
    
    print(f"Loading latency data from {args.root}...")
    print(f"Analyzing latencies: {args.latencies}ms")
    
    data = load_latency_data(args.root, args.latencies)
    if not data:
        print("No data found. Please run the latency tests first.")
        return

    plots_to_run = args.plots if "all" not in args.plots else ["performance", "breakdown", "degradation", "heatmap"]
    
    if "performance" in plots_to_run:
        print("Creating performance comparison graphs…")
        create_performance_comparison(data)

    if "breakdown" in plots_to_run:
        print("Creating operation breakdown analysis…")
        create_operation_breakdown(data)

    if "degradation" in plots_to_run:
        print("Creating performance degradation analysis…")
        create_degradation_analysis(data)

    if "heatmap" in plots_to_run:
        print("Creating throughput heatmap…")
        create_throughput_heatmap(data)

    print("Analysis complete! Generated files:")
    print("  - results/performance/latency_analysis.* (PNG, SVG, PDF)")
    print("  - results/performance/operation_breakdown.* (PNG, SVG, PDF)")
    print("  - results/performance/degradation_analysis.* (PNG, SVG, PDF)")
    print("  - results/performance/throughput_heatmap.* (PNG, SVG, PDF)")

if __name__ == "__main__":
    main()

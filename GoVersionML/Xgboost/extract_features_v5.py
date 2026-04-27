"""
ML Feature Extraction Pipeline V5
=================================
Converts NetFlow JSON/NDJSON records into a V5 feature-engineered dataset for XGBoost.

V5 keeps the robust V4 core and adds:
- Entropy and concentration signals (destination IP entropy, source port entropy,
  top destination port share)
- Dispersion and dominance signals (bytes/packets std, bytes-per-packet spread,
  dominant bytes-per-packet ratio counts)
- Initiator proxy and source port-role features
- Burstiness signal (max per-minute flows inside each window)
"""

import sys
import os
import pandas as pd
import numpy as np

pd.options.mode.chained_assignment = None

REQUIRED_COLUMNS = [
    "first",
    "last",
    "in_packets",
    "in_bytes",
    "proto",
    "tcp_flags",
    "src_port",
    "dst_port",
    "src4_addr",
    "dst4_addr",
]


def _load_json_or_ndjson(input_path):
    try:
        return pd.read_json(input_path)
    except ValueError:
        # NDJSON fallback
        return pd.read_json(input_path, lines=True)


def _count_dominant_values(series, coverage):
    counts = series.value_counts(dropna=False)
    if counts.empty:
        return 0
    cumulative = (counts.cumsum() / counts.sum()).to_numpy()
    idx = int(np.searchsorted(cumulative, coverage, side="left"))
    return idx + 1


def _group_entropy(df, key_col, value_col, out_col):
    counts = (
        df.groupby([key_col, "time_window", value_col])
        .size()
        .reset_index(name="n")
    )
    totals = counts.groupby([key_col, "time_window"])["n"].transform("sum")
    p = counts["n"] / totals.replace(0, 1)
    counts["entropy_term"] = -p * np.log2(p.replace(0, 1))
    entropy = (
        counts.groupby([key_col, "time_window"])["entropy_term"]
        .sum()
        .reset_index(name=out_col)
    )
    return entropy


def extract_features_v5(input_path, output_path, window_size="5min", botnet_ratio_threshold=0.5):
    print(f"Loading flow data from {input_path}...")

    df = _load_json_or_ndjson(input_path)
    if df.empty:
        print(f"File {input_path} is empty. Skipping.")
        return

    missing = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    print(f"Loaded {len(df):,} flows. Processing V5 features...")

    df["first"] = pd.to_datetime(df["first"], format="mixed", errors="coerce")
    df["last"] = pd.to_datetime(df["last"], format="mixed", errors="coerce")
    df = df.dropna(subset=["first"]).copy()
    df["last"] = df["last"].fillna(df["first"])

    if df.empty:
        print(f"No valid timestamp rows found in {input_path}. Skipping.")
        return

    for numeric_col in ["in_packets", "in_bytes", "proto", "src_port", "dst_port"]:
        df[numeric_col] = pd.to_numeric(df[numeric_col], errors="coerce").fillna(0)

    df["time_window"] = df["first"].dt.floor(window_size)
    window_seconds = pd.to_timedelta(window_size).total_seconds()
    if window_seconds <= 0:
        raise ValueError("window_size must be a positive duration")

    print("Calculating core behavioral indicators...")

    df["tcp_flags"] = df["tcp_flags"].astype(str).fillna("")
    df["is_tcp"] = (df["proto"] == 6).astype(int)
    df["is_udp"] = (df["proto"] == 17).astype(int)
    df["is_icmp"] = (df["proto"] == 1).astype(int)
    df["syn_only"] = (
        df["tcp_flags"].str.contains("S")
        & ~df["tcp_flags"].str.contains("A|F|R")
    ).astype(int)
    df["has_rst"] = df["tcp_flags"].str.contains("R").astype(int)

    df["well_known_port"] = (df["dst_port"] < 1024).astype(int)
    df["src_port_well_known"] = (df["src_port"] < 1024).astype(int)
    df["src_port_ephemeral"] = (df["src_port"] >= 49152).astype(int)
    df["client_initiated"] = (
        (df["src_port"] >= 49152) & (df["dst_port"] < 1024)
    ).astype(int)
    df["server_initiated"] = (
        (df["src_port"] < 1024) & (df["dst_port"] >= 49152)
    ).astype(int)

    df["duration_sec"] = (
        (df["last"] - df["first"]).dt.total_seconds().fillna(0).clip(lower=0)
    )

    packets_denom = df["in_packets"].replace(0, 1)
    df["bpp_ratio"] = df["in_bytes"] / packets_denom
    df["bpp_ratio_rounded"] = df["bpp_ratio"].round(3)

    if "label" in df.columns:
        label_str = df["label"].astype(str).str.lower()
        df["is_botnet_flow"] = label_str.str.contains("botnet|bot").astype(int)
    else:
        df["is_botnet_flow"] = 0

    print("Computing time-based features and group aggregations...")

    df = df.sort_values(by=["src4_addr", "dst4_addr", "dst_port", "first"]).reset_index(drop=True)
    df["iat"] = (
        df.groupby(["src4_addr", "dst4_addr", "dst_port", "time_window"])["first"]
        .diff()
        .dt.total_seconds()
        .fillna(0)
        .astype("float32")
    )

    df_out_ports = df[["src4_addr", "time_window", "dst_port"]].drop_duplicates()
    df_in_ports = df[["dst4_addr", "time_window", "dst_port"]].drop_duplicates()
    df_in_ports = df_in_ports.rename(columns={"dst4_addr": "src4_addr"})
    sym_matches = pd.merge(
        df_out_ports,
        df_in_ports,
        on=["src4_addr", "time_window", "dst_port"],
        how="inner",
    )
    symmetry_counts = (
        sym_matches.groupby(["src4_addr", "time_window"])
        .size()
        .reset_index(name="port_symmetry")
    )

    agg_funcs = {
        "first": "count",
        "dst4_addr": "nunique",
        "dst_port": "nunique",
        "src_port": "nunique",
        "in_bytes": ["sum", "std"],
        "in_packets": ["sum", "std"],
        "bpp_ratio": "std",
        "is_tcp": "sum",
        "is_udp": "sum",
        "is_icmp": "sum",
        "syn_only": "sum",
        "has_rst": "sum",
        "well_known_port": "sum",
        "src_port_ephemeral": "sum",
        "src_port_well_known": "sum",
        "client_initiated": "sum",
        "server_initiated": "sum",
        "duration_sec": "mean",
        "iat": ["mean", "var"],
        "is_botnet_flow": "mean",
    }

    grouped = df.groupby(["src4_addr", "time_window"]).agg(agg_funcs)
    grouped.columns = ["_".join(filter(None, col)).strip() for col in grouped.columns.values]
    grouped = grouped.reset_index()

    grouped = grouped.rename(
        columns={
            "first_count": "flow_count",
            "dst4_addr_nunique": "unique_dst_ips",
            "dst_port_nunique": "unique_dst_ports",
            "src_port_nunique": "unique_src_ports",
            "in_bytes_sum": "total_bytes",
            "in_bytes_std": "bytes_std",
            "in_packets_sum": "total_packets",
            "in_packets_std": "packets_std",
            "bpp_ratio_std": "bpp_std",
            "is_tcp_sum": "tcp_count",
            "is_udp_sum": "udp_count",
            "is_icmp_sum": "icmp_count",
            "syn_only_sum": "count_syn_only",
            "has_rst_sum": "count_rst",
            "well_known_port_sum": "count_well_known_ports",
            "src_port_ephemeral_sum": "count_src_ephemeral",
            "src_port_well_known_sum": "count_src_well_known",
            "client_initiated_sum": "count_client_initiated",
            "server_initiated_sum": "count_server_initiated",
            "duration_sec_mean": "avg_duration",
            "iat_mean": "iat_mean",
            "iat_var": "iat_variance",
            "is_botnet_flow_mean": "botnet_flow_ratio",
        }
    )

    dst_entropy = _group_entropy(df, "src4_addr", "dst4_addr", "dst_ip_entropy")
    src_port_entropy = _group_entropy(df, "src4_addr", "src_port", "src_port_entropy")

    top_port_share = (
        df.groupby(["src4_addr", "time_window", "dst_port"])
        .size()
        .reset_index(name="dst_port_flow_count")
    )
    top_port_share["top_dst_port_share_pct"] = (
        top_port_share.groupby(["src4_addr", "time_window"])["dst_port_flow_count"]
        .transform("max")
        / top_port_share.groupby(["src4_addr", "time_window"])["dst_port_flow_count"].transform("sum").replace(0, 1)
    ) * 100
    top_port_share = (
        top_port_share[["src4_addr", "time_window", "top_dst_port_share_pct"]]
        .drop_duplicates()
    )

    dominant_p90 = (
        df.groupby(["src4_addr", "time_window"])["bpp_ratio_rounded"]
        .apply(lambda s: _count_dominant_values(s, 0.90))
        .reset_index(name="dominant_bpp_count_p90")
    )
    dominant_p75 = (
        df.groupby(["src4_addr", "time_window"])["bpp_ratio_rounded"]
        .apply(lambda s: _count_dominant_values(s, 0.75))
        .reset_index(name="dominant_bpp_count_p75")
    )

    bpp_quantiles = (
        df.groupby(["src4_addr", "time_window"])["bpp_ratio"]
        .agg(
            bpp_q25=lambda s: s.quantile(0.25),
            bpp_q75=lambda s: s.quantile(0.75),
        )
        .reset_index()
    )
    bpp_quantiles["bpp_iqr"] = bpp_quantiles["bpp_q75"] - bpp_quantiles["bpp_q25"]
    bpp_quantiles = bpp_quantiles[["src4_addr", "time_window", "bpp_iqr"]]

    df["minute_bucket"] = df["first"].dt.floor("min")
    minute_counts = (
        df.groupby(["src4_addr", "time_window", "minute_bucket"])
        .size()
        .reset_index(name="minute_flow_count")
    )
    burst = (
        minute_counts.groupby(["src4_addr", "time_window"])["minute_flow_count"]
        .max()
        .reset_index(name="burst_max_flows_per_min")
    )

    grouped = pd.merge(grouped, symmetry_counts, on=["src4_addr", "time_window"], how="left")
    grouped = pd.merge(grouped, dst_entropy, on=["src4_addr", "time_window"], how="left")
    grouped = pd.merge(grouped, src_port_entropy, on=["src4_addr", "time_window"], how="left")
    grouped = pd.merge(grouped, top_port_share, on=["src4_addr", "time_window"], how="left")
    grouped = pd.merge(grouped, dominant_p90, on=["src4_addr", "time_window"], how="left")
    grouped = pd.merge(grouped, dominant_p75, on=["src4_addr", "time_window"], how="left")
    grouped = pd.merge(grouped, bpp_quantiles, on=["src4_addr", "time_window"], how="left")
    grouped = pd.merge(grouped, burst, on=["src4_addr", "time_window"], how="left")

    for col in [
        "port_symmetry",
        "dst_ip_entropy",
        "src_port_entropy",
        "top_dst_port_share_pct",
        "dominant_bpp_count_p90",
        "dominant_bpp_count_p75",
        "bpp_iqr",
        "burst_max_flows_per_min",
        "bytes_std",
        "packets_std",
        "bpp_std",
        "iat_mean",
        "iat_variance",
    ]:
        grouped[col] = pd.to_numeric(grouped[col], errors="coerce").fillna(0)

    flow_counts = grouped["flow_count"].replace(0, 1)
    grouped["flows_per_second"] = grouped["flow_count"] / window_seconds
    grouped["bytes_per_second"] = grouped["total_bytes"] / window_seconds
    grouped["packets_per_second"] = grouped["total_packets"] / window_seconds

    grouped["avg_bytes_per_flow"] = grouped["total_bytes"] / flow_counts
    grouped["avg_packets_per_flow"] = grouped["total_packets"] / flow_counts

    grouped["pct_tcp"] = (grouped["tcp_count"] / flow_counts) * 100
    grouped["pct_udp"] = (grouped["udp_count"] / flow_counts) * 100
    grouped["pct_icmp"] = (grouped["icmp_count"] / flow_counts) * 100

    grouped["pct_well_known_ports"] = (grouped["count_well_known_ports"] / flow_counts) * 100
    grouped["pct_high_ports"] = 100 - grouped["pct_well_known_ports"]

    grouped["pct_ephemeral_src_ports"] = (grouped["count_src_ephemeral"] / flow_counts) * 100
    grouped["pct_well_known_src_ports"] = (grouped["count_src_well_known"] / flow_counts) * 100
    grouped["pct_client_initiated"] = (grouped["count_client_initiated"] / flow_counts) * 100
    grouped["pct_server_initiated"] = (grouped["count_server_initiated"] / flow_counts) * 100

    unique_ports = grouped["unique_dst_ports"].replace(0, 1)
    grouped["ip_port_ratio"] = grouped["unique_dst_ips"] / unique_ports

    total_packets = grouped["total_packets"].replace(0, 1)
    grouped["avg_payload_per_packet"] = grouped["total_bytes"] / total_packets

    grouped["pct_syn_only"] = (grouped["count_syn_only"] / flow_counts) * 100
    grouped["pct_rst"] = (grouped["count_rst"] / flow_counts) * 100

    iat_std = np.sqrt(grouped["iat_variance"].clip(lower=0))
    iat_means = grouped["iat_mean"].replace(0, 1)
    grouped["iat_cv"] = iat_std / iat_means
    grouped.loc[grouped["iat_mean"] == 0, "iat_cv"] = 0

    grouped["is_botnet"] = (grouped["botnet_flow_ratio"] >= botnet_ratio_threshold).astype(int)

    features_to_keep = [
        "src4_addr",
        "time_window",
        "flows_per_second",
        "bytes_per_second",
        "packets_per_second",
        "unique_dst_ips",
        "unique_dst_ports",
        "unique_src_ports",
        "avg_bytes_per_flow",
        "avg_packets_per_flow",
        "bytes_std",
        "packets_std",
        "bpp_std",
        "bpp_iqr",
        "dst_ip_entropy",
        "src_port_entropy",
        "top_dst_port_share_pct",
        "dominant_bpp_count_p75",
        "dominant_bpp_count_p90",
        "pct_tcp",
        "pct_udp",
        "pct_icmp",
        "pct_well_known_ports",
        "pct_high_ports",
        "pct_ephemeral_src_ports",
        "pct_well_known_src_ports",
        "pct_client_initiated",
        "pct_server_initiated",
        "avg_duration",
        "iat_mean",
        "iat_variance",
        "iat_cv",
        "port_symmetry",
        "ip_port_ratio",
        "avg_payload_per_packet",
        "pct_syn_only",
        "pct_rst",
        "burst_max_flows_per_min",
        "is_botnet",
    ]

    final_df = grouped[features_to_keep].copy()

    # Ensure model matrix stability.
    for col in final_df.columns:
        if col not in ["src4_addr", "time_window"]:
            final_df[col] = pd.to_numeric(final_df[col], errors="coerce").replace([np.inf, -np.inf], 0).fillna(0)

    print(f"Extracted {len(final_df):,} Feature V5 rows ({window_size} windows).")
    botnet_windows = int(final_df["is_botnet"].sum())
    normal_windows = int(len(final_df) - botnet_windows)
    print(f"  Botnet windows: {botnet_windows:,}")
    print(f"  Normal windows: {normal_windows:,}")
    if botnet_windows > 0:
        print(f"  Imbalance Ratio (scale_pos_weight): {normal_windows / botnet_windows:.2f}")

    print(f"Saving to {output_path}...")
    final_df.to_csv(output_path, index=False)
    print("Done!")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python extract_features_v5.py <input.json|input.ndjson> <output.csv>")
        sys.exit(1)

    in_file = sys.argv[1]
    out_file = sys.argv[2]

    if not os.path.exists(in_file):
        print(f"Error: input file '{in_file}' not found.")
        sys.exit(1)

    extract_features_v5(in_file, out_file)

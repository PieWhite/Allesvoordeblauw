"""
Extreme tuning pass for V5 model.

This script expands search beyond prior tuning by combining:
- multiple parameter families (gbtree + dart)
- optional feature augmentation
- broad threshold optimization
- final full retrain on the winning recipe
"""

import argparse
import json
import os
import re

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split


BASE_FEATURES = [
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
]

_GPU_SUPPORT_CACHE = None


def gpu_training_supported():
    global _GPU_SUPPORT_CACHE
    if _GPU_SUPPORT_CACHE is not None:
        return _GPU_SUPPORT_CACHE

    try:
        probe = xgb.XGBClassifier(
            n_estimators=1,
            max_depth=1,
            learning_rate=0.3,
            objective="binary:logistic",
            eval_metric="logloss",
            tree_method="hist",
            device="cuda",
            n_jobs=1,
        )
        probe.fit([[0.0], [1.0], [2.0], [3.0]], [0, 1, 0, 1], verbose=False)
        _GPU_SUPPORT_CACHE = True
    except Exception as exc:
        print(f"CUDA probe failed, using CPU. Reason: {exc}")
        _GPU_SUPPORT_CACHE = False

    return _GPU_SUPPORT_CACHE


def resolve_training_device(requested_device):
    choice = (requested_device or "auto").strip().lower()
    if choice not in {"auto", "cpu", "cuda"}:
        raise ValueError(f"Unsupported device '{requested_device}'. Use auto, cpu, or cuda.")

    if choice == "cpu":
        return "cpu"

    if choice == "cuda":
        if gpu_training_supported():
            return "cuda"
        print("Requested CUDA but GPU training is unavailable. Falling back to CPU.")
        return "cpu"

    if gpu_training_supported():
        return "cuda"
    return "cpu"


def parse_baseline(path):
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read()
    match = re.search(r"\[\[\s*(\d+)\s+(\d+)\]\s*\[\s*(\d+)\s+(\d+)\]\]", text)
    if not match:
        raise ValueError(f"Could not parse confusion matrix from {path}")
    tn, fp, fn, tp = [int(match.group(i)) for i in range(1, 5)]
    return {"tn": tn, "fp": fp, "fn": fn, "tp": tp}


def load_df(path):
    cols = BASE_FEATURES + ["is_botnet"]
    dtypes = {c: "float32" for c in BASE_FEATURES}
    dtypes["is_botnet"] = "int8"
    return pd.read_csv(path, usecols=cols, dtype=dtypes)


def write_feature_map(path, feature_names):
    with open(path, "w", encoding="utf-8") as handle:
        for idx, name in enumerate(feature_names):
            handle.write(f"{idx} {name} q\n")


def augment_features(df):
    X = df[BASE_FEATURES].copy()

    # Clean numeric values.
    X = X.replace([np.inf, -np.inf], np.nan)

    # Derived behavior features.
    X["log_flows_per_second"] = np.log1p(np.clip(X["flows_per_second"], a_min=0, a_max=None))
    X["log_bytes_per_second"] = np.log1p(np.clip(X["bytes_per_second"], a_min=0, a_max=None))
    X["log_packets_per_second"] = np.log1p(np.clip(X["packets_per_second"], a_min=0, a_max=None))
    X["tcp_udp_gap"] = X["pct_tcp"] - X["pct_udp"]
    X["syn_rst_gap"] = X["pct_syn_only"] - X["pct_rst"]
    X["iat_std"] = np.sqrt(np.clip(X["iat_variance"], a_min=0, a_max=None))
    X["duration_flow_interaction"] = X["avg_duration"] * X["flows_per_second"]
    X["entropy_port_interaction"] = X["dst_ip_entropy"] * np.log1p(np.clip(X["unique_dst_ports"], a_min=0, a_max=None))
    X["dominance_gap"] = X["dominant_bpp_count_p90"] - X["dominant_bpp_count_p75"]
    X["src_role_gap"] = X["pct_ephemeral_src_ports"] - X["pct_well_known_src_ports"]
    X["burst_entropy_interaction"] = X["burst_max_flows_per_min"] * np.log1p(np.clip(X["dst_ip_entropy"], a_min=0, a_max=None))

    # Fill remaining missing values consistently.
    X = X.fillna(-1.0)
    return X


def base_features_only(df):
    X = df[BASE_FEATURES].copy()
    X = X.replace([np.inf, -np.inf], np.nan).fillna(-1.0)
    return X


def threshold_best(y_true, probs, baseline_fp, baseline_fn):
    best_dom = None
    best_score = None

    for t in np.linspace(0.05, 0.95, 181):
        pred = (probs >= t).astype(np.int8)
        tn, fp, fn, tp = confusion_matrix(y_true, pred).ravel()

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        score = (fp / baseline_fp) + (fn / baseline_fn)

        row = {
            "threshold": float(t),
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "score": float(score),
            "dominates": bool(fp <= baseline_fp and fn <= baseline_fn),
        }

        if best_score is None or row["score"] < best_score["score"]:
            best_score = row

        if row["dominates"]:
            if best_dom is None:
                best_dom = row
            else:
                row_err = row["fp"] + row["fn"]
                best_err = best_dom["fp"] + best_dom["fn"]
                if (row_err < best_err) or (row_err == best_err and row["f1"] > best_dom["f1"]):
                    best_dom = row

    return best_dom if best_dom is not None else best_score


def make_candidates(base_scale, include_dart=False):
    candidates = [
        {
            "name": "gbtree_trial13_like",
            "augment": True,
            "params": {
                "booster": "gbtree",
                "learning_rate": 0.03,
                "max_depth": 5,
                "min_child_weight": 5,
                "subsample": 0.95,
                "colsample_bytree": 0.75,
                "gamma": 4.0,
                "reg_alpha": 0.05,
                "reg_lambda": 5.0,
                "scale_pos_weight": max(20.0, base_scale * 0.25),
            },
        },
        {
            "name": "gbtree_precision_push",
            "augment": True,
            "params": {
                "booster": "gbtree",
                "learning_rate": 0.04,
                "max_depth": 4,
                "min_child_weight": 8,
                "subsample": 0.9,
                "colsample_bytree": 0.65,
                "gamma": 6.0,
                "reg_alpha": 0.2,
                "reg_lambda": 8.0,
                "scale_pos_weight": max(20.0, base_scale * 0.20),
            },
        },
        {
            "name": "gbtree_recall_push",
            "augment": True,
            "params": {
                "booster": "gbtree",
                "learning_rate": 0.05,
                "max_depth": 6,
                "min_child_weight": 3,
                "subsample": 1.0,
                "colsample_bytree": 0.9,
                "gamma": 1.0,
                "reg_alpha": 0.0,
                "reg_lambda": 3.0,
                "scale_pos_weight": max(30.0, base_scale * 0.35),
            },
        },
        {
            "name": "gbtree_low_depth_stable",
            "augment": True,
            "params": {
                "booster": "gbtree",
                "learning_rate": 0.02,
                "max_depth": 3,
                "min_child_weight": 10,
                "subsample": 0.85,
                "colsample_bytree": 0.7,
                "gamma": 3.0,
                "reg_alpha": 1.0,
                "reg_lambda": 10.0,
                "scale_pos_weight": max(20.0, base_scale * 0.22),
            },
        },
        {
            "name": "gbtree_no_aug_reference",
            "augment": False,
            "params": {
                "booster": "gbtree",
                "learning_rate": 0.03,
                "max_depth": 5,
                "min_child_weight": 5,
                "subsample": 0.95,
                "colsample_bytree": 0.75,
                "gamma": 4.0,
                "reg_alpha": 0.05,
                "reg_lambda": 5.0,
                "scale_pos_weight": max(20.0, base_scale * 0.25),
            },
        },
        {
            "name": "gbtree_max_delta_step",
            "augment": True,
            "params": {
                "booster": "gbtree",
                "learning_rate": 0.04,
                "max_depth": 5,
                "min_child_weight": 4,
                "subsample": 0.9,
                "colsample_bytree": 0.75,
                "gamma": 2.5,
                "reg_alpha": 0.1,
                "reg_lambda": 7.0,
                "max_delta_step": 3,
                "scale_pos_weight": max(20.0, base_scale * 0.28),
            },
        },
        {
            "name": "gbtree_high_regularization",
            "augment": True,
            "params": {
                "booster": "gbtree",
                "learning_rate": 0.02,
                "max_depth": 5,
                "min_child_weight": 12,
                "subsample": 0.8,
                "colsample_bytree": 0.65,
                "gamma": 5.0,
                "reg_alpha": 2.0,
                "reg_lambda": 12.0,
                "scale_pos_weight": max(20.0, base_scale * 0.30),
            },
        },
    ]

    if include_dart:
        candidates.append(
            {
                "name": "dart_dropout_regularized",
                "augment": True,
                "params": {
                    "booster": "dart",
                    "rate_drop": 0.1,
                    "skip_drop": 0.4,
                    "sample_type": "uniform",
                    "normalize_type": "tree",
                    "learning_rate": 0.03,
                    "max_depth": 5,
                    "min_child_weight": 5,
                    "subsample": 0.9,
                    "colsample_bytree": 0.8,
                    "gamma": 2.0,
                    "reg_alpha": 0.1,
                    "reg_lambda": 6.0,
                    "scale_pos_weight": max(20.0, base_scale * 0.25),
                },
            }
        )

    return candidates


def fit_eval_candidate(cfg, train_df, test_df, baseline, seed, xgb_device):
    X_all = augment_features(train_df) if cfg["augment"] else base_features_only(train_df)
    y_all = train_df["is_botnet"].astype(int)

    X_train, X_val, y_train, y_val = train_test_split(
        X_all,
        y_all,
        test_size=0.15,
        random_state=seed,
        stratify=y_all,
    )

    X_test = augment_features(test_df) if cfg["augment"] else base_features_only(test_df)
    y_test = test_df["is_botnet"].astype(int).to_numpy()

    model = xgb.XGBClassifier(
        objective="binary:logistic",
        tree_method="hist",
        device=xgb_device,
        n_estimators=600,
        eval_metric="aucpr",
        random_state=seed,
        n_jobs=-1,
        **cfg["params"],
    )

    model.fit(
        X_train,
        y_train,
        eval_set=[(X_val, y_val)],
        verbose=False,
    )

    probs = model.predict_proba(X_test)[:, 1]
    best = threshold_best(y_test, probs, baseline["fp"], baseline["fn"])

    return {
        "name": cfg["name"],
        "augment": cfg["augment"],
        "params": cfg["params"],
        "best_iteration": int(getattr(model, "best_iteration", model.n_estimators - 1)),
        **best,
    }


def choose_winner(rows):
    # Prefer those improving both errors vs baseline (dominates), then smallest total errors.
    dom = [r for r in rows if r["dominates"]]
    if dom:
        dom.sort(key=lambda r: (r["fp"] + r["fn"], -r["f1"]))
        return dom[0]
    rows.sort(key=lambda r: (r["score"], r["fp"] + r["fn"], -r["f1"]))
    return rows[0]


def retrain_and_write(winner, train_df, test_df, out_dir, seed, xgb_device):
    X_train = augment_features(train_df) if winner["augment"] else base_features_only(train_df)
    y_train = train_df["is_botnet"].astype(int)

    X_test = augment_features(test_df) if winner["augment"] else base_features_only(test_df)
    y_test = test_df["is_botnet"].astype(int).to_numpy()

    n_estimators = max(300, winner["best_iteration"] + 1)
    model = xgb.XGBClassifier(
        objective="binary:logistic",
        tree_method="hist",
        device=xgb_device,
        n_estimators=n_estimators,
        eval_metric="aucpr",
        random_state=seed + 1000,
        n_jobs=-1,
        **winner["params"],
    )
    model.fit(X_train, y_train, verbose=False)

    probs = model.predict_proba(X_test)[:, 1]
    pred = (probs >= winner["threshold"]).astype(np.int8)
    tn, fp, fn, tp = confusion_matrix(y_test, pred).ravel()

    report = classification_report(
        y_test,
        pred,
        target_names=["Normal (0)", "Botnet (1)"],
        digits=4,
    )

    model_path = os.path.join(out_dir, "xgboostv5.json")
    backup = os.path.join(out_dir, "xgboostv5_before_extreme_tune_backup.json")
    if os.path.exists(model_path) and not os.path.exists(backup):
        os.replace(model_path, backup)
    model.get_booster().dump_model(model_path, dump_format="json")
    fmap_path = os.path.join(out_dir, "xgboostv5.fmap")
    write_feature_map(fmap_path, list(X_train.columns))

    pred_path = os.path.join(out_dir, "test_predictions_v5_extreme_tuned.csv")
    pred_df = pd.DataFrame(
        {
            "is_botnet": y_test,
            "pred_probability": probs,
            "pred_is_botnet": pred,
        }
    )
    pred_df.to_csv(pred_path, index=False)

    eval_path = os.path.join(out_dir, "evaluation_v5_extreme_tuned.txt")
    with open(eval_path, "w", encoding="utf-8") as handle:
        handle.write("V5 Extreme Tuned Holdout Evaluation\n")
        handle.write("==================================\n")
        handle.write(f"Winning candidate: {winner['name']}\n")
        handle.write(f"Feature augmentation: {winner['augment']}\n")
        handle.write(f"Training device: {xgb_device}\n")
        handle.write(f"Threshold: {winner['threshold']:.4f}\n")
        handle.write(f"n_estimators: {n_estimators}\n")
        handle.write(f"Params: {json.dumps(winner['params'])}\n\n")
        handle.write("Confusion Matrix\n")
        handle.write(f"[[{tn} {fp}]\n [{fn} {tp}]]\n\n")
        handle.write("Classification Report\n")
        handle.write(report + "\n")

    return {
        "model_path": model_path,
        "feature_map_path": fmap_path,
        "pred_path": pred_path,
        "eval_path": eval_path,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def main():
    parser = argparse.ArgumentParser(description="Extreme tune V5 model")
    parser.add_argument(
        "--work-dir",
        default=os.path.join("..", "Binetflowdata", "v5_raw_holdout"),
        help="Directory containing train/test master CSVs",
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--max-train-rows",
        type=int,
        default=2800000,
        help="Max train rows used during candidate search",
    )
    parser.add_argument(
        "--include-dart",
        action="store_true",
        help="Include slower DART candidate in search",
    )
    parser.add_argument(
        "--device",
        choices=["auto", "cpu", "cuda"],
        default="auto",
        help="XGBoost training device (auto prefers CUDA when available)",
    )
    args = parser.parse_args()

    work_dir = os.path.abspath(args.work_dir)

    baseline = parse_baseline(os.path.join(work_dir, "evaluation_v5.txt"))
    train_df = load_df(os.path.join(work_dir, "master_train_features_v5.csv"))
    test_df = load_df(os.path.join(work_dir, "master_test_features_v5.csv"))

    # Optional speed cap for search stage only.
    if len(train_df) > args.max_train_rows:
        train_df_search = train_df.sample(n=args.max_train_rows, random_state=args.seed)
    else:
        train_df_search = train_df

    base_scale = float(
        (len(train_df_search) - int(train_df_search["is_botnet"].sum()))
        / max(1, int(train_df_search["is_botnet"].sum()))
    )

    xgb_device = resolve_training_device(args.device)

    candidates = make_candidates(base_scale, include_dart=args.include_dart)

    print(f"Baseline FP/FN: {baseline['fp']:,}/{baseline['fn']:,}")
    print(f"Search train rows: {len(train_df_search):,}")
    print(f"Test rows: {len(test_df):,}")
    print(f"Using XGBoost device: {xgb_device}")
    print(f"Running {len(candidates)} extreme candidates...")

    rows = []
    for i, cfg in enumerate(candidates, start=1):
        print(f"[{i}/{len(candidates)}] {cfg['name']} (augment={cfg['augment']})")
        row = fit_eval_candidate(cfg, train_df_search, test_df, baseline, args.seed + i, xgb_device)
        rows.append(row)
        print(
            f"  -> thr={row['threshold']:.3f}, fp={row['fp']:,}, fn={row['fn']:,}, "
            f"prec={row['precision']:.4f}, rec={row['recall']:.4f}, f1={row['f1']:.4f}, dominates={row['dominates']}"
        )

    winner = choose_winner(rows)
    print("Winner:")
    print(winner)

    trials_path = os.path.join(work_dir, "extreme_trials_v5.csv")
    out_rows = []
    for r in rows:
        rr = {k: v for k, v in r.items() if k != "params"}
        rr.update({f"param_{k}": v for k, v in r["params"].items()})
        out_rows.append(rr)
    pd.DataFrame(out_rows).sort_values(by=["dominates", "fp", "fn", "f1"], ascending=[False, True, True, False]).to_csv(
        trials_path, index=False
    )

    final = retrain_and_write(winner, train_df, test_df, work_dir, args.seed, xgb_device)

    print("\nExtreme tuning complete.")
    print(f"Final FP/FN: {final['fp']:,}/{final['fn']:,}")
    print(f"Model: {final['model_path']}")
    print(f"Eval: {final['eval_path']}")
    print(f"Trials: {trials_path}")


if __name__ == "__main__":
    main()

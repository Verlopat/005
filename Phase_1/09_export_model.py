"""
Stage 09 — Export the trained detection layer as a deployable artifact.

Stages 06 and 08 saved hyperparameters and probability matrices, not the
fitted model. This stage refits the winner from the cached tuned parameters,
refits the isotonic calibrator on the validation fold, and writes a single
bundle the inference service can load.

WHY THIS IS A SEPARATE STAGE, not just a pickle:

  The alert contract carries a `model_version` field, and the blockchain
  layer anchors model provenance so that any alert can be traced back to the
  exact model that produced it. That requires a deterministic identifier
  computed over everything that affects a prediction — the booster, the
  ordered feature list, the label order, the calibrator, and the confidence
  gate. A pickle alone gives none of that.

  The model_id below is a SHA-256 over exactly those components. Anchor it
  on-chain once per retrain; every alert then references it.

Outputs (outputs/09_model/):
  detector_bundle.joblib   everything needed to score a flow
  booster.txt              raw LightGBM model, framework-portable
  model_card.json          provenance, metrics, schema, gate
  predict_example.py       minimal, runnable inference example

Run: python 09_export_model.py
"""

from __future__ import annotations

import hashlib
import json
import platform
import sys
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd
from sklearn.calibration import IsotonicRegression
from sklearn.metrics import f1_score, accuracy_score

import config

OUTDIR = config.OUTPUTS_DIR / "09_model"
TUNE_DIR = config.OUTPUTS_DIR / "06_tuning"
ICR_DIR = config.OUTPUTS_DIR / "08_calibration_icr"

WINNER = "flat"

# Stage 06 fitted a vector of SEVEN per-class thresholds on the validation
# fold by coordinate ascent (the `flat_tuned_tau` row). Dividing each class
# column by its threshold before argmax lowers the bar for rare classes.
# Setting this False exports the plain argmax variant instead.
#
# Do not confuse these with the single scalar anchoring gate below: the
# thresholds decide WHICH CLASS is predicted, the gate decides WHAT GOES
# ON-CHAIN. They are unrelated quantities that both ended up called "tau".
USE_CLASS_THRESHOLDS = True

# Operating point carried into deployment. Chosen from stage 08 as the point
# minimising on-chain volume subject to ICR >= 0.95: near-total anchor
# precision at ~11% ledger volume. Set to None to skip gate metadata.
ICR_TARGET = 0.95


def load_class_thresholds(labels):
    """Recover the stage-06 threshold vector, in canonical label order."""
    results = TUNE_DIR / "results.json"
    if results.exists():
        payload = json.loads(results.read_text())
        tau_map = payload.get(WINNER, {}).get("tau")
        if tau_map:
            return np.array([float(tau_map[l]) for l in labels])
    npz = TUNE_DIR / f"{WINNER}_test.npz"
    if npz.exists():
        blob = np.load(npz, allow_pickle=True)
        if "tau" in blob:
            file_labels = [str(c) for c in blob["classes"]]
            tau = np.asarray(blob["tau"], dtype="float64")
            return np.array([tau[file_labels.index(l)] for l in labels])
    return None


def sha256_of(*parts: bytes) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.hexdigest()


def main() -> None:
    try:
        import joblib
    except ImportError:
        sys.exit("joblib is required. Run: pip install joblib")

    params_file = TUNE_DIR / f"{WINNER}_params.json"
    if not params_file.exists():
        sys.exit(f"Missing {params_file}. Run 06_tune.py first.")
    OUTDIR.mkdir(parents=True, exist_ok=True)

    params = json.loads(params_file.read_text())
    feats = json.loads(config.SELECTED_FEATURES_JSON.read_text())["selected_features"]
    COARSE = config.COARSE_LABEL_COLUMN
    needed = feats + [COARSE]

    print(f"exporting: {WINNER} | {len(feats)} features")

    # ---- refit on train --------------------------------------------------
    train_df = pd.read_parquet(config.TRAIN_PARQUET, columns=needed)
    X_tr = train_df[feats].astype("float32")
    y_tr = train_df[COARSE].astype(str).to_numpy(dtype=object)
    del train_df

    from lightgbm import LGBMClassifier
    labels = [c for c in config.COARSE_CATEGORIES if c in set(y_tr)]
    t0 = time.perf_counter()
    model = LGBMClassifier(objective="multiclass", num_class=len(labels),
                           n_jobs=-1, random_state=config.RANDOM_SEED,
                           verbosity=-1, **params)
    model.fit(X_tr, y_tr)
    fit_min = (time.perf_counter() - t0) / 60
    print(f"  refit on {len(X_tr):,} rows: {fit_min:.1f} min")
    del X_tr, y_tr

    # The classifier's internal class order need not match the canonical
    # order. Store the permutation so downstream code never has to guess.
    model_classes = [str(c) for c in model.classes_]
    order = [model_classes.index(l) for l in labels]
    benign_idx = labels.index("Benign")

    # ---- refit the calibrator on val ------------------------------------
    val_df = pd.read_parquet(config.VAL_PARQUET, columns=needed)
    y_va = val_df[COARSE].astype(str).to_numpy(dtype=object)
    pv = model.predict_proba(val_df[feats].astype("float32"))[:, order]
    raw_val = 1.0 - pv[:, benign_idx]
    del val_df, pv

    calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    calibrator.fit(raw_val, (y_va != "Benign").astype(int))
    print(f"  calibrator fitted on {len(y_va):,} validation rows")
    del raw_val, y_va

    # ---- verify against the stage-06 result ------------------------------
    test_df = pd.read_parquet(config.TEST_PARQUET, columns=needed)
    y_te = test_df[COARSE].astype(str).to_numpy(dtype=object)
    proba_te = model.predict_proba(test_df[feats].astype("float32"))[:, order]
    del test_df
    thresholds = load_class_thresholds(labels) if USE_CLASS_THRESHOLDS else None
    if thresholds is None:
        thresholds = np.ones(len(labels))
        variant = "flat_argmax"
    else:
        variant = "flat_tuned_tau"
        print("  class thresholds: "
              + ", ".join(f"{l}={t:.3g}" for l, t in zip(labels, thresholds)))

    pred = np.asarray(labels)[(proba_te / thresholds).argmax(axis=1)]
    macro = f1_score(y_te, pred, average="macro", labels=labels, zero_division=0)
    acc = accuracy_score(y_te, pred)
    yb = (y_te != "Benign").astype(int)
    bf1 = f1_score(yb, (pred != "Benign").astype(int), zero_division=0)
    print(f"  verification on test ({variant}): macro-F1 {macro:.4f} | "
          f"acc {acc:.4f} | binary-F1 {bf1:.4f}")
    print("  (stage 06 reported 0.8172 for flat_tuned_tau, 0.8171 for "
          "flat_argmax — a large gap here means the refit is not reproducing "
          "that run)")

    # ---- confidence gate -------------------------------------------------
    gate = None
    ops_file = ICR_DIR / "icr_operating_points.csv"
    if ICR_TARGET is not None and ops_file.exists():
        ops = pd.read_csv(ops_file)
        row = ops[np.isclose(ops["ICR_target"], ICR_TARGET)]
        if not row.empty:
            r = row.iloc[0]
            gate = {"icr_target": float(ICR_TARGET), "tau": float(r["tau"]),
                    "icr": float(r["ICR"]),
                    "on_chain_volume": float(r["on_chain_volume"]),
                    "write_reduction": float(r["write_reduction"]),
                    "anchor_precision": float(r["anchor_precision"])}
            print(f"  anchoring gate: tau={gate['tau']:.6f} "
                  f"(ICR {gate['icr']:.4f}, volume {gate['on_chain_volume']:.4f})")

    # ---- write artifacts -------------------------------------------------
    booster_path = OUTDIR / "booster.txt"
    model.booster_.save_model(str(booster_path))

    bundle = {
        "model": model,
        "calibrator": calibrator,
        "features": feats,           # ORDER MATTERS at inference time
        "labels": labels,
        "class_order": order,
        "benign_index": benign_idx,
        "class_thresholds": thresholds,   # divide, then argmax
        "variant": variant,
        "gate": gate,
    }
    bundle_path = OUTDIR / "detector_bundle.joblib"
    joblib.dump(bundle, bundle_path, compress=3)

    model_id = sha256_of(
        booster_path.read_bytes(),
        json.dumps(feats).encode(),
        json.dumps(labels).encode(),
        json.dumps(params, sort_keys=True).encode(),
        # The thresholds change predictions, so they belong in the identity.
        json.dumps([float(t) for t in thresholds]).encode(),
    )

    card = {
        "model_id_sha256": model_id,
        "model_version": f"{variant}-{model_id[:12]}",
        "variant": variant,
        "architecture": "LightGBM multiclass, 7 coarse threat categories",
        "class_thresholds": {l: float(t) for l, t in zip(labels, thresholds)},
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "hyperparameters": params,
        "features": feats,
        "n_features": len(feats),
        "labels": labels,
        "calibration": "isotonic, fitted on the validation fold",
        "anchoring_gate": gate,
        "training": {
            "dataset": "NF-CSE-CIC-IDS2018-v2",
            "split": "60/20/20 by row position, no shuffling",
            "benign_downsampling": f"train only, keep fraction "
                                   f"{config.BENIGN_KEEP_FRACTION}",
            "val_test_prior": "natural (no downsampling)",
            "fit_minutes": fit_min,
        },
        "test_metrics": {"macro_f1": float(macro), "accuracy": float(acc),
                         "binary_f1": float(bf1)},
        "notes": [
            "Identifiers (IPs, ports) are never model features; they travel "
            "alongside the feature vector as alert metadata.",
            "model_id_sha256 covers the booster, the ordered feature list, "
            "the label order and the hyperparameters. Anchor it once per "
            "retrain so every alert can be traced to the model that produced it.",
            "Infiltration carries markedly lower confidence than other "
            "classes and is excluded first as the gate rises — see "
            "08_calibration_icr/icr_per_class.csv.",
        ],
    }
    (OUTDIR / "model_card.json").write_text(json.dumps(card, indent=2))

    (OUTDIR / "predict_example.py").write_text('''"""Minimal inference example. Run from the project root."""
import joblib, numpy as np, pandas as pd

b = joblib.load("outputs/09_model/detector_bundle.joblib")
model, cal, feats, labels = b["model"], b["calibrator"], b["features"], b["labels"]
thresholds = b["class_thresholds"]

# Columns must appear in exactly this order.
flows = pd.read_parquet("work/splits/test.parquet", columns=feats).head(1000)

proba = model.predict_proba(flows.astype("float32"))[:, b["class_order"]]

# Per-class thresholds, then argmax. This is the `flat_tuned_tau` rule;
# thresholds of all-ones reduce it to plain argmax.
verdict = np.asarray(labels)[(proba / thresholds).argmax(axis=1)]

# Calibrated attack confidence, independent of which class was chosen.
confidence = cal.predict(1.0 - proba[:, b["benign_index"]])

if b["gate"]:
    anchor = confidence >= b["gate"]["tau"]
    print(f"anchoring {anchor.sum()} of {len(flows)} flows "
          f"at gate tau={b['gate']['tau']:.6f}")

print(f"variant: {b['variant']}")
print(pd.DataFrame({"verdict": verdict,
                    "confidence": confidence}).head(10).to_string())
''')

    print(f"\nmodel_id : {model_id}")
    print(f"version  : {card['model_version']}")
    for p in (bundle_path, booster_path, OUTDIR / "model_card.json",
              OUTDIR / "predict_example.py"):
        print(f"  {p.name:26} {p.stat().st_size / 1e6:.2f} MB")
    print(f"\nsaved -> {OUTDIR}")


if __name__ == "__main__":
    main()
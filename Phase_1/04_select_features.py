"""
Stage 04 — Feature selection.

Four passes, in order, each printed as it runs:
  (A) drop zero-variance features
  (B) drop one of each pair of features correlated above
      config.CORRELATION_CUTOFF (keep the higher-variance one of the pair)
  (C) rank survivors by LightGBM gain importance (train fold)
  (D) confirm the top 25 with permutation importance on the validation fold

Retrains LightGBM on the selected (top 25) feature set vs. the full original
feature set and prints the macro-F1 difference, measured on the held-out
test fold.

Writes outputs/selected_features.json, outputs/lgbm_importance.csv,
outputs/permutation_importance.csv.

Run: python 04_select_features.py
"""

from __future__ import annotations

import json
import sys
import time

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.feature_selection import VarianceThreshold
from sklearn.inspection import permutation_importance
from sklearn.metrics import f1_score

import config

TOP_N = 25

# Permutation importance is a *ranking confirmation* pass, not a reported
# metric, so it runs on a sample of the validation fold. Since 02_prepare
# stopped downsampling benign outside the train fold, val is ~3.8M rows;
# n_repeats=5 over ~35 features would mean ~175 full predict passes, and
# n_jobs=-1 copies the whole fold into every worker process.
PERM_SAMPLE = 400_000
PERM_N_JOBS = 2

# Gain importance from an unweighted model is dominated by the classes that
# contribute most total loss (Benign, DDoS). Features that only discriminate
# a rare class such as Web Attacks contribute little gain and can be ranked
# out of the top 25 even when they are the only signal that class has.
# Left False to keep continuity with the committed stage-04 methodology;
# flip to True to re-run selection under the same weighting stage 05 uses.
BALANCED_SELECTION = False


def train_lgbm(X: pd.DataFrame, y: pd.Series) -> LGBMClassifier:
    clf = LGBMClassifier(
        objective="multiclass",
        importance_type="gain",
        class_weight="balanced" if BALANCED_SELECTION else None,
        random_state=config.RANDOM_SEED,
        n_jobs=-1,
        verbosity=-1,
    )
    clf.fit(X, y)
    return clf


def per_class_f1(y_true, y_pred) -> pd.Series:
    labels = [c for c in config.COARSE_CATEGORIES if c in set(y_true)]
    scores = f1_score(y_true, y_pred, labels=labels, average=None, zero_division=0)
    return pd.Series(scores, index=labels)


def main() -> None:
    if not config.TRAIN_PARQUET.exists() or not config.COLUMNS_JSON.exists():
        print("Missing work/splits or work/columns.json. Run 02_prepare.py first.")
        sys.exit(1)

    columns_payload = json.loads(config.COLUMNS_JSON.read_text(encoding="utf-8"))
    label_column = columns_payload["multiclass_label"] or columns_payload["binary_label"]
    all_features = list(columns_payload["features"])

    # Read only what this stage uses. The parquets also carry identifiers and
    # the fine-grained label, which would otherwise sit in memory across three
    # folds totalling ~9.8M rows for no reason.
    needed = all_features + [label_column]
    train_df = pd.read_parquet(config.TRAIN_PARQUET, columns=needed)
    val_df = pd.read_parquet(config.VAL_PARQUET, columns=needed)

    y_train, y_val = train_df[label_column], val_df[label_column]
    print(f"train {len(train_df):,} | val {len(val_df):,} rows, "
          f"{len(all_features)} candidate features")
    if BALANCED_SELECTION:
        print("Selection models use class_weight='balanced'.")

    # --- Pass A: zero variance ------------------------------------------
    X_train_full = train_df[all_features]
    vt = VarianceThreshold(threshold=0.0)
    vt.fit(X_train_full)
    survivors_a = list(X_train_full.columns[vt.get_support()])
    dropped_a = [c for c in all_features if c not in survivors_a]
    print(f"(A) zero variance: dropped {len(dropped_a)} of {len(all_features)}: {dropped_a}")
    del X_train_full

    # --- Pass B: pairwise correlation ------------------------------------
    corr = train_df[survivors_a].corr().abs()
    variances = train_df[survivors_a].var()
    to_drop: set[str] = set()
    upper = corr.where(np.triu(np.ones(corr.shape), k=1).astype(bool))
    for col in upper.columns:
        for row in upper.index:
            value = upper.loc[row, col]
            if pd.notna(value) and value > config.CORRELATION_CUTOFF:
                loser = row if variances[row] < variances[col] else col
                to_drop.add(loser)
    survivors_b = [c for c in survivors_a if c not in to_drop]
    print(f"(B) correlation > {config.CORRELATION_CUTOFF}: dropped {len(to_drop)} of "
          f"{len(survivors_a)}: {sorted(to_drop)}")
    del corr, upper

    # --- Pass C: LightGBM gain importance ---------------------------------
    started = time.perf_counter()
    model_c = train_lgbm(train_df[survivors_b], y_train)
    importance_c = pd.Series(model_c.feature_importances_, index=survivors_b, name="gain")
    importance_c = importance_c.sort_values(ascending=False)
    importance_c.to_csv(config.LGBM_IMPORTANCE_CSV, header=True)
    print(f"(C) LightGBM gain importance computed on {len(survivors_b)} features "
          f"in {(time.perf_counter() - started) / 60:.1f} min, wrote {config.LGBM_IMPORTANCE_CSV}")

    top_n = list(importance_c.head(TOP_N).index)
    print(f"    top {len(top_n)} by gain: {top_n}")

    # --- Pass D: permutation importance confirmation on validation fold ---
    val_perm = (val_df.sample(PERM_SAMPLE, random_state=config.RANDOM_SEED)
                if len(val_df) > PERM_SAMPLE else val_df)
    started = time.perf_counter()
    perm = permutation_importance(
        model_c, val_perm[survivors_b], val_perm[label_column],
        n_repeats=5, random_state=config.RANDOM_SEED, n_jobs=PERM_N_JOBS,
    )
    perm_series = pd.Series(perm.importances_mean, index=survivors_b,
                            name="permutation_importance")
    perm_top_n = perm_series.loc[top_n].sort_values(ascending=False)
    perm_top_n.to_csv(config.PERMUTATION_IMPORTANCE_CSV, header=True)
    print(f"(D) permutation importance on {len(val_perm):,} sampled val rows "
          f"({(time.perf_counter() - started) / 60:.1f} min), wrote "
          f"{config.PERMUTATION_IMPORTANCE_CSV}")
    for feature, value in perm_top_n.items():
        print(f"    {feature:<35} {value:.5f}")

    # A selected feature whose permutation importance is <= 0 was ranked in by
    # gain but does not actually help held-out predictions. Worth knowing.
    inert = [f for f, v in perm_top_n.items() if v <= 0]
    if inert:
        print(f"    NOTE: {len(inert)} selected feature(s) have non-positive "
              f"permutation importance: {inert}")

    selected_features = top_n
    config.SELECTED_FEATURES_JSON.write_text(
        json.dumps({"selected_features": selected_features}, indent=2), encoding="utf-8"
    )
    print(f"\nWrote {config.SELECTED_FEATURES_JSON} ({len(selected_features)} features)")

    del val_df, val_perm, model_c, y_val

    # --- Retrain: selected set vs. full original feature set, on test ----
    test_df = pd.read_parquet(config.TEST_PARQUET, columns=needed)
    y_test = test_df[label_column]
    print(f"\ntest {len(test_df):,} rows")

    model_selected = train_lgbm(train_df[selected_features], y_train)
    preds_selected = model_selected.predict(test_df[selected_features])
    f1_selected = f1_score(y_test, preds_selected, average="macro", zero_division=0)
    by_class_selected = per_class_f1(y_test, preds_selected)
    del model_selected, preds_selected

    model_full = train_lgbm(train_df[all_features], y_train)
    preds_full = model_full.predict(test_df[all_features])
    f1_full = f1_score(y_test, preds_full, average="macro", zero_division=0)
    by_class_full = per_class_f1(y_test, preds_full)
    del model_full, preds_full

    print(f"\nTest macro-F1, full feature set ({len(all_features)} features):      {f1_full:.4f}")
    print(f"Test macro-F1, selected feature set ({len(selected_features)} features): {f1_selected:.4f}")
    print(f"Difference (selected - full): {f1_selected - f1_full:+.4f}")

    # Macro-F1 alone hides which classes paid for the reduction.
    comparison = pd.DataFrame({
        "full": by_class_full,
        "selected": by_class_selected,
    })
    comparison["delta"] = comparison["selected"] - comparison["full"]
    print("\nPer-class F1, full vs selected:")
    print(comparison.to_string(float_format=lambda v: f"{v:+.4f}"))

    print("\nNext: python 05_compare_models.py")


if __name__ == "__main__":
    main()
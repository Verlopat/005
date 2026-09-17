"""
Batch-score a CSV of NetFlow flows against the trained detector bundle.

  python predict_csv.py input.csv
  python predict_csv.py input.csv -o results.csv
  python predict_csv.py input.csv --limit 20
  python predict_csv.py input.csv --names    only the predicted class name per row, nothing else

Input: a CSV whose columns are (a subset of) the 25 feature names the model
was trained on, in any order, with no label column required. Predicts one
row of output per row of input.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

import config

MODEL_DIR = config.OUTPUTS_DIR / "09_model"
BUNDLE_PATH = MODEL_DIR / "detector_bundle.joblib"
STATS_PATH = MODEL_DIR / "feature_stats.csv"
SEVERITY_PATH = config.OUTPUTS_DIR / "10_contract" / "severity_map.json"

GROUND_TRUTH_NAMES = {config.COARSE_LABEL_COLUMN.lower(): "coarse", "attack": "fine", "label": "binary"}


def load_bundle():
    if not BUNDLE_PATH.exists():
        print(f"Error: missing {BUNDLE_PATH}. Run 09_export_model.py first.")
        sys.exit(1)
    bundle = joblib.load(BUNDLE_PATH)
    if not STATS_PATH.exists():
        print(f"Error: missing {STATS_PATH}.")
        sys.exit(1)
    stats = pd.read_csv(STATS_PATH, index_col=0)
    severity = json.loads(SEVERITY_PATH.read_text(encoding="utf-8")) if SEVERITY_PATH.exists() else {}
    return bundle, stats, severity


def normalized_map(columns) -> dict[str, str]:
    return {str(c).strip().lower(): c for c in columns}


def find_ground_truth_column(columns) -> tuple[str | None, str | None]:
    norm = normalized_map(columns)
    for kind_priority in ("coarse", "fine", "binary"):
        for name, kind in GROUND_TRUTH_NAMES.items():
            if kind == kind_priority and name in norm:
                return norm[name], kind
    return None, None


def build_feature_matrix(df: pd.DataFrame, features: list[str], stats: pd.DataFrame, quiet: bool = False):
    norm = normalized_map(df.columns)
    matched = {f: norm.get(f.strip().lower()) for f in features}
    missing = [f for f, src in matched.items() if src is None]

    if len(missing) == len(features):
        print("Error: none of the required feature columns were found in the input CSV.")
        sys.exit(1)

    if missing:
        print(f"\n{len(missing)} of {len(features)} feature columns are missing from the input:")
        for f in missing:
            print(f"  {f}")
        print("Missing features will be filled with their training median from feature_stats.csv.")
        print("A filled feature is one the model is not actually seeing for these rows.")
        answer = input("Continue? [y/N]: ").strip().lower()
        if answer != "y":
            print("Aborted.")
            sys.exit(1)

    matched_source_cols = {src for src in matched.values() if src is not None}
    ground_truth_col, ground_truth_kind = find_ground_truth_column(df.columns)
    extra_cols = [c for c in df.columns if c not in matched_source_cols and c != ground_truth_col]
    if not quiet:
        print(f"Ignoring {len(extra_cols)} extra column(s) not among the model's features.")

    X = pd.DataFrame(index=df.index)
    non_numeric_count = 0
    masked_count = 0
    for f in features:
        src = matched[f]
        if src is None:
            X[f] = np.nan
            continue
        raw = df[src]
        numeric = pd.to_numeric(raw, errors="coerce")
        non_numeric_count += int((numeric.isna() & ~raw.isna()).sum())
        # Same divide-by-near-zero exporter artifact 02_prepare.py cleans out
        # of the training data (see config.NUMERIC_OUTLIER_ABS_CUTOFF) — a
        # value this large reaching the model would be nonsense, not signal.
        out_of_range = numeric.abs() > config.NUMERIC_OUTLIER_ABS_CUTOFF
        masked_count += int(out_of_range.sum())
        X[f] = numeric.mask(out_of_range, np.nan)

    medians = stats["median"]
    X = X.fillna(medians)
    if not quiet:
        print(f"Masked {masked_count:,} out-of-range value(s) as exporter artifacts; "
              f"{non_numeric_count:,} value(s) were non-numeric.")

    X = X[features]
    return X, ground_truth_col, ground_truth_kind, len(extra_cols)


def compute_accuracy(predicted_class: np.ndarray, truth_raw: pd.Series, kind: str) -> None:
    if kind == "coarse":
        correct = predicted_class == truth_raw.astype(str).to_numpy()
        print(f"\nGround truth found in input (coarse '{config.COARSE_LABEL_COLUMN}' column):")
        print(f"  accuracy: {correct.mean():.4f} ({correct.sum():,} / {len(correct):,})")
    elif kind == "fine":
        try:
            mapped = config.map_to_coarse_category(truth_raw.astype(str))
        except AssertionError as e:
            print(f"\nGround truth column 'Attack' found but could not be mapped to coarse "
                  f"categories, skipping accuracy: {e}")
            return
        correct = predicted_class == mapped.to_numpy()
        print(f"\nGround truth found in input ('Attack' fine-grained column, mapped to coarse):")
        print(f"  accuracy: {correct.mean():.4f} ({correct.sum():,} / {len(correct):,})")
    elif kind == "binary":
        truth_numeric = pd.to_numeric(truth_raw, errors="coerce")
        valid = truth_numeric.notna()
        predicted_attack = predicted_class != "Benign"
        correct = (predicted_attack[valid.to_numpy()] == (truth_numeric[valid] == 1).to_numpy())
        print(f"\nGround truth found in input ('Label' binary column):")
        print(f"  binary detection accuracy (attack vs benign): "
              f"{correct.mean():.4f} ({correct.sum():,} / {len(correct):,})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_csv")
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--names", action="store_true",
                         help="Print only the predicted class name per row, nothing else.")
    args = parser.parse_args()
    quiet = args.names

    input_path = Path(args.input_csv)
    if not input_path.exists():
        print(f"Error: input file not found: {input_path}")
        sys.exit(1)

    try:
        df = pd.read_csv(input_path)
    except pd.errors.EmptyDataError:
        print(f"Error: input file is empty: {input_path}")
        sys.exit(1)
    except pd.errors.ParserError as e:
        print(f"Error: could not parse {input_path} as CSV: {e}")
        sys.exit(1)

    if not quiet:
        print(f"Read {len(df):,} row(s), {len(df.columns)} column(s) from {input_path}")

    if args.limit is not None and len(df) > args.limit:
        df = df.head(args.limit).reset_index(drop=True)
        if not quiet:
            print(f"Limiting to first {len(df):,} row(s) (--limit).")

    bundle, stats, severity = load_bundle()
    features = bundle["features"]
    labels = bundle["labels"]
    class_order = bundle["class_order"]
    benign_index = bundle["benign_index"]
    thresholds = np.asarray(bundle["class_thresholds"], dtype="float64")
    gate = bundle["gate"]

    X, ground_truth_col, ground_truth_kind, _ = build_feature_matrix(df, features, stats, quiet=quiet)

    started = time.perf_counter()
    proba = bundle["model"].predict_proba(X.astype("float32"))[:, class_order]
    # Plain argmax would pick whichever class has the largest raw probability;
    # class_thresholds rescales each class's probability by how confident the
    # model must be in that class before it wins, so a class with a low
    # threshold (e.g. DDoS at 0.1) can out-rank Benign even at a modest
    # probability, while a high-threshold class (e.g. DoS/BruteForce at 5.0)
    # needs to dominate the vote. This IS the trained decision rule, not an
    # approximation of it.
    predicted_class = np.asarray(labels)[(proba / thresholds).argmax(axis=1)]
    confidence = bundle["calibrator"].predict(1.0 - proba[:, benign_index])
    if gate:
        anchor = confidence >= gate["tau"]
    else:
        anchor = np.zeros(len(confidence), dtype=bool)
    elapsed_ms = (time.perf_counter() - started) * 1000

    severities = np.array([severity.get(c, "UNKNOWN") for c in predicted_class])

    if quiet:
        for cls in predicted_class:
            print(cls)
    else:
        print()
        row_w = max(len("row"), len(str(len(X)))) + 2
        cls_w = max(len("predicted_class"), max(len(c) for c in labels)) + 2
        sev_w = max(len("severity"), max((len(s) for s in severities), default=0)) + 2
        conf_w = len("confidence") + 2
        anc_w = max(len("anchor"), len("False")) + 2
        print(f"{'row':<{row_w}}{'predicted_class':<{cls_w}}{'severity':<{sev_w}}"
              f"{'confidence':<{conf_w}}{'anchor':<{anc_w}}")
        for i in range(len(X)):
            print(f"{i + 1:<{row_w}}{predicted_class[i]:<{cls_w}}{severities[i]:<{sev_w}}"
                  f"{confidence[i]:<{conf_w}.4f}{str(bool(anchor[i])):<{anc_w}}")

        print()
        print(f"Total rows: {len(X):,}")
        print("Predicted class counts:")
        counts = pd.Series(predicted_class).value_counts()
        for label in labels:
            print(f"  {label:<{cls_w}} {int(counts.get(label, 0)):>8,}")
        print(f"Would anchor: {int(anchor.sum()):,} / {len(X):,}")
        print(f"Mean inference time per row: {elapsed_ms / len(X):.4f} ms")

        if ground_truth_col is not None:
            compute_accuracy(predicted_class, df[ground_truth_col], ground_truth_kind)

    output_path = Path(args.output) if args.output else input_path.parent / f"{input_path.stem}_predictions.csv"
    out = pd.DataFrame({
        "row": range(1, len(X) + 1),
        "predicted_class": predicted_class,
        "severity": severities,
        "confidence": confidence,
        "anchor": anchor,
    })
    for i, label in enumerate(labels):
        out[f"prob_{label}"] = proba[:, i]
    out = pd.concat([out, df.reset_index(drop=True)], axis=1)
    out.to_csv(output_path, index=False)
    if not quiet:
        print(f"\nWrote {output_path}")


if __name__ == "__main__":
    main()

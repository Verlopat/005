"""
Write a CSV of real flows from the test fold, feature-columns only, for
exercising predict_csv.py against genuine data without leaking the answer.

  python make_test_csv.py                        20 random flows -> test_flows.csv
  python make_test_csv.py --rows 50
  python make_test_csv.py --class DDoS            only flows of that class
  python make_test_csv.py --answers answers.csv   also write the true labels
                                                   to a separate file
"""

from __future__ import annotations

import sys
import argparse

import joblib
import pandas as pd

import config

MODEL_DIR = config.OUTPUTS_DIR / "09_model"
BUNDLE_PATH = MODEL_DIR / "detector_bundle.joblib"
OUTPUT_PATH = config.BASE_DIR / "test_flows.csv"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rows", type=int, default=20)
    parser.add_argument("--class", dest="cls", default=None,
                         help="Restrict to one coarse threat category, e.g. DDoS.")
    parser.add_argument("--answers", default=None,
                         help="Also write ground truth (row, true_class) to this file.")
    args = parser.parse_args()

    if not BUNDLE_PATH.exists():
        print(f"Error: missing {BUNDLE_PATH}. Run 09_export_model.py first.")
        sys.exit(1)
    if not config.TEST_PARQUET.exists():
        print(f"Error: missing {config.TEST_PARQUET}. Run 02_prepare.py first.")
        sys.exit(1)

    bundle = joblib.load(BUNDLE_PATH)
    features = bundle["features"]
    label_col = config.COARSE_LABEL_COLUMN

    df = pd.read_parquet(config.TEST_PARQUET, columns=features + [label_col])

    if args.cls is not None:
        match = next((c for c in config.COARSE_CATEGORIES if c.lower() == args.cls.lower()), None)
        if match is None:
            print(f"Error: '{args.cls}' is not a coarse threat category. "
                  f"Choose from: {config.COARSE_CATEGORIES}")
            sys.exit(1)
        df = df[df[label_col] == match]
        if df.empty:
            print(f"Error: no test-fold flows found for class {match!r}.")
            sys.exit(1)

    n = min(args.rows, len(df))
    if n < args.rows:
        print(f"Only {len(df):,} flow(s) available, using all {n:,}.")
    sample = df.sample(n=n, random_state=config.RANDOM_SEED).reset_index(drop=True)

    print("Selected classes:")
    for cls, count in sample[label_col].value_counts().sort_index().items():
        print(f"  {cls:<15} {count:>6,}")

    sample[features].to_csv(OUTPUT_PATH, index=False)
    print(f"\nWrote {OUTPUT_PATH} ({len(sample):,} rows, {len(features)} feature columns, no label)")

    if args.answers:
        answers = pd.DataFrame({
            "row": range(1, len(sample) + 1),
            "true_class": sample[label_col],
        })
        answers.to_csv(args.answers, index=False)
        print(f"Wrote {args.answers} ({len(answers):,} rows)")


if __name__ == "__main__":
    main()

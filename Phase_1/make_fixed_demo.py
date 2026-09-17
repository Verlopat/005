"""
Write the permanent, fixed demo file.

  python make_fixed_demo.py

Unlike make_demo_dataset.py (which is meant to be re-run, with either
realistic or --balanced proportions), this writes ONE fixed set of 25 rows
with a hardcoded seed, independent of config.RANDOM_SEED, so this file's
contents never change even if the pipeline's seed ever does. It is meant to
be run once and then left alone — see the warning printed at the end.
"""

from __future__ import annotations

import sys

import joblib
import pandas as pd

import config

MODEL_DIR = config.OUTPUTS_DIR / "09_model"
BUNDLE_PATH = MODEL_DIR / "detector_bundle.joblib"
DATASET_PATH = config.BASE_DIR / "demo_final.csv"
ANSWERS_PATH = config.BASE_DIR / "demo_final_answers.csv"

FIXED_SEED = 42

QUOTAS = {
    "Benign": 10,
    "DDoS": 4,
    "DoS": 3,
    "Bot": 3,
    "BruteForce": 3,
    "Infiltration": 1,
    "Web Attacks": 1,
}


def main() -> None:
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
    available = df[label_col].value_counts().to_dict()
    for cls, quota in QUOTAS.items():
        if available.get(cls, 0) < quota:
            print(f"Error: only {available.get(cls, 0)} {cls!r} row(s) available in the test fold, "
                  f"need {quota}.")
            sys.exit(1)

    parts = [df[df[label_col] == cls].sample(n=n, random_state=FIXED_SEED) for cls, n in QUOTAS.items()]
    picked = pd.concat(parts, ignore_index=True)
    picked = picked.sample(frac=1, random_state=FIXED_SEED).reset_index(drop=True)

    print("Class counts written:")
    for cls, count in picked[label_col].value_counts().reindex(config.COARSE_CATEGORIES, fill_value=0).items():
        if count:
            print(f"  {cls:<15} {count:>3,}")

    picked[features].to_csv(DATASET_PATH, index=False)
    print(f"\nWrote {DATASET_PATH} ({len(picked)} rows, {len(features)} feature columns, no label)")

    answers = pd.DataFrame({"row": range(1, len(picked) + 1), "true_class": picked[label_col]})
    answers.to_csv(ANSWERS_PATH, index=False)
    print(f"Wrote {ANSWERS_PATH}")

    print(f"\nWARNING: {DATASET_PATH.name} is the permanent demo file. "
          f"Do not run this script again — it will overwrite it.")


if __name__ == "__main__":
    main()

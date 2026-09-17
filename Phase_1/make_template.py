"""
Write template.csv: one header row of the model's 25 feature names, in the
exact order the model expects, and one data row of their training medians.

  python make_template.py

Gives a correctly-shaped starting point for predict_csv.py without having to
type 25 column names by hand.
"""

from __future__ import annotations

import sys

import joblib
import pandas as pd

import config

MODEL_DIR = config.OUTPUTS_DIR / "09_model"
BUNDLE_PATH = MODEL_DIR / "detector_bundle.joblib"
STATS_PATH = MODEL_DIR / "feature_stats.csv"
TEMPLATE_PATH = config.BASE_DIR / "template.csv"


def main() -> None:
    if not BUNDLE_PATH.exists():
        print(f"Error: missing {BUNDLE_PATH}. Run 09_export_model.py first.")
        sys.exit(1)
    if not STATS_PATH.exists():
        print(f"Error: missing {STATS_PATH}.")
        sys.exit(1)

    bundle = joblib.load(BUNDLE_PATH)
    features = bundle["features"]
    stats = pd.read_csv(STATS_PATH, index_col=0)

    row = {f: stats.loc[f, "median"] for f in features}
    pd.DataFrame([row], columns=features).to_csv(TEMPLATE_PATH, index=False)

    print(f"Wrote {TEMPLATE_PATH}")
    print("Edit the values, then run: python predict_csv.py template.csv")


if __name__ == "__main__":
    main()

"""
Print real parameter values, per attack class, to type into predict.py.

  python show_examples.py

For each threat category it prints the median of the parameters predict.py
asks for, computed over genuine flows of that category in the held-out test
fold, plus one concrete example flow. Typing those values reproduces a real
attack rather than a plausible-looking invention.

Medians are the safer demo values: an individual flow can sit in the tail of
its class and get classified as something else, which is a true property of
the data but a confusing thing to show a panel.
"""

from __future__ import annotations

import json
import sys

import numpy as np
import pandas as pd

import config

HOW_MANY = 6            # keep in step with predict.py
MODEL_DIR = config.OUTPUTS_DIR / "09_model"


def main():
    import joblib
    bundle = MODEL_DIR / "detector_bundle.joblib"
    if not bundle.exists():
        sys.exit(f"Missing {bundle}. Run 09_export_model.py first.")
    b = joblib.load(bundle)
    feats, labels = b["features"], b["labels"]

    ask = None
    perm = getattr(config, "PERMUTATION_IMPORTANCE_CSV", None)
    if perm and perm.exists():
        s = pd.read_csv(perm, index_col=0).iloc[:, 0].sort_values(ascending=False)
        ask = [f for f in s.index if f in feats][:HOW_MANY]
    if not ask:
        imp = pd.Series(b["model"].feature_importances_, index=feats)
        ask = list(imp.sort_values(ascending=False).index[:HOW_MANY])

    COARSE = config.COARSE_LABEL_COLUMN
    payload = json.loads(config.COLUMNS_JSON.read_text(encoding="utf-8"))
    fine_col = payload.get("fine_grained_label")
    cols = list(dict.fromkeys(ask + [COARSE] + ([fine_col] if fine_col else [])))

    print("  loading the test fold ...")
    df = pd.read_parquet(config.TEST_PARQUET, columns=cols)
    y = df[COARSE].astype(str)

    for lab in labels:
        sub = df[y == lab]
        if sub.empty:
            continue
        print("\n" + "=" * 70)
        print(f"  {lab}   ({len(sub):,} flows in the test fold)")
        print("=" * 70)
        print("  typical values — type these into predict.py:\n")
        for f in ask:
            med = float(sub[f].median())
            print(f"    {f:<30} {med:g}")

        if fine_col and sub[fine_col].nunique() > 1:
            counts = sub[fine_col].value_counts()
            print(f"\n  variants present: "
                  + ", ".join(f"{k} ({v:,})" for k, v in counts.items()))

    print("\n" + "=" * 70)
    print("  Note: these are medians across each class. Individual flows vary")
    print("  widely, and a flow drawn from the tail of its class may well be")
    print("  classified as something else — that is a real property of the")
    print("  data, not a fault in the model.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
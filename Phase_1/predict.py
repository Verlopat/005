"""
Ask for a few flow parameters, predict the attack.

  python predict.py

That's all it does. It asks for the handful of parameters that actually
drive the prediction, you type values, it names the attack.

WHY ONLY A FEW PARAMETERS AND NOT ALL 25

  The model was trained on 25 features, so it needs 25 values to score a
  flow. But permutation importance on the validation fold shows the top
  six carry the overwhelming majority of the decision weight, and nobody
  can type 25 correlated NetFlow values by hand. So this asks for the ones
  that matter and fills the remainder with their training-fold medians.

  Change HOW_MANY below to ask for more or fewer.
"""

from __future__ import annotations

import json
import sys

import numpy as np
import pandas as pd

import config

HOW_MANY = 6            # how many parameters to ask for
MODEL_DIR = config.OUTPUTS_DIR / "09_model"
STATS = MODEL_DIR / "feature_stats.csv"


def load():
    import joblib
    bundle = MODEL_DIR / "detector_bundle.joblib"
    if not bundle.exists():
        sys.exit(f"Missing {bundle}. Run 09_export_model.py first.")
    b = joblib.load(bundle)

    if STATS.exists():
        stats = pd.read_csv(STATS, index_col=0)
    else:
        print("preparing (one time only) ...")
        df = pd.read_parquet(config.TRAIN_PARQUET, columns=b["features"])
        stats = pd.DataFrame({"median": df.median(),
                              "p05": df.quantile(0.05), "p95": df.quantile(0.95)})
        stats.to_csv(STATS)

    # Rank by permutation importance where stage 04 recorded it, since that
    # measures what actually changes held-out predictions. Gain importance is
    # the fallback: it measures how often the model splits on a feature, which
    # is not the same thing.
    ask = None
    perm = getattr(config, "PERMUTATION_IMPORTANCE_CSV", None)
    if perm and perm.exists():
        s = pd.read_csv(perm, index_col=0).iloc[:, 0].sort_values(ascending=False)
        ask = [f for f in s.index if f in b["features"]][:HOW_MANY]
    if not ask:
        imp = pd.Series(b["model"].feature_importances_, index=b["features"])
        ask = list(imp.sort_values(ascending=False).index[:HOW_MANY])
    return b, stats, ask


def main():
    b, stats, ask = load()
    model, cal = b["model"], b["calibrator"]
    feats, labels = b["features"], b["labels"]
    order, benign = b["class_order"], b["benign_index"]
    thresholds = np.asarray(b["class_thresholds"], dtype="float64")

    sev_file = config.OUTPUTS_DIR / "10_contract" / "severity_map.json"
    severity = json.loads(sev_file.read_text()) if sev_file.exists() else {}

    print(f"\nEnter the flow parameters. Press Enter alone to use the typical "
          f"value.\nType q to quit.\n")

    while True:
        values = {f: float(stats.loc[f, "median"]) for f in feats}

        for f in ask:
            med = float(stats.loc[f, "median"])
            raw = input(f"  {f}  [{med:g}] : ").strip()
            if raw.lower() in ("q", "quit", "exit"):
                print()
                return
            if raw:
                try:
                    values[f] = float(raw)
                except ValueError:
                    print(f"      not a number — using {med:g}")

        row = pd.DataFrame([[values[f] for f in feats]],
                           columns=feats).astype("float32")
        proba = model.predict_proba(row)[:, order][0]
        k = int((proba / thresholds).argmax())
        cls = labels[k]
        conf = float(cal.predict(np.array([1.0 - proba[benign]]))[0])

        print()
        if cls == "Benign":
            print(f"  ->  NORMAL TRAFFIC        (confidence {1 - conf:.4f})")
        else:
            print(f"  ->  {cls.upper()} ATTACK   [{severity.get(cls, 'UNKNOWN')}]"
                  f"   (confidence {conf:.4f})")

        # Second-place class, shown only when the model is genuinely torn.
        ranked = np.argsort(proba)[::-1]
        if proba[ranked[1]] > 0.15:
            print(f"      next most likely: {labels[ranked[1]]} "
                  f"({proba[ranked[1]]:.3f})")
        print()


if __name__ == "__main__":
    main()
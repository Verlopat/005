"""Minimal inference example. Run from the project root."""
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

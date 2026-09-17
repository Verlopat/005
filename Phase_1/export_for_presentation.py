"""
Export presentation-ready CSVs from the pipeline's existing metrics,
calibration, and demo artifacts. CSV output only — no .txt, no .json.

  python export_for_presentation.py

Writes into outputs/presentation/, then zips that folder into
presentation_results.zip in the project root.
"""

from __future__ import annotations

import glob
import json
import zipfile
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq

import config

MODEL_DIR = config.OUTPUTS_DIR / "09_model"
BUNDLE_PATH = MODEL_DIR / "detector_bundle.joblib"
MODEL_CARD_PATH = MODEL_DIR / "model_card.json"
METRICS_DIR = config.OUTPUTS_DIR / "07_metrics"
CALIBRATION_DIR = config.OUTPUTS_DIR / "08_calibration_icr"
PRESENTATION_DIR = config.OUTPUTS_DIR / "presentation"
ZIP_PATH = config.BASE_DIR / "presentation_results.zip"
DEMO_CSV = config.BASE_DIR / "demo_final.csv"
DEMO_ANSWERS_CSV = config.BASE_DIR / "demo_final_answers.csv"

ROUND_DP = 4

written: list[tuple[str, int]] = []


def write_csv(df: pd.DataFrame, name: str) -> None:
    path = PRESENTATION_DIR / name
    df.to_csv(path, index=False, encoding="utf-8-sig")
    written.append((name, len(df)))


def r4(x):
    return round(x, ROUND_DP) if pd.notna(x) else x


# --- 1. model_summary.csv --------------------------------------------------
def build_model_summary() -> None:
    df = pd.read_csv(METRICS_DIR / "metrics_table.csv")
    df = df[df["view"] == "as_sampled"].sort_values("f1_macro", ascending=False)

    column_map = {
        "model": "Model",
        "accuracy": "Accuracy",
        "precision_macro": "Precision (macro)",
        "recall_macro_DR": "Recall/DR (macro)",
        "f1_macro": "F1 (macro)",
        "binary_f1": "Binary F1",
        "TNR_specificity": "Specificity (TNR)",
        "FPR": "FPR",
        # metrics_table.csv's macro-OvR ROC/PR-AUC columns are unpopulated
        # for every model; the binary ones are what's actually measured.
        "ROC_AUC_binary": "ROC-AUC",
        "PR_AUC_binary": "PR-AUC",
        "MCC": "MCC",
        "cohen_kappa": "Cohen Kappa",
    }
    out = df[list(column_map)].rename(columns=column_map)
    numeric_cols = [c for c in out.columns if c != "Model"]
    out[numeric_cols] = out[numeric_cols].apply(lambda col: col.map(r4))
    write_csv(out, "model_summary.csv")


# --- 2 & 3. classification_report_<model>.csv / _ALL_MODELS ----------------
def build_classification_reports() -> None:
    column_map = {
        "class": "Class",
        "support": "Support",
        "precision": "Precision",
        "recall_DR": "Recall/DR",
        "f1": "F1",
        "TNR_specificity": "Specificity (TNR)",
        "binary_recall": "Binary Recall",
        "ROC_AUC_ovr": "ROC-AUC (OvR)",
    }
    value_cols = ["precision", "recall_DR", "f1", "TNR_specificity", "binary_recall", "ROC_AUC_ovr"]

    all_models = []
    for path in sorted(glob.glob(str(METRICS_DIR / "per_class_*.csv"))):
        model_name = Path(path).stem.removeprefix("per_class_")
        df = pd.read_csv(path)
        total_support = int(df["support"].sum())

        macro_row = {"class": "MACRO AVG", "support": total_support}
        weighted_row = {"class": "WEIGHTED AVG", "support": total_support}
        for col in value_cols:
            valid = df[col].notna()
            macro_row[col] = df.loc[valid, col].mean()
            weighted_row[col] = (
                np.average(df.loc[valid, col], weights=df.loc[valid, "support"]) if valid.any() else np.nan
            )

        full = pd.concat([df, pd.DataFrame([macro_row, weighted_row])], ignore_index=True)
        out = full[list(column_map)].rename(columns=column_map)
        out[[column_map[c] for c in value_cols]] = out[[column_map[c] for c in value_cols]].apply(
            lambda col: col.map(r4)
        )
        write_csv(out, f"classification_report_{model_name}.csv")

        stamped = out.copy()
        stamped.insert(0, "Model", model_name)
        all_models.append(stamped)

    write_csv(pd.concat(all_models, ignore_index=True), "classification_report_ALL_MODELS.csv")


# --- 4 & 5. demo_prediction_report.csv / demo_summary.csv ------------------
def run_demo_predictions(bundle: dict):
    demo = pd.read_csv(DEMO_CSV)
    answers = pd.read_csv(DEMO_ANSWERS_CSV)
    features, labels = bundle["features"], bundle["labels"]

    X = demo[features].astype("float32")
    proba = bundle["model"].predict_proba(X)[:, bundle["class_order"]]
    prediction = np.asarray(labels)[(proba / bundle["class_thresholds"]).argmax(axis=1)]
    confidence = bundle["calibrator"].predict(1.0 - proba[:, bundle["benign_index"]])
    gate = bundle["gate"]
    anchor = confidence >= gate["tau"] if gate else np.zeros(len(confidence), dtype=bool)

    true_class = answers["true_class"].to_numpy()
    correct = prediction == true_class
    return demo, true_class, prediction, correct, confidence, anchor, proba, labels


def build_demo_prediction_report(bundle: dict, results) -> None:
    _, true_class, prediction, correct, confidence, anchor, proba, labels = results

    out = pd.DataFrame({
        "Row": range(1, len(prediction) + 1),
        "True Class": true_class,
        "Predicted Class": prediction,
        "Correct (YES/NO)": np.where(correct, "YES", "NO"),
        "Confidence": [r4(c) for c in confidence],
        "Anchor On-Chain": np.where(anchor, "YES", "NO"),
    })
    for i, label in enumerate(labels):
        out[f"P({label})"] = [r4(p) for p in proba[:, i]]
    write_csv(out, "demo_prediction_report.csv")


def build_demo_summary(results) -> None:
    _, true_class, prediction, correct, *_ = results
    total, n_correct = len(prediction), int(correct.sum())

    metrics_block = pd.DataFrame({
        "Metric": ["Total Rows", "Correct", "Incorrect", "Accuracy"],
        # dtype=object preserves each value's own Python type (int vs float);
        # otherwise pandas upcasts the whole mixed int/float column to
        # float64 and the integer counts render as "25.0" instead of "25".
        "Value": pd.Series([total, n_correct, total - n_correct, r4(n_correct / total)], dtype=object),
    })

    rows = []
    for cls in pd.unique(true_class):
        mask = true_class == cls
        cls_rows = int(mask.sum())
        cls_correct = int(correct[mask].sum())
        rows.append({"Class": cls, "Rows": cls_rows, "Correct": cls_correct,
                      "Recall": r4(cls_correct / cls_rows)})
    class_block = pd.DataFrame(rows)

    path = PRESENTATION_DIR / "demo_summary.csv"
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        metrics_block.to_csv(fh, index=False)
        fh.write("\n")
        class_block.to_csv(fh, index=False)
    written.append(("demo_summary.csv", len(metrics_block) + len(class_block)))


# --- 6. model_card.csv ------------------------------------------------------
def build_model_card_csv(card: dict) -> None:
    rows = [
        ("model_version", card["model_version"]),
        ("model_id_sha256", card["model_id_sha256"]),
        ("architecture", card["architecture"]),
        ("training.dataset", card["training"]["dataset"]),
        ("training.split", card["training"]["split"]),
        ("n_features", card["n_features"]),
        ("test_metrics.macro_f1", r4(card["test_metrics"]["macro_f1"])),
        ("test_metrics.accuracy", r4(card["test_metrics"]["accuracy"])),
        ("test_metrics.binary_f1", r4(card["test_metrics"]["binary_f1"])),
        ("calibration", card["calibration"]),
        ("anchoring_gate.tau", r4(card["anchoring_gate"]["tau"])),
    ]
    out = pd.DataFrame(rows, columns=["Property", "Value"])
    write_csv(out, "model_card.csv")


# --- 7. key_results.csv -----------------------------------------------------
def build_key_results(bundle: dict, card: dict) -> None:
    metrics = pd.read_csv(METRICS_DIR / "metrics_table.csv")
    winner = metrics[(metrics["model"] == bundle["variant"]) & (metrics["view"] == "as_sampled")].iloc[0]

    calib = pd.read_csv(CALIBRATION_DIR / "calibration_metrics.csv")
    iso = calib[calib["method"] == "isotonic"].iloc[0]

    icr = pd.read_csv(CALIBRATION_DIR / "icr_operating_points.csv")
    icr95 = icr[np.isclose(icr["ICR_target"], 0.95)].iloc[0]

    test_rows = pq.ParquetFile(config.TEST_PARQUET).metadata.num_rows

    # Single-event latency, matching the "single event, CPU only" framing of
    # the p99 < 50ms hard requirement — timed row-by-row over the demo set,
    # not amortized over a large batch.
    import time
    X = pd.read_csv(DEMO_CSV)[bundle["features"]].astype("float32")
    times_ms = []
    for i in range(len(X)):
        row = X.iloc[[i]]
        started = time.perf_counter()
        bundle["model"].predict_proba(row)
        times_ms.append((time.perf_counter() - started) * 1000)
    latency_ms = float(np.mean(times_ms))

    rows = [
        ("Macro-F1", r4(winner["f1_macro"])),
        ("Accuracy", r4(winner["accuracy"])),
        ("Binary F1", r4(winner["binary_f1"])),
        ("Precision (macro)", r4(winner["precision_macro"])),
        ("Recall (macro)", r4(winner["recall_macro_DR"])),
        ("Specificity", r4(winner["TNR_specificity"])),
        ("FPR", r4(winner["FPR"])),
        ("ROC-AUC", r4(winner["ROC_AUC_binary"])),
        ("MCC", r4(winner["MCC"])),
        ("Expected Calibration Error", r4(iso["ECE"])),
        ("Brier Score", r4(iso["brier"])),
        ("Integrity Coverage Ratio", r4(icr95["ICR"])),
        ("On-Chain Volume", r4(icr95["on_chain_volume"])),
        ("Ledger Write Reduction", r4(icr95["write_reduction"])),
        ("Inference Latency (ms/event)", r4(latency_ms)),
        ("Test Set Size", test_rows),
        ("Number of Classes", len(bundle["labels"])),
        ("Number of Features", len(bundle["features"])),
    ]
    out = pd.DataFrame({
        "Metric": [m for m, _ in rows],
        # See build_demo_summary: object dtype keeps the integer rows
        # (Test Set Size, Number of Classes, Number of Features) from being
        # upcast to float64 alongside the float-valued metric rows.
        "Value": pd.Series([v for _, v in rows], dtype=object),
    })
    write_csv(out, "key_results.csv")


def zip_presentation_dir() -> None:
    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in sorted(PRESENTATION_DIR.iterdir()):
            zf.write(file, arcname=file.name)


def main() -> None:
    PRESENTATION_DIR.mkdir(parents=True, exist_ok=True)

    bundle = joblib.load(BUNDLE_PATH)
    card = json.loads(MODEL_CARD_PATH.read_text(encoding="utf-8"))

    build_model_summary()
    build_classification_reports()

    results = run_demo_predictions(bundle)
    build_demo_prediction_report(bundle, results)
    build_demo_summary(results)

    build_model_card_csv(card)
    build_key_results(bundle, card)

    zip_presentation_dir()

    print(f"Wrote {len(written)} file(s) to {PRESENTATION_DIR}:")
    for name, n in written:
        print(f"  {name:<45} {n:>4} row(s)")
    print(f"\nZipped {PRESENTATION_DIR} -> {ZIP_PATH}")


if __name__ == "__main__":
    main()

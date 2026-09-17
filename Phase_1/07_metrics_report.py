"""
Stage 07 — Full metrics report across every model already evaluated.

Reads the saved probability matrices from stage 05 and stage 06 and computes
the complete metric set. NOTHING IS RETRAINED — every model wrote y_true,
y_pred and proba to .npz when it ran, so this is pure post-processing and
takes minutes rather than hours.

Metrics per model:
  Accuracy, Precision (macro + weighted), Recall / Detection Rate,
  F1 (macro + weighted), Binary F1 (attack vs benign), TNR / Specificity,
  FPR, ROC-AUC (binary, macro-OvR, weighted-OvR), PR-AUC, MCC, balanced
  accuracy, Cohen's kappa, plus a full per-class classification report and
  confusion matrix.

Everything is reported twice:
  as-sampled      the test fold as written by 02_prepare
  natural-prior   benign reweighted by 1/BENIGN_KEEP_FRACTION

  Note: the test fold is ALREADY at natural prior (02_prepare downsamples
  train only), so these two are expected to agree. The weighted column is
  retained as a guard — if it ever diverges, the split has been rebuilt
  with benign downsampling applied before the split again.

Outputs: outputs/07_metrics/metrics_table.csv, per_class_<model>.csv,
         classification_reports.txt, roc_curves.png, roc_per_class_<best>.png

Run: python 07_metrics_report.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score,
                             balanced_accuracy_score, classification_report,
                             cohen_kappa_score, confusion_matrix, f1_score,
                             matthews_corrcoef, precision_recall_fscore_support,
                             roc_auc_score, roc_curve)

import config

OUTDIR = config.OUTPUTS_DIR / "07_metrics"
SOURCES = [config.OUTPUTS_DIR / "05_comparison",
           config.OUTPUTS_DIR / "06_tuning"]


def load_runs():
    """Every *_test.npz written by stages 05 and 06."""
    runs = {}
    for folder in SOURCES:
        if not folder.exists():
            continue
        for path in sorted(folder.glob("*_test.npz")):
            name = path.stem.replace("_test", "")
            if folder.name.startswith("06"):
                name = f"{name}_tuned"
            runs[name] = path
    return runs


def prediction_variants(blob, labels):
    """Return [(suffix, y_pred), ...] plus the reordered probability matrix.

    Stage 05 stored a single y_pred. Stage 06 stored proba plus a fitted tau
    vector, which encodes TWO operating points on the same model: plain
    argmax, and argmax after per-class threshold scaling. Both are reported
    so the threshold search can be judged on its own.
    """
    proba = blob["proba"].astype("float32") if "proba" in blob else None
    file_labels = [str(c) for c in blob["classes"]]
    if proba is not None and file_labels != labels:
        proba = proba[:, [file_labels.index(l) for l in labels]]

    if "y_pred" in blob:
        return [("", np.asarray(blob["y_pred"]).astype(str))], proba

    arr = np.asarray(labels)
    variants = [("_argmax", arr[proba.argmax(axis=1)])]
    if "tau" in blob:
        tau = np.asarray(blob["tau"], dtype="float64")
        if not np.allclose(tau, 1.0):
            variants.append(("_tau", arr[(proba / tau).argmax(axis=1)]))
    return variants, proba


def full_metrics(y_true, y_pred, proba, labels, weights=None):
    yt_bin = (y_true != "Benign").astype(int)
    yp_bin = (y_pred != "Benign").astype(int)

    cm = confusion_matrix(yt_bin, yp_bin, sample_weight=weights)
    tn, fp, fn, tp = (float(v) for v in cm.ravel())

    pm, rm, fm, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="macro",
        sample_weight=weights, zero_division=0)
    pw, rw, fw, _ = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, average="weighted",
        sample_weight=weights, zero_division=0)
    bp, br, bf, _ = precision_recall_fscore_support(
        yt_bin, yp_bin, average="binary", sample_weight=weights, zero_division=0)

    row = {
        "accuracy": accuracy_score(y_true, y_pred, sample_weight=weights),
        "balanced_accuracy": (balanced_accuracy_score(y_true, y_pred,
                                                      sample_weight=weights)
                              if weights is None else np.nan),
        "precision_macro": pm, "recall_macro_DR": rm, "f1_macro": fm,
        "precision_weighted": pw, "recall_weighted": rw, "f1_weighted": fw,
        "binary_precision": bp, "binary_recall_DR": br, "binary_f1": bf,
        # TNR / specificity: of all true benign flows, the share left alone.
        "TNR_specificity": tn / (tn + fp) if (tn + fp) else np.nan,
        "FPR": fp / (fp + tn) if (fp + tn) else np.nan,
        "FNR": fn / (fn + tp) if (fn + tp) else np.nan,
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "MCC": (matthews_corrcoef(y_true, y_pred) if weights is None else np.nan),
        "cohen_kappa": cohen_kappa_score(y_true, y_pred, sample_weight=weights),
    }

    # ROC-AUC and PR-AUC need scores, not hard labels.
    if proba is not None:
        attack_score = 1.0 - proba[:, labels.index("Benign")]
        try:
            row["ROC_AUC_binary"] = roc_auc_score(yt_bin, attack_score,
                                                  sample_weight=weights)
            row["PR_AUC_binary"] = average_precision_score(
                yt_bin, attack_score, sample_weight=weights)
        except ValueError:
            row["ROC_AUC_binary"] = row["PR_AUC_binary"] = np.nan
        if weights is None:
            present = [l for l in labels if (y_true == l).any()]
            try:
                idx = [labels.index(l) for l in present]
                norm = proba[:, idx] / proba[:, idx].sum(axis=1, keepdims=True)
                row["ROC_AUC_macro_ovr"] = roc_auc_score(
                    y_true, norm, multi_class="ovr", average="macro", labels=present)
                row["ROC_AUC_weighted_ovr"] = roc_auc_score(
                    y_true, norm, multi_class="ovr", average="weighted", labels=present)
            except ValueError:
                row["ROC_AUC_macro_ovr"] = row["ROC_AUC_weighted_ovr"] = np.nan
    return row


def per_class_table(y_true, y_pred, proba, labels):
    rows = []
    for lab in labels:
        mask = y_true == lab
        if not mask.any():
            continue
        p, r, f, _ = precision_recall_fscore_support(
            y_true == lab, y_pred == lab, average="binary", zero_division=0)
        neg = ~mask
        tn = float((y_pred[neg] != lab).sum())
        fp = float((y_pred[neg] == lab).sum())
        entry = {
            "class": lab, "support": int(mask.sum()),
            "precision": p, "recall_DR": r, "f1": f,
            "TNR_specificity": tn / (tn + fp) if (tn + fp) else np.nan,
            # Detected as an attack at all, even if the class name is wrong —
            # the number the alert contract's verdict field actually depends on.
            "binary_recall": (float((y_pred[mask] != "Benign").mean())
                              if lab != "Benign" else np.nan),
        }
        if proba is not None:
            try:
                entry["ROC_AUC_ovr"] = roc_auc_score(mask.astype(int),
                                                     proba[:, labels.index(lab)])
            except ValueError:
                entry["ROC_AUC_ovr"] = np.nan
        rows.append(entry)
    return pd.DataFrame(rows)


def main() -> None:
    runs = load_runs()
    if not runs:
        sys.exit(f"No *_test.npz found in {[str(s) for s in SOURCES]}. "
                 f"Run stage 05 (and optionally 06) first.")
    OUTDIR.mkdir(parents=True, exist_ok=True)
    print(f"Found {len(runs)} model runs: {', '.join(runs)}\n")

    table, curves, reports = [], {}, []
    for run_name, path in runs.items():
        blob = np.load(path, allow_pickle=True)
        labels = [c for c in config.COARSE_CATEGORIES
                  if c in {str(x) for x in blob["classes"]}]
        y_true = np.asarray(blob["y_true"]).astype(str)
        variants, proba = prediction_variants(blob, labels)
        weights = np.where(y_true == "Benign",
                           1.0 / config.BENIGN_KEEP_FRACTION, 1.0)

        for suffix, y_pred in variants:
            name = f"{run_name}{suffix}"
            as_sampled = full_metrics(y_true, y_pred, proba, labels)
            natural = full_metrics(y_true, y_pred, proba, labels, weights=weights)

            table.append({"model": name, "view": "as_sampled", **as_sampled})
            table.append({"model": name, "view": "natural_prior", **natural})

            pc = per_class_table(y_true, y_pred, proba, labels)
            pc.to_csv(OUTDIR / f"per_class_{name}.csv", index=False)

            reports.append(
                f"\n{'=' * 78}\n{name}\n{'=' * 78}\n"
                + classification_report(y_true, y_pred, labels=labels,
                                        digits=4, zero_division=0)
                + "\nConfusion matrix (rows = true, cols = predicted)\n"
                + pd.DataFrame(confusion_matrix(y_true, y_pred, labels=labels),
                               index=labels, columns=labels).to_string()
                + "\n\nPer-class detail\n"
                + pc.to_string(index=False, float_format=lambda v: f"{v:.4f}") + "\n")

            # The ROC curve is a property of the scores, not of the decision
            # rule, so argmax and tuned-tau share one curve. Plot it once.
            if proba is not None and suffix in ("", "_argmax"):
                score = 1.0 - proba[:, labels.index("Benign")]
                fpr, tpr, _ = roc_curve((y_true != "Benign").astype(int), score)
                step = max(1, len(fpr) // 4000)   # thin for a readable plot
                curves[run_name] = (fpr[::step], tpr[::step],
                                    as_sampled.get("ROC_AUC_binary", np.nan))

            print(f"  {name:26} macro-F1 {as_sampled['f1_macro']:.4f} | "
                  f"binF1 {as_sampled['binary_f1']:.4f} | "
                  f"TNR {as_sampled['TNR_specificity']:.4f} | "
                  f"ROC-AUC {as_sampled.get('ROC_AUC_binary', float('nan')):.4f}")
        del blob, proba

    df = pd.DataFrame(table)
    df.to_csv(OUTDIR / "metrics_table.csv", index=False)
    (OUTDIR / "classification_reports.txt").write_text(
        "\n".join(reports), encoding="utf-8")

    headline = ["model", "accuracy", "precision_macro", "recall_macro_DR",
                "f1_macro", "binary_f1", "TNR_specificity", "ROC_AUC_binary",
                "PR_AUC_binary", "MCC"]
    view = df[df["view"] == "as_sampled"][headline].sort_values(
        "f1_macro", ascending=False)
    print(f"\n{'=' * 78}\nHEADLINE METRICS — ranked by macro-F1\n{'=' * 78}")
    print(view.to_string(index=False, float_format=lambda v: f"{v:.4f}"))

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        plt.figure(figsize=(8, 7))
        for name, (fpr, tpr, auc) in sorted(
                curves.items(), key=lambda kv: -(kv[1][2] if kv[1][2] == kv[1][2] else 0)):
            plt.plot(fpr, tpr, lw=1.4, label=f"{name} (AUC={auc:.4f})")
        plt.plot([0, 1], [0, 1], "k--", lw=0.8, label="chance")
        plt.xlabel("False positive rate")
        plt.ylabel("True positive rate / Detection rate")
        plt.title("ROC — attack vs benign, test fold")
        plt.legend(fontsize=7, loc="lower right")
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(OUTDIR / "roc_curves.png", dpi=160)
        plt.close()
        print(f"\nWrote {OUTDIR / 'roc_curves.png'}")
    except ImportError:
        print("\nmatplotlib not installed — skipped ROC plot. "
              "pip install matplotlib")

    print(f"Wrote {OUTDIR / 'metrics_table.csv'}")
    print(f"Wrote {OUTDIR / 'classification_reports.txt'}")
    print(f"Wrote per_class_<model>.csv for {len(runs)} models")


if __name__ == "__main__":
    main()

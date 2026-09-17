"""
Stage 11 — Terminal demonstration.

Enter feature values, get a verdict. No web server, no separate interface.

  python 11_demo.py

Modes offered at the prompt:
  1  enter feature values one at a time (blank uses the training median)
  2  paste all values comma-separated
  3  load a real flow from the held-out test fold, with its true label shown
  4  load a flow from a JSON file

Mode 1 is the interactive one. Twenty-five NetFlow features is more than
anyone wants to type, so any field left blank falls back to that feature's
training-fold median, and the prompt shows the typical range. Entering three
or four values and accepting the rest is a legitimate way to explore how the
model responds to a particular feature.

Mode 3 exists for verification: it draws a genuine flow of a chosen attack
class and prints the ground-truth label alongside the prediction, so a result
can be checked rather than taken on trust.
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone

import numpy as np
import pandas as pd

import config

MODEL_DIR = config.OUTPUTS_DIR / "09_model"
CONTRACT_DIR = config.OUTPUTS_DIR / "10_contract"
STATS_CACHE = MODEL_DIR / "feature_stats.csv"
BAR = "=" * 68


class Detector:
    def __init__(self):
        import joblib
        bundle = MODEL_DIR / "detector_bundle.joblib"
        if not bundle.exists():
            sys.exit(f"Missing {bundle}. Run 09_export_model.py first.")
        b = joblib.load(bundle)
        self.model, self.cal = b["model"], b["calibrator"]
        self.feats, self.labels = b["features"], b["labels"]
        self.order, self.benign_idx = b["class_order"], b["benign_index"]
        self.thresholds = np.asarray(b["class_thresholds"], dtype="float64")
        self.tau = float((b.get("gate") or {}).get("tau", 0.5))
        card = json.loads((MODEL_DIR / "model_card.json").read_text())
        self.model_version = card["model_version"]
        sev = CONTRACT_DIR / "severity_map.json"
        self.severity = json.loads(sev.read_text()) if sev.exists() else {}
        self.explainer = None
        try:
            import shap
            self.explainer = shap.TreeExplainer(self.model)
        except Exception:
            pass

    def predict(self, values: dict) -> dict:
        row = pd.DataFrame([[float(values[f]) for f in self.feats]],
                           columns=self.feats).astype("float32")
        t0 = time.perf_counter()
        proba = self.model.predict_proba(row)[:, self.order]
        latency = (time.perf_counter() - t0) * 1000
        k = int((proba[0] / self.thresholds).argmax())
        cls = self.labels[k]
        conf = float(self.cal.predict(1.0 - proba[:, self.benign_idx])[0])

        top = []
        if self.explainer is not None:
            try:
                sv = np.asarray(self.explainer.shap_values(row))
                vals = sv[0, :, k] if sv.ndim == 3 else sv[0]
                for j in np.argsort(np.abs(vals))[::-1][:5]:
                    top.append((self.feats[j], float(row.iloc[0, j]), float(vals[j])))
            except Exception:
                pass

        return {
            "verdict": "NORMAL" if cls == "Benign" else "ANOMALY",
            "threat_class": cls,
            "severity": self.severity.get(cls, "UNKNOWN"),
            "confidence": round(conf, 6),
            "anchor": bool(conf >= self.tau),
            "anchor_gate_tau": round(self.tau, 6),
            "model_version": self.model_version,
            "inference_latency_ms": round(latency, 3),
            "class_probabilities": {l: float(p) for l, p in zip(self.labels, proba[0])},
            "top_contributing_features": top,
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        }


def feature_stats(feats):
    """Median and range per feature, so the prompts can suggest values.
    Computed once from the training fold and cached."""
    if STATS_CACHE.exists():
        return pd.read_csv(STATS_CACHE, index_col=0)
    print("  computing feature statistics from the training fold (one time) ...")
    df = pd.read_parquet(config.TRAIN_PARQUET, columns=feats)
    stats = pd.DataFrame({
        "median": df.median(), "p05": df.quantile(0.05),
        "p95": df.quantile(0.95), "min": df.min(), "max": df.max(),
    })
    stats.to_csv(STATS_CACHE)
    return stats


def show(result, truth=None, fine=None):
    print("\n" + BAR)
    tag = "ANOMALY DETECTED" if result["verdict"] == "ANOMALY" else "NORMAL TRAFFIC"
    print(f"  {tag}   ->   {result['threat_class']}"
          f"   [severity: {result['severity']}]")
    print(BAR)
    if truth is not None:
        ok = truth == result["threat_class"]
        extra = f"  ({fine})" if fine and fine != truth else ""
        print(f"  ground truth      : {truth}{extra}")
        print(f"  result            : {'CORRECT' if ok else 'MISCLASSIFIED'}")
    print(f"  confidence        : {result['confidence']:.6f}")
    print(f"  anchor on-chain   : {result['anchor']}   "
          f"(gate tau = {result['anchor_gate_tau']:.6f})")
    print(f"  inference latency : {result['inference_latency_ms']:.3f} ms")
    print(f"  model version     : {result['model_version']}")

    print("\n  class probabilities:")
    for l, p in sorted(result["class_probabilities"].items(), key=lambda kv: -kv[1]):
        if p < 0.001:
            continue
        print(f"    {l:<14} {p:8.5f}  {'#' * int(round(p * 36))}")

    if result["top_contributing_features"]:
        print("\n  why (SHAP contributions toward the predicted class):")
        for name, val, s in result["top_contributing_features"]:
            print(f"    {'+' if s >= 0 else '-'} {name:<32} "
                  f"value={val:>15.4f}  shap={s:+.4f}")
    print(BAR)


def enter_manually(det, stats):
    """One prompt per feature. Blank accepts the training median."""
    print(f"\n  {len(det.feats)} features. Press Enter to accept the median shown.")
    print("  Type 'done' to accept medians for everything remaining, 'q' to cancel.\n")
    values = {}
    for i, f in enumerate(det.feats, 1):
        med = float(stats.loc[f, "median"])
        lo, hi = float(stats.loc[f, "p05"]), float(stats.loc[f, "p95"])
        raw = input(f"  [{i:2d}/{len(det.feats)}] {f}\n"
                    f"        median={med:g}   typical={lo:g} .. {hi:g}\n"
                    f"        > ").strip()
        if raw.lower() in ("q", "quit"):
            return None
        if raw.lower() == "done":
            for g in det.feats[i - 1:]:
                values[g] = float(stats.loc[g, "median"])
            break
        if raw == "":
            values[f] = med
            continue
        try:
            values[f] = float(raw)
        except ValueError:
            print(f"        not a number — using median {med:g}")
            values[f] = med
    for f in det.feats:
        values.setdefault(f, float(stats.loc[f, "median"]))
    return values


def paste_values(det, stats):
    print(f"\n  Paste {len(det.feats)} comma-separated values, in this order:\n")
    for i in range(0, len(det.feats), 2):
        line = "    " + "  ".join(
            f"{j + 1:2d}. {det.feats[j]:<30}"
            for j in range(i, min(i + 2, len(det.feats))))
        print(line)
    raw = input("\n  > ").strip()
    parts = [p.strip() for p in raw.replace("\t", ",").split(",") if p.strip()]
    if len(parts) != len(det.feats):
        print(f"  expected {len(det.feats)} values, got {len(parts)}")
        return None
    try:
        return dict(zip(det.feats, (float(p) for p in parts)))
    except ValueError as e:
        print(f"  could not parse: {e}")
        return None


def real_flow(det):
    payload = json.loads(config.COLUMNS_JSON.read_text(encoding="utf-8"))
    COARSE = config.COARSE_LABEL_COLUMN
    fine_col = payload.get("fine_grained_label")
    cols = list(dict.fromkeys(det.feats + [COARSE] + ([fine_col] if fine_col else [])))
    print("  loading the test fold ...")
    df = pd.read_parquet(config.TEST_PARQUET, columns=cols)
    present = [l for l in det.labels if (df[COARSE].astype(str) == l).any()]

    print()
    for i, c in enumerate(present, 1):
        n = int((df[COARSE].astype(str) == c).sum())
        print(f"    {i}. {c:<14} ({n:,} flows)")
    print(f"    {len(present) + 1}. any class at random")
    sel = input("\n  class > ").strip()
    try:
        sub = df if sel == str(len(present) + 1) else \
            df[df[COARSE].astype(str) == present[int(sel) - 1]]
    except (ValueError, IndexError):
        print("  not a valid option")
        return None, None, None
    r = sub.sample(1, random_state=np.random.randint(0, 1 << 30))
    values = {f: float(r[f].iloc[0]) for f in det.feats}
    fine = str(r[fine_col].iloc[0]) if fine_col else None
    return values, str(r[COARSE].iloc[0]), fine


def from_file(det):
    path = input("  path to JSON > ").strip().strip('"').strip("'")
    try:
        data = json.loads(open(path, encoding="utf-8").read())
    except Exception as e:
        print(f"  could not read that file: {e}")
        return None
    missing = [f for f in det.feats if f not in data]
    if missing:
        print(f"  missing {len(missing)} feature(s): {', '.join(missing[:5])}"
              f"{' ...' if len(missing) > 5 else ''}")
        return None
    return {f: float(data[f]) for f in det.feats}


def predict_batch(det, frame: pd.DataFrame) -> tuple:
    """Score many rows in one call. Batched inference is what the deployed
    service actually does, so the per-flow latency reported here is the
    realistic figure — single-row timing is dominated by call overhead."""
    X = frame[det.feats].astype("float32")
    t0 = time.perf_counter()
    proba = det.model.predict_proba(X)[:, det.order]
    elapsed_ms = (time.perf_counter() - t0) * 1000
    pred = np.asarray(det.labels)[(proba / det.thresholds).argmax(axis=1)]
    conf = det.cal.predict(1.0 - proba[:, det.benign_idx])
    return pred, conf, proba, elapsed_ms


def show_batch(det, frame, truth=None, fine=None, label=""):
    pred, conf, proba, elapsed = predict_batch(det, frame)
    n = len(frame)
    anchor = conf >= det.tau

    print("\n" + BAR)
    print(f"  BATCH RESULTS — {n} flows{(' — ' + label) if label else ''}")
    print(BAR)

    header = f"  {'#':>4}  {'predicted':<14} {'conf':>9}  {'anchor':>6}"
    if truth is not None:
        header += f"  {'ground truth':<14} {'':>5}"
    print(header)
    print("  " + "-" * (len(header) - 2))

    for i in range(n):
        line = (f"  {i + 1:>4}  {pred[i]:<14} {conf[i]:9.6f}  "
                f"{'YES' if anchor[i] else 'no':>6}")
        if truth is not None:
            t = truth[i]
            extra = f" ({fine[i]})" if fine is not None and fine[i] != t else ""
            mark = "OK" if t == pred[i] else "WRONG"
            line += f"  {t + extra:<14} {mark:>5}"
        print(line)

    print("  " + "-" * (len(header) - 2))
    print(f"  anchored          : {int(anchor.sum())} of {n} "
          f"({anchor.mean() * 100:.1f}%)")
    print(f"  mean confidence   : {conf.mean():.6f}")
    print(f"  total inference   : {elapsed:.2f} ms "
          f"({elapsed / n:.4f} ms per flow, batched)")

    if truth is not None:
        correct = (pred == truth).sum()
        print(f"  correct           : {correct} of {n} "
              f"({correct / n * 100:.1f}%)")
        wrong = [(truth[i], pred[i]) for i in range(n) if truth[i] != pred[i]]
        if wrong:
            print("\n  misclassifications:")
            for t, p in pd.Series(wrong).value_counts().items():
                print(f"    {t[0]:<14} -> {t[1]:<14} x{p}")
        # Per-class recall matters more than the aggregate on imbalanced data.
        classes = sorted(set(truth))
        if len(classes) > 1:
            print("\n  per-class recall in this batch:")
            for c in classes:
                m = truth == c
                print(f"    {c:<14} {int((pred[m] == c).sum()):>4} / "
                      f"{int(m.sum()):<4} = {(pred[m] == c).mean():.3f}")
    print(BAR)

    return pd.DataFrame({
        "row": np.arange(1, n + 1),
        "predicted": pred,
        "confidence": np.round(conf, 6),
        "anchor": anchor,
        **({"ground_truth": truth, "correct": pred == truth} if truth is not None else {}),
    })


def batch_from_testfold(det):
    payload = json.loads(config.COLUMNS_JSON.read_text(encoding="utf-8"))
    COARSE = config.COARSE_LABEL_COLUMN
    fine_col = payload.get("fine_grained_label")
    cols = list(dict.fromkeys(det.feats + [COARSE] + ([fine_col] if fine_col else [])))
    print("  loading the test fold ...")
    df = pd.read_parquet(config.TEST_PARQUET, columns=cols)
    print(f"  {len(df):,} flows available")

    raw = input("  how many rows? [25] > ").strip()
    n = int(raw) if raw.isdigit() and int(raw) > 0 else 25
    n = min(n, len(df))

    print("\n    1. the first N rows, in capture order")
    print("    2. N rows at random")
    print("    3. N rows of one chosen class")
    mode = input("  select > ").strip()

    if mode == "2":
        sub = df.sample(n, random_state=np.random.randint(0, 1 << 30))
        label = f"{n} random"
    elif mode == "3":
        present = [l for l in det.labels if (df[COARSE].astype(str) == l).any()]
        print()
        for i, c in enumerate(present, 1):
            print(f"    {i}. {c:<14} ({int((df[COARSE].astype(str) == c).sum()):,})")
        try:
            cls = present[int(input("\n  class > ").strip()) - 1]
        except (ValueError, IndexError):
            print("  not a valid option")
            return
        pool = df[df[COARSE].astype(str) == cls]
        sub = pool.head(min(n, len(pool)))
        label = f"class {cls}"
    else:
        sub = df.head(n)
        label = f"first {n} rows"

    sub = sub.reset_index(drop=True)
    truth = sub[COARSE].astype(str).to_numpy()
    fine = sub[fine_col].astype(str).to_numpy() if fine_col else None
    out = show_batch(det, sub, truth, fine, label)
    offer_save(out)


def batch_from_csv(det, stats):
    """Score an external CSV — including a different dataset entirely.

    Cross-dataset testing needs three things the in-project path gets for
    free. First, the exporter cleaning applied in stage 02 (magnitude
    masking and median imputation) has not been applied to raw external
    data, so it is applied here with the TRAINING-fold medians. Second, a
    foreign dataset may not carry all 25 features, so missing ones are
    filled with the training median rather than refusing outright. Third,
    its labels are its own — NF-UNSW-NB15 has Exploits, Fuzzers, Worms and
    so on, which do not map onto these seven categories — so multiclass
    scoring is meaningless while BINARY attack-versus-benign scoring is
    both valid and the standard cross-dataset comparison.
    """
    path = input("  path to CSV > ").strip().strip('"').strip("'")
    try:
        df = pd.read_csv(path, low_memory=False)
    except Exception as e:
        print(f"  could not read that file: {e}")
        return
    print(f"  {len(df):,} rows, {len(df.columns)} columns")

    raw = input("  how many rows to score? [all] > ").strip()
    if raw.isdigit() and int(raw) > 0:
        df = df.head(int(raw))
    df = df.reset_index(drop=True)

    missing = [f for f in det.feats if f not in df.columns]
    if missing:
        print(f"\n  {len(missing)} of {len(det.feats)} model features are absent:")
        for f in missing[:8]:
            print(f"    - {f}")
        if len(missing) > 8:
            print(f"    ... and {len(missing) - 8} more")
        print("\n  These can be filled with the training-fold median, but every")
        print("  filled feature is a feature the model is not actually seeing,")
        print("  so treat the result as indicative only.")
        if input("  proceed anyway? [y/N] > ").strip().lower() != "y":
            return
        for f in missing:
            df[f] = float(stats.loc[f, "median"])

    # Same cleaning stage 02 applies: magnitude masking catches the exporter's
    # divide-by-near-zero artifacts and +/-Inf, then train-fold medians fill.
    block = df[det.feats].apply(pd.to_numeric, errors="coerce")
    cutoff = getattr(config, "NUMERIC_OUTLIER_ABS_CUTOFF", 2e13)
    n_masked = int((block.abs() > cutoff).to_numpy().sum())
    block = block.mask(block.abs() > cutoff)
    n_nan = int(block.isna().to_numpy().sum()) - n_masked
    for f in det.feats:
        block[f] = block[f].fillna(float(stats.loc[f, "median"]))
    df[det.feats] = block
    if n_masked or n_nan:
        print(f"  cleaning: {n_masked:,} values beyond {cutoff:.0e} masked, "
              f"{max(n_nan, 0):,} non-numeric or missing — all filled with "
              f"training medians")

    # ---- work out what ground truth, if any, is available -----------------
    COARSE = config.COARSE_LABEL_COLUMN
    truth = binary_truth = None
    mode = "none"

    if COARSE in df.columns:
        truth = df[COARSE].astype(str).to_numpy()
        mode = "multiclass"
    else:
        lab_col = next((c for c in df.columns if c.lower() == "label"), None)
        atk_col = next((c for c in df.columns if c.lower() == "attack"), None)
        if atk_col is not None:
            vals = df[atk_col].astype(str)
            benign_names = {str(v).lower() for v in
                            getattr(config, "BENIGN_LABEL_VALUES", ["Benign"])}
            binary_truth = (~vals.str.lower().isin(benign_names)).astype(int).to_numpy()
            mode = "binary"
            print(f"  using '{atk_col}' for binary ground truth; its classes are "
                  f"foreign to this model, so multiclass scoring is skipped")
        elif lab_col is not None:
            binary_truth = pd.to_numeric(df[lab_col], errors="coerce") \
                             .fillna(0).astype(int).to_numpy()
            mode = "binary"
            print(f"  using '{lab_col}' (0/1) for binary ground truth")
        else:
            print("  no label column found — predictions shown without ground truth")

    out = show_batch(det, df, truth, None, f"from {path}")

    if mode == "binary":
        pred_attack = (out["predicted"].to_numpy() != "Benign").astype(int)
        tp = int(((binary_truth == 1) & (pred_attack == 1)).sum())
        fn = int(((binary_truth == 1) & (pred_attack == 0)).sum())
        fp = int(((binary_truth == 0) & (pred_attack == 1)).sum())
        tn = int(((binary_truth == 0) & (pred_attack == 0)).sum())
        dr = tp / (tp + fn) if (tp + fn) else float("nan")
        fpr = fp / (fp + tn) if (fp + tn) else float("nan")
        prec = tp / (tp + fp) if (tp + fp) else float("nan")
        f1 = 2 * prec * dr / (prec + dr) if (prec + dr) else float("nan")
        print("\n  BINARY attack-vs-benign (the valid cross-dataset comparison):")
        print(f"    detection rate   : {dr:.4f}   ({tp} of {tp + fn} attacks caught)")
        print(f"    false pos. rate  : {fpr:.4f}   ({fp} of {fp + tn} benign flagged)")
        print(f"    precision        : {prec:.4f}")
        print(f"    binary F1        : {f1:.4f}")
        print("\n  In-distribution reference on NF-CSE-CIC-IDS2018-v2: "
              "binary F1 0.9809, FPR 0.0003.")
        print("  A large drop here is the expected and well-documented "
              "cross-dataset behaviour,")
        print("  not a defect — report it as a generalisation result.")
        out["binary_truth"] = binary_truth

    offer_save(out)


def offer_save(out: pd.DataFrame):
    if input("\n  save these results to CSV? [y/N] > ").strip().lower() != "y":
        return
    path = config.OUTPUTS_DIR / "11_batch_results.csv"
    out.to_csv(path, index=False)
    print(f"  wrote {path}")


def main():
    det = Detector()
    stats = feature_stats(det.feats)

    print("\n" + BAR)
    print("  CLOUD IDS — DETECTION LAYER")
    print(BAR)
    print(f"  model            : {det.model_version}")
    print(f"  features         : {len(det.feats)}")
    print(f"  threat classes   : {', '.join(det.labels)}")
    print(f"  anchoring gate   : tau = {det.tau:.6f}")
    print(BAR)

    while True:
        print("\n  --- single flow ---")
        print("  1. enter feature values one at a time")
        print("  2. paste all values comma-separated")
        print("  3. load a real flow from the test fold (shows ground truth)")
        print("  4. load a flow from a JSON file")
        print("  --- many flows at once ---")
        print("  5. batch from the test fold (first N, random N, or one class)")
        print("  6. batch from an external CSV (any NetFlow v9 dataset)")
        print("  --- other ---")
        print("  7. show the feature list")
        print("  q. quit")
        choice = input("\n  select > ").strip().lower()

        truth = fine = None
        if choice in ("q", "quit", "exit"):
            print()
            return
        elif choice == "1":
            values = enter_manually(det, stats)
        elif choice == "2":
            values = paste_values(det, stats)
        elif choice == "3":
            values, truth, fine = real_flow(det)
        elif choice == "4":
            values = from_file(det)
        elif choice == "5":
            batch_from_testfold(det)
            continue
        elif choice == "6":
            batch_from_csv(det, stats)
            continue
        elif choice == "7":
            print()
            for i, f in enumerate(det.feats, 1):
                s = stats.loc[f]
                print(f"    {i:2d}. {f:<32} median={s['median']:<14g} "
                      f"range={s['min']:g} .. {s['max']:g}")
            continue
        else:
            print("  not a valid option")
            continue

        if values is None:
            continue
        result = det.predict(values)
        show(result, truth, fine)

        if input("\n  print the full alert JSON? [y/N] > ").strip().lower() == "y":
            out = dict(result)
            out["top_contributing_features"] = [
                {"feature": n, "value": v, "shap": s}
                for n, v, s in result["top_contributing_features"]]
            out["class_probabilities"] = {
                k: round(v, 6) for k, v in out["class_probabilities"].items()}
            print()
            print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
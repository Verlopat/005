"""
Stage 05 — Model comparison.

LogReg / RandomForest / LightGBM / XGBoost / CatBoost on the SAME 25 features
and the SAME pre-written splits from 02_prepare.py. All class-balanced,
defaults otherwise.

SELECTION RULE: winner = highest TEST macro-F1. Latency is recorded but is
NOT a filter — nothing is excluded for being slow.

Two metric blocks are reported per model:
  (1) AS-SAMPLED — on the test split as written, benign downsampled to
      config.BENIGN_KEEP_FRACTION. Directly comparable to the stage-04
      baseline (accuracy 0.9719 / macro-F1 0.7750).
  (2) NATURAL-PRIOR — identical predictions, but benign rows weighted
      1/BENIGN_KEEP_FRACTION to recover the deployment class balance.
      This is the honest false-positive picture and the one that feeds
      the on-chain volume axis of the ICR curve.

Each model's results are saved as it finishes; re-running skips completed
models, so a crash costs one model, not the run.

Run: python 05_compare_models.py
"""

from __future__ import annotations

import json
import sys
import time
import warnings

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    f1_score, precision_recall_fscore_support,
)
from sklearn.utils.class_weight import compute_sample_weight

import config

warnings.filterwarnings("ignore")

RUN = ["logreg", "extratrees", "randomforest", "balanced_rf",
       "lightgbm", "xgboost", "catboost", "mlp", "cascade",
       "cascade_unweighted", "lightgbm_unweighted"]

# "voting" is derived after the loop by averaging the saved probability
# matrices of the three boosters — no extra training.
VOTING_MEMBERS = ["lightgbm", "xgboost", "catboost"]

# LogReg on ~2.25M training rows is slow and will lose anyway. Subsample its
# training only, preserving row order. None = train on everything.
LOGREG_TRAIN_SUBSAMPLE = 1_000_000

# sklearn's MLPClassifier accepts neither class_weight nor sample_weight, so
# the only way to give it the same balanced treatment as the others is to
# resample. Each class is capped at this many training rows; rare classes
# keep everything they have. Stated in the write-up as a limitation of the
# comparison rather than glossed over.
MLP_CLASS_CAP = 100_000
MLP_MAX_ITER = 30

# Forests are the memory risk. Depth cap + fewer workers.
RF_MAX_DEPTH = 20
RF_N_JOBS = 4

LATENCY_BATCH = 1000
LATENCY_REPEATS = 50

OUTDIR = config.OUTPUTS_DIR / "05_comparison"
BASELINE_ACC, BASELINE_MF1 = 0.9719, 0.7750


# --------------------------------------------------------------------------
def resolve_label_columns(df: pd.DataFrame) -> tuple[str, str | None]:
    """Return (coarse_label_column, fine_label_column_or_None).

    02_prepare.py may have written the coarse categories into
    config.COARSE_LABEL_COLUMN, or mapped them in place over the raw
    multiclass column. Detect which, rather than assuming.
    """
    payload = json.loads(config.COLUMNS_JSON.read_text(encoding="utf-8"))
    # "multiclass_label" is overwritten with the COARSE column name by
    # 02_prepare.py; the raw fine-grained name lives under its own key.
    raw_multiclass = (payload.get("fine_grained_label")
                      or payload.get("multiclass_label")
                      or payload.get("binary_label"))

    coarse_set = set(config.COARSE_CATEGORIES)

    if config.COARSE_LABEL_COLUMN in df.columns:
        coarse = config.COARSE_LABEL_COLUMN
        fine = raw_multiclass if raw_multiclass in df.columns else None
        if fine and set(df[fine].astype(str).unique()) <= coarse_set:
            fine = None  # it was mapped in place; no fine detail left
        return coarse, fine

    if raw_multiclass in df.columns:
        values = set(df[raw_multiclass].astype(str).unique())
        if values <= coarse_set:
            return raw_multiclass, None   # mapped in place
        return raw_multiclass, raw_multiclass  # still fine-grained

    sys.exit(f"Cannot find a label column. columns.json says {raw_multiclass!r}, "
             f"parquet has {list(df.columns)}")


def measure_latency(predict_fn, X):
    Xb = X.iloc[:LATENCY_BATCH]
    predict_fn(Xb)
    batch = []
    for _ in range(LATENCY_REPEATS):
        t0 = time.perf_counter()
        predict_fn(Xb)
        batch.append((time.perf_counter() - t0) * 1000)
    X1 = X.iloc[:1]
    predict_fn(X1)
    single = []
    for _ in range(200):
        t0 = time.perf_counter()
        predict_fn(X1)
        single.append((time.perf_counter() - t0) * 1000)
    return {
        "batch_size": LATENCY_BATCH,
        "batch_p50_ms": float(np.percentile(batch, 50)),
        "batch_p99_ms": float(np.percentile(batch, 99)),
        "single_p50_ms": float(np.percentile(single, 50)),
        "single_p99_ms": float(np.percentile(single, 99)),
    }


def metrics_block(y_true, y_pred, labels, weights=None):
    acc = accuracy_score(y_true, y_pred, sample_weight=weights)
    mf1 = f1_score(y_true, y_pred, average="macro", labels=labels,
                   sample_weight=weights, zero_division=0)
    yt = (y_true != "Benign").astype(int)
    yp = (y_pred != "Benign").astype(int)
    bp, br, bf, _ = precision_recall_fscore_support(
        yt, yp, average="binary", sample_weight=weights, zero_division=0)
    w = np.ones(len(y_true)) if weights is None else weights
    fp = float(w[(yt == 0) & (yp == 1)].sum())
    tn = float(w[(yt == 0) & (yp == 0)].sum())
    return {"accuracy": float(acc), "macro_f1": float(mf1),
            "binary_precision": float(bp), "binary_recall": float(br),
            "binary_f1": float(bf),
            "fpr": fp / (fp + tn) if (fp + tn) else float("nan")}


def per_class_detail(y_true, y_pred, labels):
    out = {}
    for lab in labels:
        m = y_true == lab
        if m.sum() == 0:
            continue
        out[lab] = {
            "support": int(m.sum()),
            "recall": float((y_pred[m] == lab).mean()),
            "f1": float(f1_score(y_true == lab, y_pred == lab, zero_division=0)),
            "binary_recall": (float((y_pred[m] != "Benign").mean())
                              if lab != "Benign" else None),
        }
    return out


# ------------------------------- LOAD -------------------------------------
for p in (config.TRAIN_PARQUET, config.VAL_PARQUET, config.TEST_PARQUET,
          config.SELECTED_FEATURES_JSON):
    if not p.exists():
        sys.exit(f"Missing {p}. Run stages 02 and 04 first.")

OUTDIR.mkdir(parents=True, exist_ok=True)

feats = json.loads(config.SELECTED_FEATURES_JSON.read_text())["selected_features"]
print(f"{len(feats)} selected features")

print("loading splits ...")
train_df = pd.read_parquet(config.TRAIN_PARQUET)
test_df = pd.read_parquet(config.TEST_PARQUET)

COARSE, FINE = resolve_label_columns(train_df)
print(f"coarse label column: {COARSE}")
print(f"fine label column:   {FINE or 'NOT AVAILABLE (mapped in place)'}")

X_tr = train_df[feats].astype("float32")
y_tr = train_df[COARSE].astype(str).to_numpy(dtype=object)
X_te = test_df[feats].astype("float32")
y_te = test_df[COARSE].astype(str).to_numpy(dtype=object)
y_fine = test_df[FINE].astype(str).to_numpy(dtype=object) if FINE else None
del train_df

labels = [c for c in config.COARSE_CATEGORIES if c in set(y_tr) | set(y_te)]
lab2i = {l: i for i, l in enumerate(labels)}

# natural-prior weights: undo the benign downsampling
w_te = np.where(y_te == "Benign", 1.0 / config.BENIGN_KEEP_FRACTION, 1.0)

print(f"train {len(X_tr):,} | test {len(X_te):,}")
print("\ntrain class counts:")
print(pd.Series(y_tr).value_counts().to_string())
print(f"\nnatural-prior benign weight: {1 / config.BENIGN_KEEP_FRACTION:.3f}x")
print(f"benign share  as-sampled {(y_te == 'Benign').mean():.3f}  ->  "
      f"natural {w_te[y_te == 'Benign'].sum() / w_te.sum():.3f}")

if set(y_tr) != set(y_te):
    print(f"\n!! classes differ across splits — train-only {set(y_tr) - set(y_te)}, "
          f"test-only {set(y_te) - set(y_tr)}")


# ------------------------------ MODELS ------------------------------------
def build_logreg():
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    return make_pipeline(StandardScaler(),
                         LogisticRegression(class_weight="balanced",
                                            max_iter=1000, n_jobs=-1,
                                            random_state=config.RANDOM_SEED))


def build_rf():
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(class_weight="balanced",
                                  max_depth=RF_MAX_DEPTH, n_jobs=RF_N_JOBS,
                                  random_state=config.RANDOM_SEED)


def build_lgbm():
    from lightgbm import LGBMClassifier
    return LGBMClassifier(objective="multiclass", num_class=len(labels),
                          class_weight="balanced", n_jobs=-1,
                          random_state=config.RANDOM_SEED, verbosity=-1)


def build_xgb():
    from xgboost import XGBClassifier
    return XGBClassifier(objective="multi:softprob", num_class=len(labels),
                         tree_method="hist", n_jobs=-1,
                         random_state=config.RANDOM_SEED, verbosity=0)


def build_cat():
    from catboost import CatBoostClassifier
    # CatBoost defaults to iterations=1000 while LightGBM and XGBoost default
    # to 100. Left alone, "defaults otherwise" would hand CatBoost 10x the
    # capacity and 10x the training time, making the comparison meaningless.
    # Matched to 100 so all three boosters get the same tree budget.
    return CatBoostClassifier(loss_function="MultiClass",
                              iterations=100,
                              auto_class_weights="Balanced",
                              random_seed=config.RANDOM_SEED,
                              verbose=50, allow_writing_files=False)


def build_extratrees():
    # The UQ authors who published NF-CSE-CIC-IDS2018-v2 used an Extra Trees
    # classifier in their own papers, so this is the closest thing to a
    # published baseline for this exact dataset.
    from sklearn.ensemble import ExtraTreesClassifier
    return ExtraTreesClassifier(class_weight="balanced",
                                max_depth=RF_MAX_DEPTH, n_jobs=RF_N_JOBS,
                                random_state=config.RANDOM_SEED)


def build_balanced_rf():
    # Draws a class-balanced bootstrap per tree rather than reweighting the
    # loss — a genuinely different mechanism from class_weight='balanced'.
    from imblearn.ensemble import BalancedRandomForestClassifier
    return BalancedRandomForestClassifier(
        sampling_strategy="all", replacement=True, bootstrap=False,
        max_depth=RF_MAX_DEPTH, n_jobs=RF_N_JOBS,
        random_state=config.RANDOM_SEED)


def build_mlp():
    from sklearn.neural_network import MLPClassifier
    from sklearn.pipeline import make_pipeline
    from sklearn.preprocessing import StandardScaler
    return make_pipeline(
        StandardScaler(),
        MLPClassifier(hidden_layer_sizes=(128, 64), max_iter=MLP_MAX_ITER,
                      early_stopping=True, n_iter_no_change=5,
                      batch_size=1024, random_state=config.RANDOM_SEED))


class Cascade:
    """Two-stage classifier: detect, then name.

    Stage A is binary attack-vs-benign over all training rows. Stage B is
    multiclass over attack rows ONLY. The point is the ratio the rare
    classes face: in a flat 7-class model Web Attacks (2,114 train rows)
    competes against Benign (898,322) and DDoS (833,537); with benign
    removed from stage B that contest drops by well over an order of
    magnitude.

    Probabilities compose properly, which matters because the confidence
    gate on the ICR curve consumes them:
        P(Benign)      = P_A(benign)
        P(attack A_i)  = P_A(attack) * P_B(A_i | attack)
    so the 7 outputs still sum to 1 and stay usable for calibration.
    """

    def __init__(self, class_labels, balanced=True):
        self.labels = list(class_labels)
        self.balanced = balanced
        self.stage_a = None
        self.stage_b = None

    def fit(self, X, y):
        from lightgbm import LGBMClassifier
        y = np.asarray(y).astype(str)
        weight = "balanced" if self.balanced else None

        self.stage_a = LGBMClassifier(objective="binary",
                                      class_weight=weight, n_jobs=-1,
                                      random_state=config.RANDOM_SEED,
                                      verbosity=-1)
        self.stage_a.fit(X, (y != "Benign").astype(int))

        attack = y != "Benign"
        n_attack_classes = len(set(y[attack]))
        self.stage_b = LGBMClassifier(objective="multiclass",
                                      num_class=n_attack_classes,
                                      class_weight=weight, n_jobs=-1,
                                      random_state=config.RANDOM_SEED,
                                      verbosity=-1)
        self.stage_b.fit(X[attack], y[attack])
        return self

    def predict_proba(self, X):
        pa = self.stage_a.predict_proba(X)
        pb = self.stage_b.predict_proba(X)
        out = np.zeros((len(X), len(self.labels)), dtype="float32")
        out[:, self.labels.index("Benign")] = pa[:, 0]
        for j, lab in enumerate(self.stage_b.classes_):
            out[:, self.labels.index(str(lab))] = pa[:, 1] * pb[:, j]
        return out

    def predict(self, X):
        return np.array(self.labels)[self.predict_proba(X).argmax(axis=1)]


def build_cascade():
    return Cascade(labels, balanced=True)


def build_cascade_unweighted():
    # Stage 05 showed class_weight='balanced' collapsing benign precision:
    # weights are fitted on a train fold that is 40% benign, then meet a test
    # fold that is 88% benign. These two unweighted variants isolate how much
    # of the cascade's advantage is the architecture and how much is the
    # weighting choice.
    return Cascade(labels, balanced=False)


def build_lgbm_unweighted():
    from lightgbm import LGBMClassifier
    return LGBMClassifier(objective="multiclass", num_class=len(labels),
                          n_jobs=-1, random_state=config.RANDOM_SEED,
                          verbosity=-1)


BUILDERS = {"logreg": build_logreg, "randomforest": build_rf,
            "extratrees": build_extratrees, "balanced_rf": build_balanced_rf,
            "mlp": build_mlp, "cascade": build_cascade,
            "cascade_unweighted": build_cascade_unweighted,
            "lightgbm_unweighted": build_lgbm_unweighted,
            "lightgbm": build_lgbm, "xgboost": build_xgb, "catboost": build_cat}


def training_subset(name):
    """Per-model training-set adjustments, all order-preserving."""
    if name == "logreg" and LOGREG_TRAIN_SUBSAMPLE and len(X_tr) > LOGREG_TRAIN_SUBSAMPLE:
        rng = np.random.default_rng(config.RANDOM_SEED)
        idx = np.sort(rng.choice(len(X_tr), LOGREG_TRAIN_SUBSAMPLE, replace=False))
        print(f"  subsampled training: {len(idx):,} rows")
        return X_tr.iloc[idx], y_tr[idx]

    if name == "mlp":
        rng = np.random.default_rng(config.RANDOM_SEED)
        keep = []
        for lab in labels:
            pos = np.flatnonzero(y_tr == lab)
            if len(pos) > MLP_CLASS_CAP:
                pos = rng.choice(pos, MLP_CLASS_CAP, replace=False)
            keep.append(pos)
        idx = np.sort(np.concatenate(keep))
        print(f"  class-capped training at {MLP_CLASS_CAP:,}/class: "
              f"{len(idx):,} rows (MLPClassifier supports no class weighting)")
        return X_tr.iloc[idx], y_tr[idx]

    return X_tr, y_tr

results = {}
for name in RUN:
    outfile = OUTDIR / f"{name}.json"
    if outfile.exists():
        print(f"\n=== {name}: done already, skipping ===")
        results[name] = json.loads(outfile.read_text())
        continue

    print(f"\n{'=' * 70}\n{name}\n{'=' * 70}")
    try:
        model = BUILDERS[name]()
        Xf, yf = training_subset(name)

        t0 = time.perf_counter()
        if name == "xgboost":
            model.fit(Xf, np.array([lab2i[v] for v in yf]),
                      sample_weight=compute_sample_weight("balanced", yf))
        else:
            model.fit(Xf, yf)
        fit_min = (time.perf_counter() - t0) / 60
        print(f"  fit: {fit_min:.1f} min")

        def predict(Z, _m=model, _n=name):
            p = np.asarray(_m.predict(Z)).ravel()
            return (np.array([labels[int(i)] for i in p]) if _n == "xgboost"
                    else p.astype(str))

        pred = predict(X_te)

        as_sampled = metrics_block(y_te, pred, labels)
        natural = metrics_block(y_te, pred, labels, weights=w_te)

        print(f"\n  AS-SAMPLED    acc {as_sampled['accuracy']:.4f} | "
              f"macro-F1 {as_sampled['macro_f1']:.4f} | "
              f"binF1 {as_sampled['binary_f1']:.4f} | "
              f"FPR {as_sampled['fpr']:.5f}")
        print(f"  NATURAL-PRIOR acc {natural['accuracy']:.4f} | "
              f"macro-F1 {natural['macro_f1']:.4f} | "
              f"binF1 {natural['binary_f1']:.4f} | "
              f"FPR {natural['fpr']:.5f}")
        print("\n" + classification_report(y_te, pred, labels=labels,
                                           digits=3, zero_division=0))
        print("confusion (rows=true, cols=pred)")
        print(pd.DataFrame(confusion_matrix(y_te, pred, labels=labels),
                           index=labels, columns=labels).to_string())

        r = {"as_sampled": as_sampled, "natural_prior": natural,
             "per_class": per_class_detail(y_te, pred, labels),
             "fit_minutes": fit_min, "latency": measure_latency(predict, X_te)}
        print(f"\n  latency: batch({LATENCY_BATCH}) p99 "
              f"{r['latency']['batch_p99_ms']:.1f} ms | single p99 "
              f"{r['latency']['single_p99_ms']:.3f} ms")

        if FINE:
            d = pd.DataFrame({"fine": y_fine, "true": y_te, "pred": pred})
            d = d[d["true"] != "Benign"]
            g = d.groupby("fine").apply(lambda x: pd.Series({
                "support": len(x),
                "binary_recall": (x["pred"] != "Benign").mean(),
                "coarse_correct": (x["pred"] == x["true"]).mean(),
            }), include_groups=False).sort_values("coarse_correct")
            print("\nper raw subtype:")
            print(g.to_string(float_format=lambda v: f"{v:.4f}"))
            r["per_subtype"] = g.to_dict("index")

        np.savez_compressed(OUTDIR / f"{name}_test.npz",
                            y_true=y_te, y_pred=pred,
                            proba=model.predict_proba(X_te).astype("float32"),
                            classes=np.array(labels))
        outfile.write_text(json.dumps(r, indent=2))
        results[name] = r

    except Exception as e:
        print(f"  FAILED: {type(e).__name__}: {e}")
        results[name] = {"error": f"{type(e).__name__}: {e}"}

# --------------------------- VOTING ENSEMBLE ------------------------------
# Averages the probability matrices already saved by the three boosters.
# No refitting: their errors are partly uncorrelated, so the mean is usually
# a little better than any single member. Cost is 3x inference latency,
# which is why the summed p99 is reported honestly below.
vote_file = OUTDIR / "voting.json"
if vote_file.exists():
    results["voting"] = json.loads(vote_file.read_text())
    print("\n=== voting: done already, skipping ===")
else:
    available = [m for m in VOTING_MEMBERS if (OUTDIR / f"{m}_test.npz").exists()]
    if len(available) < 2:
        print(f"\n=== voting: skipped, needs >=2 members, found {available} ===")
    else:
        print(f"\n{'=' * 70}\nvoting (soft) — members: {', '.join(available)}\n{'=' * 70}")
        try:
            stack = None
            for member in available:
                blob = np.load(OUTDIR / f"{member}_test.npz", allow_pickle=True)
                member_labels = [str(c) for c in blob["classes"]]
                proba = blob["proba"].astype("float32")
                # Reorder to the canonical label order before averaging —
                # silently summing mismatched columns would be a real bug.
                order = [member_labels.index(l) for l in labels]
                proba = proba[:, order]
                stack = proba if stack is None else stack + proba
            proba = stack / len(available)
            pred = np.array(labels)[proba.argmax(axis=1)]

            as_sampled = metrics_block(y_te, pred, labels)
            natural = metrics_block(y_te, pred, labels, weights=w_te)
            print(f"  AS-SAMPLED    acc {as_sampled['accuracy']:.4f} | "
                  f"macro-F1 {as_sampled['macro_f1']:.4f} | "
                  f"binF1 {as_sampled['binary_f1']:.4f}")
            print(f"  NATURAL-PRIOR acc {natural['accuracy']:.4f} | "
                  f"macro-F1 {natural['macro_f1']:.4f} | "
                  f"FPR {natural['fpr']:.5f}")
            print("\n" + classification_report(y_te, pred, labels=labels,
                                               digits=3, zero_division=0))

            r = {"as_sampled": as_sampled, "natural_prior": natural,
                 "per_class": per_class_detail(y_te, pred, labels),
                 "members": available,
                 "fit_minutes": sum(results[m]["fit_minutes"] for m in available),
                 "latency": {"batch_p99_ms": sum(results[m]["latency"]["batch_p99_ms"]
                                                 for m in available),
                             "single_p99_ms": sum(results[m]["latency"]["single_p99_ms"]
                                                  for m in available),
                             "note": "summed across members"}}
            np.savez_compressed(OUTDIR / "voting_test.npz", y_true=y_te,
                                y_pred=pred, proba=proba,
                                classes=np.array(labels))
            vote_file.write_text(json.dumps(r, indent=2))
            results["voting"] = r
        except Exception as e:
            print(f"  FAILED: {type(e).__name__}: {e}")
            results["voting"] = {"error": f"{type(e).__name__}: {e}"}


# ------------------------------ SUMMARY -----------------------------------
rows = []
for name, r in results.items():
    if "error" in r:
        rows.append({"model": name, "macro_F1": np.nan, "note": r["error"][:45]})
        continue
    rows.append({
        "model": name,
        "macro_F1": r["as_sampled"]["macro_f1"],
        "accuracy": r["as_sampled"]["accuracy"],
        "binary_F1": r["as_sampled"]["binary_f1"],
        "nat_macroF1": r["natural_prior"]["macro_f1"],
        "nat_FPR": r["natural_prior"]["fpr"],
        "Infil_rec": r["per_class"].get("Infiltration", {}).get("recall"),
        "Web_rec": r["per_class"].get("Web Attacks", {}).get("recall"),
        "fit_min": r["fit_minutes"],
        "p99_ms": r["latency"]["batch_p99_ms"],
    })

summary = pd.DataFrame(rows).sort_values("macro_F1", ascending=False)
print(f"\n{'=' * 70}\nSUMMARY — ranked by as-sampled macro-F1 (selection rule)\n{'=' * 70}")
print(summary.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
print(f"\nstage-04 untuned baseline: accuracy {BASELINE_ACC} | macro-F1 {BASELINE_MF1}")
summary.to_csv(OUTDIR / "summary.csv", index=False)
print(f"saved -> {OUTDIR}")
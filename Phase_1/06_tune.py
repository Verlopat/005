"""
Stage 06 — Optuna tuning, then per-class threshold optimisation.

Two architectures are tuned head-to-head on the SAME 25 features and the
SAME splits from 02_prepare.py:

  cascade   stage A binary attack-vs-benign, stage B multiclass over attack
            rows only. Tuned as two independent Optuna studies because the
            two stages do genuinely different jobs.
  flat      single 7-class LightGBM, unweighted (the 0.7424 stage-05 entry).

Untuned stage-05 reference: cascade 0.7524 / flat 0.7424 macro-F1. That gap
is one seed wide and decides nothing, which is why both are tuned before a
model is chosen.

DISCIPLINE — the test fold is touched exactly once, at the very end, to
report final numbers. Optuna optimises macro-F1 on VAL. Thresholds are
fitted on VAL. Nothing selects on test.

Two numbers are reported per model:
  argmax     standard prediction
  tuned-tau  per-class thresholds fitted on val by coordinate ascent

Run: python 06_tune.py
"""

from __future__ import annotations

import json
import sys
import time
import warnings

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, f1_score,
                             precision_recall_fscore_support)

import config

warnings.filterwarnings("ignore")

try:
    import optuna
except ImportError:
    sys.exit("Optuna is not installed. Run: pip install optuna")

optuna.logging.set_verbosity(optuna.logging.WARNING)

N_TRIALS = 40
OUTDIR = config.OUTPUTS_DIR / "06_tuning"
LATENCY_BATCH = 1000
LATENCY_REPEATS = 50

# Optuna scores every trial on the full val fold by default, which is 3.78M
# rows. Scoring on a fixed stratified subsample makes 40 trials tractable and
# keeps every trial comparable (the same rows every time). The winner is then
# re-scored on the FULL val fold before thresholds are fitted.
VAL_SCORE_SAMPLE = 600_000


# --------------------------------------------------------------------------
# metrics — identical definitions to stage 05 so numbers stay comparable
# --------------------------------------------------------------------------
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
        if not m.any():
            continue
        out[lab] = {
            "support": int(m.sum()),
            "recall": float((y_pred[m] == lab).mean()),
            "f1": float(f1_score(y_true == lab, y_pred == lab, zero_division=0)),
            "binary_recall": (float((y_pred[m] != "Benign").mean())
                              if lab != "Benign" else None),
        }
    return out


def measure_latency(predict_fn, X):
    predict_fn(X.iloc[:LATENCY_BATCH])
    batch = []
    for _ in range(LATENCY_REPEATS):
        t0 = time.perf_counter()
        predict_fn(X.iloc[:LATENCY_BATCH])
        batch.append((time.perf_counter() - t0) * 1000)
    return {"batch_size": LATENCY_BATCH,
            "batch_p50_ms": float(np.percentile(batch, 50)),
            "batch_p99_ms": float(np.percentile(batch, 99))}


# --------------------------------------------------------------------------
# threshold optimisation
# --------------------------------------------------------------------------
def apply_thresholds(proba, labels, tau):
    """Divide each class column by its threshold, then argmax.

    Lowering a class's tau makes it easier for that class to win, which is
    what the rare classes need. tau = 1 for every class reproduces argmax
    exactly, so the search can only improve on the argmax baseline.
    """
    return np.asarray(labels)[(proba / tau).argmax(axis=1)]


def fit_thresholds(proba, y_true, labels, rounds=3):
    """Coordinate ascent on per-class thresholds, maximising macro-F1.

    Fitted on VAL only. A grid search over 7 classes jointly is infeasible,
    but macro-F1 responds well to sweeping one class at a time and repeating.
    """
    tau = np.ones(len(labels))
    grid = np.array([0.05, 0.1, 0.2, 0.35, 0.5, 0.7, 1.0, 1.4, 2.0, 3.0, 5.0])
    best = f1_score(y_true, apply_thresholds(proba, labels, tau),
                    average="macro", labels=labels, zero_division=0)
    print(f"    argmax macro-F1 on val: {best:.4f}")

    for r in range(rounds):
        improved = False
        for j, lab in enumerate(labels):
            original = tau[j]
            for candidate in grid:
                tau[j] = candidate
                score = f1_score(y_true, apply_thresholds(proba, labels, tau),
                                 average="macro", labels=labels, zero_division=0)
                if score > best + 1e-6:
                    best, original, improved = score, candidate, True
            tau[j] = original
        print(f"    round {r + 1}: macro-F1 {best:.4f}")
        if not improved:
            break
    return tau, best


# --------------------------------------------------------------------------
# models
# --------------------------------------------------------------------------
class Cascade:
    """Detect, then name. Stage B never sees benign traffic."""

    def __init__(self, labels, params_a=None, params_b=None):
        self.labels = list(labels)
        self.params_a = params_a or {}
        self.params_b = params_b or {}

    def fit(self, X, y):
        from lightgbm import LGBMClassifier
        y = np.asarray(y).astype(str)
        base = dict(n_jobs=-1, random_state=config.RANDOM_SEED, verbosity=-1)

        self.stage_a = LGBMClassifier(objective="binary",
                                      class_weight="balanced",
                                      **base, **self.params_a)
        self.stage_a.fit(X, (y != "Benign").astype(int))

        attack = y != "Benign"
        self.stage_b = LGBMClassifier(objective="multiclass",
                                      num_class=len(set(y[attack])),
                                      class_weight="balanced",
                                      **base, **self.params_b)
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
        return np.asarray(self.labels)[self.predict_proba(X).argmax(axis=1)]


def build_flat(params):
    from lightgbm import LGBMClassifier
    return LGBMClassifier(objective="multiclass", num_class=len(LABELS),
                          n_jobs=-1, random_state=config.RANDOM_SEED,
                          verbosity=-1, **params)


def suggest_lgbm(trial, prefix):
    """Search space. min_child_samples and min_split_gain matter most here:
    they decide whether a 2,114-row class such as Web Attacks is ever given
    its own splits, or is absorbed into DDoS."""
    return {
        "n_estimators": trial.suggest_int(f"{prefix}_n_estimators", 100, 600, step=50),
        "learning_rate": trial.suggest_float(f"{prefix}_learning_rate", 0.02, 0.3, log=True),
        "num_leaves": trial.suggest_int(f"{prefix}_num_leaves", 31, 255, log=True),
        "max_depth": trial.suggest_int(f"{prefix}_max_depth", 4, 14),
        "min_child_samples": trial.suggest_int(f"{prefix}_min_child_samples", 5, 300, log=True),
        "min_split_gain": trial.suggest_float(f"{prefix}_min_split_gain", 0.0, 0.5),
        "subsample": trial.suggest_float(f"{prefix}_subsample", 0.6, 1.0),
        "subsample_freq": trial.suggest_int(f"{prefix}_subsample_freq", 0, 5),
        "colsample_bytree": trial.suggest_float(f"{prefix}_colsample_bytree", 0.5, 1.0),
        "reg_alpha": trial.suggest_float(f"{prefix}_reg_alpha", 1e-8, 10.0, log=True),
        "reg_lambda": trial.suggest_float(f"{prefix}_reg_lambda", 1e-8, 10.0, log=True),
    }


# --------------------------------------------------------------------------
# load
# --------------------------------------------------------------------------
for p in (config.TRAIN_PARQUET, config.VAL_PARQUET, config.TEST_PARQUET,
          config.SELECTED_FEATURES_JSON):
    if not p.exists():
        sys.exit(f"Missing {p}. Run stages 02 and 04 first.")

OUTDIR.mkdir(parents=True, exist_ok=True)

FEATS = json.loads(config.SELECTED_FEATURES_JSON.read_text())["selected_features"]
payload = json.loads(config.COLUMNS_JSON.read_text(encoding="utf-8"))
COARSE = config.COARSE_LABEL_COLUMN
FINE = payload.get("fine_grained_label")

print(f"{len(FEATS)} features | loading splits ...")
needed = FEATS + [COARSE] + ([FINE] if FINE else [])
train_df = pd.read_parquet(config.TRAIN_PARQUET, columns=needed)
val_df = pd.read_parquet(config.VAL_PARQUET, columns=needed)

X_tr = train_df[FEATS].astype("float32")
y_tr = train_df[COARSE].astype(str).to_numpy(dtype=object)
X_va = val_df[FEATS].astype("float32")
y_va = val_df[COARSE].astype(str).to_numpy(dtype=object)
del train_df

LABELS = [c for c in config.COARSE_CATEGORIES if c in set(y_tr) | set(y_va)]
print(f"train {len(X_tr):,} | val {len(X_va):,} | classes {LABELS}")

rng = np.random.default_rng(config.RANDOM_SEED)
if len(X_va) > VAL_SCORE_SAMPLE:
    keep = []
    for lab in LABELS:
        pos = np.flatnonzero(y_va == lab)
        take = max(1, int(round(len(pos) * VAL_SCORE_SAMPLE / len(y_va))))
        keep.append(rng.choice(pos, min(take, len(pos)), replace=False))
    sub = np.sort(np.concatenate(keep))
    X_va_s, y_va_s = X_va.iloc[sub], y_va[sub]
else:
    X_va_s, y_va_s = X_va, y_va
print(f"Optuna scores trials on {len(X_va_s):,} stratified val rows\n")


def score(pred):
    return f1_score(y_va_s, pred, average="macro", labels=LABELS, zero_division=0)


# --------------------------------------------------------------------------
# tuning
# --------------------------------------------------------------------------
def tune_cascade():
    def objective_a(trial):
        """Stage A is binary. Its job is benign precision — a false positive
        here can never be recovered by stage B, so it is scored on binary F1."""
        from lightgbm import LGBMClassifier
        p = suggest_lgbm(trial, "a")
        m = LGBMClassifier(objective="binary", class_weight="balanced",
                           n_jobs=-1, random_state=config.RANDOM_SEED,
                           verbosity=-1, **p)
        m.fit(X_tr, (y_tr != "Benign").astype(int))
        pred = m.predict(X_va_s)
        return f1_score((y_va_s != "Benign").astype(int), pred, zero_division=0)

    def objective_b(trial):
        """Stage B sees attack rows only, so it is scored on macro-F1 over
        the attack classes alone — benign cannot mask a rare-class failure."""
        from lightgbm import LGBMClassifier
        p = suggest_lgbm(trial, "b")
        atk_tr = y_tr != "Benign"
        atk_va = y_va_s != "Benign"
        m = LGBMClassifier(objective="multiclass",
                           num_class=len(set(y_tr[atk_tr])),
                           class_weight="balanced", n_jobs=-1,
                           random_state=config.RANDOM_SEED, verbosity=-1, **p)
        m.fit(X_tr[atk_tr], y_tr[atk_tr])
        pred = m.predict(X_va_s[atk_va])
        return f1_score(y_va_s[atk_va], pred, average="macro", zero_division=0)

    best = {}
    for tag, objective in (("A", objective_a), ("B", objective_b)):
        print(f"  tuning cascade stage {tag} ({N_TRIALS} trials) ...")
        study = optuna.create_study(
            direction="maximize",
            sampler=optuna.samplers.TPESampler(seed=config.RANDOM_SEED))
        study.optimize(objective, n_trials=N_TRIALS, show_progress_bar=False)
        print(f"    best stage-{tag} score: {study.best_value:.4f}")
        best[tag] = {k.split("_", 1)[1]: v for k, v in study.best_params.items()}
    return best


def tune_flat():
    def objective(trial):
        m = build_flat(suggest_lgbm(trial, "f"))
        m.fit(X_tr, y_tr)
        return score(m.predict(X_va_s))

    print(f"  tuning flat LightGBM ({N_TRIALS} trials) ...")
    study = optuna.create_study(
        direction="maximize",
        sampler=optuna.samplers.TPESampler(seed=config.RANDOM_SEED))
    study.optimize(objective, n_trials=N_TRIALS, show_progress_bar=False)
    print(f"    best val macro-F1: {study.best_value:.4f}")
    return {k.split("_", 1)[1]: v for k, v in study.best_params.items()}


results = {}
for name in ("cascade", "flat"):
    cache = OUTDIR / f"{name}_params.json"
    if cache.exists():
        print(f"=== {name}: tuned already, reusing params ===")
        params = json.loads(cache.read_text())
    else:
        print(f"\n{'=' * 70}\ntuning {name}\n{'=' * 70}")
        t0 = time.perf_counter()
        params = tune_cascade() if name == "cascade" else tune_flat()
        print(f"  tuning took {(time.perf_counter() - t0) / 60:.1f} min")
        cache.write_text(json.dumps(params, indent=2))
    results[name] = {"params": params}


# --------------------------------------------------------------------------
# refit on train, fit thresholds on FULL val
# --------------------------------------------------------------------------
models = {}
for name in ("cascade", "flat"):
    print(f"\n{'=' * 70}\nrefitting {name} with tuned params\n{'=' * 70}")
    p = results[name]["params"]
    t0 = time.perf_counter()
    model = (Cascade(LABELS, p["A"], p["B"]) if name == "cascade"
             else build_flat(p))
    model.fit(X_tr, y_tr)
    results[name]["fit_minutes"] = (time.perf_counter() - t0) / 60
    print(f"  fit: {results[name]['fit_minutes']:.1f} min")

    proba_va = model.predict_proba(X_va).astype("float32")
    if name == "flat":
        order = [list(model.classes_).index(l) for l in LABELS]
        proba_va = proba_va[:, order]
    print("  fitting per-class thresholds on the full val fold:")
    tau, val_best = fit_thresholds(proba_va, y_va, LABELS)
    results[name]["tau"] = dict(zip(LABELS, tau.tolist()))
    results[name]["val_macro_f1_tuned_tau"] = val_best
    print("  thresholds: " + ", ".join(f"{l}={t:.2f}" for l, t in zip(LABELS, tau)))
    models[name] = (model, tau)
    del proba_va

del X_va, y_va, X_va_s, y_va_s, val_df


# --------------------------------------------------------------------------
# final evaluation — test fold touched here, once
# --------------------------------------------------------------------------
test_df = pd.read_parquet(config.TEST_PARQUET, columns=needed)
X_te = test_df[FEATS].astype("float32")
y_te = test_df[COARSE].astype(str).to_numpy(dtype=object)
y_fine = test_df[FINE].astype(str).to_numpy(dtype=object) if FINE else None
del test_df
w_te = np.where(y_te == "Benign", 1.0 / config.BENIGN_KEEP_FRACTION, 1.0)
print(f"\ntest {len(X_te):,} rows")

for name, (model, tau) in models.items():
    print(f"\n{'=' * 70}\n{name} — final test evaluation\n{'=' * 70}")
    proba = model.predict_proba(X_te).astype("float32")
    if name == "flat":
        order = [list(model.classes_).index(l) for l in LABELS]
        proba = proba[:, order]

    for variant, t in (("argmax", np.ones(len(LABELS))), ("tuned_tau", tau)):
        pred = apply_thresholds(proba, LABELS, t)
        block = metrics_block(y_te, pred, LABELS)
        nat = metrics_block(y_te, pred, LABELS, weights=w_te)
        results[name][variant] = {
            "as_sampled": block, "natural_prior": nat,
            "per_class": per_class_detail(y_te, pred, LABELS)}
        print(f"\n  [{variant}] macro-F1 {block['macro_f1']:.4f} | "
              f"acc {block['accuracy']:.4f} | binF1 {block['binary_f1']:.4f} | "
              f"natFPR {nat['fpr']:.5f}")
        if variant == "tuned_tau":
            print(classification_report(y_te, pred, labels=LABELS,
                                        digits=4, zero_division=0))
            print("confusion (rows=true, cols=pred)")
            print(pd.DataFrame(confusion_matrix(y_te, pred, labels=LABELS),
                               index=LABELS, columns=LABELS).to_string())
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
                results[name]["per_subtype"] = g.to_dict("index")

    results[name]["latency"] = measure_latency(
        lambda Z: model.predict_proba(Z), X_te)
    print(f"\n  latency: batch({LATENCY_BATCH}) p99 "
          f"{results[name]['latency']['batch_p99_ms']:.1f} ms")

    np.savez_compressed(OUTDIR / f"{name}_test.npz", y_true=y_te,
                        proba=proba, classes=np.array(LABELS), tau=tau)
    del proba

(OUTDIR / "results.json").write_text(json.dumps(results, indent=2, default=str))


# --------------------------------------------------------------------------
# summary
# --------------------------------------------------------------------------
rows = []
for name in results:
    for variant in ("argmax", "tuned_tau"):
        b, n = results[name][variant]["as_sampled"], results[name][variant]["natural_prior"]
        pc = results[name][variant]["per_class"]
        rows.append({
            "model": f"{name}_{variant}",
            "macro_F1": b["macro_f1"], "accuracy": b["accuracy"],
            "binary_F1": b["binary_f1"], "nat_FPR": n["fpr"],
            "Infil_rec": pc.get("Infiltration", {}).get("recall"),
            "Web_rec": pc.get("Web Attacks", {}).get("recall"),
            "p99_ms": results[name]["latency"]["batch_p99_ms"],
        })

summary = pd.DataFrame(rows).sort_values("macro_F1", ascending=False)
print(f"\n{'=' * 70}\nSUMMARY — tuned, ranked by test macro-F1\n{'=' * 70}")
print(summary.to_string(index=False, float_format=lambda v: f"{v:.4f}"))
print("\nuntuned stage-05 reference: cascade 0.7524 | flat 0.7424")
summary.to_csv(OUTDIR / "summary.csv", index=False)
print(f"saved -> {OUTDIR}")

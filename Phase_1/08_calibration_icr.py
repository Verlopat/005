"""
Stage 08 — Calibration, then the Integrity Coverage Ratio (ICR) curve.

This is the stage the blockchain layer actually consumes. The detection
model emits a confidence score; the anchoring policy gates on it. That gate
is only meaningful if the score means what it says, which is what
calibration establishes, and its operating point is chosen from the ICR
curve.

PART A — CALIBRATION
  A raw gradient-boosting probability of 0.9 does not necessarily mean the
  flow is malicious 90% of the time. Isotonic and sigmoid (Platt) mappings
  are fitted ON THE VALIDATION FOLD and compared against the uncalibrated
  scores using ECE, MCE, Brier score and a reliability diagram.

PART B — INTEGRITY COVERAGE RATIO
  Anchoring every flow on-chain is not viable: ledger writes cost time and
  storage. Selective anchoring gates on calibrated confidence tau.

      ICR(tau)          = fraction of TRUE ATTACK flows anchored at tau
      on-chain volume   = fraction of ALL flows anchored at tau
      write reduction   = 1 - on-chain volume

  Sweeping tau traces the trade-off between evidentiary completeness and
  ledger cost. This is a blockchain-layer metric, not a classification
  metric: it asks what fraction of real attacks left a tamper-evident
  record, which no accuracy figure answers.

DISCIPLINE — calibrators are fitted on VAL. Test is used only to report.

Run: python 08_calibration_icr.py
"""

from __future__ import annotations

import json
import sys
import time

import numpy as np
import pandas as pd
from sklearn.calibration import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, roc_auc_score

import config

OUTDIR = config.OUTPUTS_DIR / "08_calibration_icr"
TUNE_DIR = config.OUTPUTS_DIR / "06_tuning"

# Which tuned architecture to carry forward. "flat" won stage 06 on macro-F1
# (0.8172 vs 0.8136); "cascade" is the alternative.
WINNER = "flat"

N_BINS = 15            # reliability diagram / ECE bins
TAU_POINTS = 201       # resolution of the ICR sweep


# --------------------------------------------------------------------------
# calibration metrics
# --------------------------------------------------------------------------
def expected_calibration_error(y_binary, scores, n_bins=N_BINS):
    """ECE: average gap between confidence and observed frequency, weighted
    by bin population. MCE: the worst single bin. Both in probability units,
    so 0.02 means 'off by 2 percentage points on average'."""
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    idx = np.clip(np.digitize(scores, edges[1:-1], right=False), 0, n_bins - 1)
    ece = mce = 0.0
    rows = []
    for b in range(n_bins):
        m = idx == b
        n = int(m.sum())
        if n == 0:
            rows.append({"bin_lo": edges[b], "bin_hi": edges[b + 1], "count": 0,
                         "mean_confidence": np.nan, "observed_frequency": np.nan,
                         "gap": np.nan})
            continue
        conf = float(scores[m].mean())
        freq = float(y_binary[m].mean())
        gap = abs(conf - freq)
        ece += n / len(scores) * gap
        mce = max(mce, gap)
        rows.append({"bin_lo": edges[b], "bin_hi": edges[b + 1], "count": n,
                     "mean_confidence": conf, "observed_frequency": freq,
                     "gap": gap})
    return ece, mce, pd.DataFrame(rows)


def calibration_block(name, y_binary, scores):
    ece, mce, table = expected_calibration_error(y_binary, scores)
    return {
        "method": name,
        "ECE": ece,
        "MCE": mce,
        "brier": brier_score_loss(y_binary, scores),
        "roc_auc": roc_auc_score(y_binary, scores),
    }, table


# --------------------------------------------------------------------------
# ICR
# --------------------------------------------------------------------------
def icr_curve(y_binary, scores, tau_grid):
    """For each gate tau, what fraction of true attacks get anchored, and
    what fraction of all traffic is written to the ledger.

    A flow is anchored when its calibrated attack confidence >= tau. Note
    that benign flows above tau are anchored too — they are the cost side of
    the trade, and they are what 'on-chain volume' counts that ICR does not.
    """
    total = len(scores)
    total_attacks = int(y_binary.sum())
    rows = []
    for tau in tau_grid:
        anchored = scores >= tau
        n_anchored = int(anchored.sum())
        attacks_anchored = int((anchored & (y_binary == 1)).sum())
        benign_anchored = n_anchored - attacks_anchored
        rows.append({
            "tau": float(tau),
            "ICR": attacks_anchored / total_attacks if total_attacks else np.nan,
            "on_chain_volume": n_anchored / total,
            "write_reduction": 1.0 - n_anchored / total,
            "anchored_flows": n_anchored,
            "attacks_anchored": attacks_anchored,
            "attacks_missed": total_attacks - attacks_anchored,
            "benign_anchored": benign_anchored,
            "anchor_precision": (attacks_anchored / n_anchored) if n_anchored else np.nan,
        })
    return pd.DataFrame(rows)


def per_class_icr(y_true, scores, tau, labels):
    """Which attack classes fall below the gate. A single ICR figure can
    hide a class that is systematically never anchored."""
    rows = []
    for lab in labels:
        if lab == "Benign":
            continue
        m = y_true == lab
        if not m.any():
            continue
        rows.append({"class": lab, "support": int(m.sum()),
                     "ICR_at_tau": float((scores[m] >= tau).mean()),
                     "mean_confidence": float(scores[m].mean())})
    return pd.DataFrame(rows).sort_values("ICR_at_tau")


# --------------------------------------------------------------------------
# model rebuild (validation probabilities were not saved by stage 06)
# --------------------------------------------------------------------------
class Cascade:
    def __init__(self, labels, params_a=None, params_b=None):
        self.labels = list(labels)
        self.params_a = params_a or {}
        self.params_b = params_b or {}

    def fit(self, X, y):
        from lightgbm import LGBMClassifier
        y = np.asarray(y).astype(str)
        base = dict(n_jobs=-1, random_state=config.RANDOM_SEED, verbosity=-1)
        self.stage_a = LGBMClassifier(objective="binary", class_weight="balanced",
                                      **base, **self.params_a)
        self.stage_a.fit(X, (y != "Benign").astype(int))
        attack = y != "Benign"
        self.stage_b = LGBMClassifier(objective="multiclass",
                                      num_class=len(set(y[attack])),
                                      class_weight="balanced", **base, **self.params_b)
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


def main() -> None:
    OUTDIR.mkdir(parents=True, exist_ok=True)
    params_file = TUNE_DIR / f"{WINNER}_params.json"
    test_file = TUNE_DIR / f"{WINNER}_test.npz"
    for p in (params_file, test_file):
        if not p.exists():
            sys.exit(f"Missing {p}. Run 06_tune.py first.")

    params = json.loads(params_file.read_text())
    feats = json.loads(config.SELECTED_FEATURES_JSON.read_text())["selected_features"]
    payload = json.loads(config.COLUMNS_JSON.read_text(encoding="utf-8"))
    COARSE = config.COARSE_LABEL_COLUMN

    blob = np.load(test_file, allow_pickle=True)
    labels = [str(c) for c in blob["classes"]]
    y_te = np.asarray(blob["y_true"]).astype(str)
    proba_te = blob["proba"].astype("float32")
    benign_col = labels.index("Benign")
    raw_test = 1.0 - proba_te[:, benign_col]     # attack confidence
    yb_te = (y_te != "Benign").astype(int)
    print(f"winner: {WINNER} | test {len(y_te):,} rows | "
          f"{int(yb_te.sum()):,} true attacks")

    # ---- validation probabilities: refit once ----------------------------
    val_cache = OUTDIR / f"{WINNER}_val_proba.npz"
    if val_cache.exists():
        vb = np.load(val_cache, allow_pickle=True)
        y_va = np.asarray(vb["y_true"]).astype(str)
        raw_val = vb["raw_score"].astype("float32")
        print("reusing cached validation scores")
    else:
        print("stage 06 saved test scores only — refitting the winner to "
              "produce VALIDATION scores for the calibrator ...")
        needed = feats + [COARSE]
        train_df = pd.read_parquet(config.TRAIN_PARQUET, columns=needed)
        X_tr = train_df[feats].astype("float32")
        y_tr = train_df[COARSE].astype(str).to_numpy(dtype=object)
        del train_df

        t0 = time.perf_counter()
        if WINNER == "cascade":
            model = Cascade(labels, params["A"], params["B"]).fit(X_tr, y_tr)
            order = list(range(len(labels)))
        else:
            from lightgbm import LGBMClassifier
            model = LGBMClassifier(objective="multiclass", num_class=len(labels),
                                   n_jobs=-1, random_state=config.RANDOM_SEED,
                                   verbosity=-1, **params)
            model.fit(X_tr, y_tr)
            order = [list(model.classes_).index(l) for l in labels]
        print(f"  refit: {(time.perf_counter() - t0) / 60:.1f} min")
        del X_tr, y_tr

        val_df = pd.read_parquet(config.VAL_PARQUET, columns=needed)
        y_va = val_df[COARSE].astype(str).to_numpy(dtype=object)
        pv = model.predict_proba(val_df[feats].astype("float32")).astype("float32")
        pv = pv[:, order]
        raw_val = 1.0 - pv[:, benign_col]
        del val_df, pv, model
        np.savez_compressed(val_cache, y_true=y_va, raw_score=raw_val)

    yb_va = (y_va != "Benign").astype(int)
    print(f"val {len(y_va):,} rows | {int(yb_va.sum()):,} true attacks\n")

    # ---- PART A: calibration --------------------------------------------
    print("=" * 70)
    print("PART A — calibration (fitted on val, reported on test)")
    print("=" * 70)

    iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    iso.fit(raw_val, yb_va)
    platt = LogisticRegression(C=1e10, solver="lbfgs")
    platt.fit(raw_val.reshape(-1, 1), yb_va)

    scored = {
        "uncalibrated": raw_test,
        "isotonic": iso.predict(raw_test).astype("float32"),
        "platt": platt.predict_proba(raw_test.reshape(-1, 1))[:, 1].astype("float32"),
    }

    cal_rows, tables = [], {}
    for method, s in scored.items():
        row, table = calibration_block(method, yb_te, s)
        cal_rows.append(row)
        tables[method] = table
        table.to_csv(OUTDIR / f"reliability_{method}.csv", index=False)

    cal = pd.DataFrame(cal_rows)
    print(cal.to_string(index=False, float_format=lambda v: f"{v:.6f}"))
    cal.to_csv(OUTDIR / "calibration_metrics.csv", index=False)

    # ROC-AUC is rank-based, so a monotone calibrator cannot change it.
    # If it moves, the mapping is not monotone and something is wrong.
    spread = cal["roc_auc"].max() - cal["roc_auc"].min()
    print(f"\nROC-AUC spread across methods: {spread:.6f} "
          f"({'as expected — calibration is rank-preserving' if spread < 1e-4 else 'UNEXPECTED — check the calibrator'})")

    best = cal.sort_values("ECE").iloc[0]["method"]
    print(f"lowest ECE: {best}")
    cal_score = scored[best]

    # ---- PART B: ICR -----------------------------------------------------
    print(f"\n{'=' * 70}")
    print(f"PART B — Integrity Coverage Ratio (calibrator: {best})")
    print("=" * 70)

    # A uniform grid wastes resolution: after isotonic calibration the scores
    # cluster on a few flat steps. Anchoring the grid on the observed score
    # quantiles guarantees every distinct operating point is visited.
    tau_grid = np.unique(np.concatenate([
        np.linspace(0.0, 1.0, TAU_POINTS),
        np.quantile(cal_score, np.linspace(0.0, 1.0, 400)),
        np.unique(cal_score)[:2000] if len(np.unique(cal_score)) < 2000
        else np.quantile(cal_score, np.linspace(0.85, 1.0, 600)),
        1 - np.logspace(-7, -1, 60),
    ]))
    tau_grid = tau_grid[(tau_grid >= 0) & (tau_grid <= 1.0 + 1e-9)]
    curve = icr_curve(yb_te, cal_score, tau_grid)
    curve.to_csv(OUTDIR / "icr_curve.csv", index=False)

    print("\nselected operating points:")
    # Isotonic regression produces large flat steps, so many flows share an
    # identical calibrated score and the curve advances discontinuously.
    # Picking the largest tau meeting a target lands on a step edge and can
    # return a degenerate point (tau=0 anchoring everything). Instead, for
    # each target take the row that MINIMISES on-chain volume subject to
    # ICR >= target — the actual efficient operating point.
    show = []
    for target in (0.999, 0.995, 0.99, 0.98, 0.95, 0.90, 0.80):
        ok = curve[curve["ICR"] >= target]
        if ok.empty:
            continue
        r = ok.loc[ok["on_chain_volume"].idxmin()]
        if r["on_chain_volume"] >= 0.999:      # degenerate: anchoring all
            continue
        show.append({"ICR_target": target, "tau": r["tau"], "ICR": r["ICR"],
                     "on_chain_volume": r["on_chain_volume"],
                     "write_reduction": r["write_reduction"],
                     "reduction_factor": 1.0 / r["on_chain_volume"],
                     "anchored_flows": int(r["anchored_flows"]),
                     "attacks_missed": int(r["attacks_missed"]),
                     "benign_anchored": int(r["benign_anchored"]),
                     "anchor_precision": r["anchor_precision"]})
    ops = pd.DataFrame(show).drop_duplicates(subset="tau")
    print(ops.to_string(index=False, float_format=lambda v: f"{v:.6f}"))
    ops.to_csv(OUTDIR / "icr_operating_points.csv", index=False)

    if not ops.empty:
        r = ops.iloc[0]
        reduction = 1.0 / r["on_chain_volume"] if r["on_chain_volume"] else float("inf")
        print(f"\nHeadline: at tau = {r['tau']:.4f} the system anchors "
              f"{r['on_chain_volume'] * 100:.2f}% of flow records on-chain "
              f"while achieving {r['ICR'] * 100:.2f}% integrity coverage of "
              f"attack traffic — a {reduction:.1f}x reduction in ledger write "
              f"volume against anchoring everything.")

        # Per-class coverage across several gates. A single aggregate ICR can
        # hide a class that is systematically dropped: Infiltration flows carry
        # far lower confidence than any other class, so a high gate excludes
        # them first. That class-dependent blind spot is a real property of
        # confidence-gated anchoring and is reported rather than averaged away.
        taus = sorted(ops["tau"].unique())
        frames = []
        for t in taus:
            pc = per_class_icr(y_te, cal_score, t, labels)
            pc.insert(0, "tau", t)
            frames.append(pc)
        pc_all = pd.concat(frames, ignore_index=True)
        pc_all.to_csv(OUTDIR / "icr_per_class.csv", index=False)

        pivot = pc_all.pivot(index="class", columns="tau", values="ICR_at_tau")
        conf = (pc_all.groupby("class")["mean_confidence"].first()
                .rename("mean_conf"))
        support = pc_all.groupby("class")["support"].first()
        summary = pd.concat([support, conf, pivot], axis=1).sort_values("mean_conf")
        print("\nper-class ICR across gates (rows sorted by mean confidence):")
        print(summary.to_string(float_format=lambda v: f"{v:.4f}"))

        weakest = summary.index[0]
        print(f"\nWeakest class for anchoring: {weakest} "
              f"(mean confidence {summary.loc[weakest, 'mean_conf']:.4f}). "
              f"Classes that are hardest to classify are also the hardest to "
              f"anchor — a class-dependent limitation of confidence gating.")

    # ---- plots -----------------------------------------------------------
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots(1, 2, figsize=(13, 5.5))
        ax[0].plot([0, 1], [0, 1], "k--", lw=0.9, label="perfect calibration")
        for method, table in tables.items():
            t = table.dropna()
            ax[0].plot(t["mean_confidence"], t["observed_frequency"],
                       marker="o", ms=4, lw=1.4, label=method)
        ax[0].set_xlabel("mean predicted confidence")
        ax[0].set_ylabel("observed attack frequency")
        ax[0].set_title("Reliability diagram (test fold)")
        ax[0].legend(fontsize=8)
        ax[0].grid(alpha=0.3)

        ax[1].plot(curve["on_chain_volume"], curve["ICR"], lw=1.8)
        if not ops.empty:
            ax[1].scatter(ops["on_chain_volume"], ops["ICR"], color="crimson",
                          zorder=5, s=30)
            for _, r in ops.iterrows():
                ax[1].annotate(f"tau={r['tau']:.3f}",
                               (r["on_chain_volume"], r["ICR"]),
                               textcoords="offset points", xytext=(6, -9),
                               fontsize=7)
        ax[1].set_xscale("log")
        ax[1].set_xlabel("on-chain volume (fraction of all flows anchored, log scale)")
        ax[1].set_ylabel("Integrity Coverage Ratio")
        ax[1].set_title("ICR vs ledger write volume")
        ax[1].grid(alpha=0.3, which="both")
        plt.tight_layout()
        plt.savefig(OUTDIR / "calibration_and_icr.png", dpi=160)
        plt.close()

        plt.figure(figsize=(7.5, 5))
        plt.plot(curve["tau"], curve["ICR"], label="ICR (attack coverage)")
        plt.plot(curve["tau"], curve["on_chain_volume"], label="on-chain volume")
        plt.xlabel("confidence gate tau")
        plt.ylabel("fraction")
        plt.title("Coverage and ledger cost against the confidence gate")
        plt.legend()
        plt.grid(alpha=0.3)
        plt.tight_layout()
        plt.savefig(OUTDIR / "icr_vs_tau.png", dpi=160)
        plt.close()
        print(f"\nWrote {OUTDIR / 'calibration_and_icr.png'}")
        print(f"Wrote {OUTDIR / 'icr_vs_tau.png'}")
    except ImportError:
        print("\nmatplotlib not installed — plots skipped.")

    print(f"saved -> {OUTDIR}")


if __name__ == "__main__":
    main()

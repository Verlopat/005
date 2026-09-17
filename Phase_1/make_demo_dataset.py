"""
Write demo_dataset.csv: 25 real test-fold flows. Feature columns only, no
label of any kind, no identifiers — the file cannot leak the answer.

  python make_demo_dataset.py             realistic operational proportions (default)
  python make_demo_dataset.py --balanced  equal-ish class weighting instead

Ground truth for these same 25 rows goes to demo_answers.csv instead,
never into demo_dataset.csv.
"""

from __future__ import annotations

import argparse
import sys

import joblib
import pandas as pd

import config

MODEL_DIR = config.OUTPUTS_DIR / "09_model"
BUNDLE_PATH = MODEL_DIR / "detector_bundle.joblib"
DATASET_PATH = config.BASE_DIR / "demo_dataset.csv"
ANSWERS_PATH = config.BASE_DIR / "demo_answers.csv"

TOTAL_ROWS = 25
BENIGN_QUOTA = 3

# Approximate real operational mix (see CLAUDE.md's class-distribution
# table): Benign dominates, the rest fall off sharply toward the rarest
# classes. This is the default composition.
#
# The previous version (still available via --balanced) sampled classes
# equally, which over-represented Web Attacks by roughly 650x relative to
# its 0.018% share of the source capture, and Infiltration by about 100x.
# That made the sample far harder than real traffic and unrepresentative
# in the opposite direction from the natural prior.
REALISTIC_QUOTAS = {
    "Benign": 10,
    "DDoS": 4,
    "DoS": 3,
    "Bot": 3,
    "BruteForce": 3,
    "Infiltration": 1,
    "Web Attacks": 1,
}


def equal_quotas() -> dict[str, int]:
    attack_classes = [c for c in config.COARSE_CATEGORIES if c != "Benign"]
    remaining = TOTAL_ROWS - BENIGN_QUOTA

    base, extra = divmod(remaining, len(attack_classes))
    quotas = {"Benign": BENIGN_QUOTA}
    for i, cls in enumerate(attack_classes):
        quotas[cls] = base + (1 if i < extra else 0)
    return quotas


def apply_shortfall(quotas: dict[str, int], available: dict[str, int]) -> dict[str, int]:
    quotas = dict(quotas)
    attack_classes = [c for c in quotas if c != "Benign"]

    # Cap each class at what actually exists, pool the shortfall, and hand
    # it to attack classes with spare capacity (never to Benign — Benign's
    # quota is deliberate in both modes, not a place to dump overflow).
    pool = 0
    for cls, quota in quotas.items():
        have = available.get(cls, 0)
        if have < quota:
            pool += quota - have
            quotas[cls] = have

    while pool > 0:
        capacity = {c: available.get(c, 0) - quotas[c] for c in attack_classes if available.get(c, 0) > quotas[c]}
        if not capacity:
            break
        for cls in capacity:
            if pool == 0:
                break
            quotas[cls] += 1
            pool -= 1

    return quotas


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--balanced", action="store_true",
                         help="Equal-ish class weighting instead of realistic operational proportions.")
    args = parser.parse_args()

    if not BUNDLE_PATH.exists():
        print(f"Error: missing {BUNDLE_PATH}. Run 09_export_model.py first.")
        sys.exit(1)
    if not config.TEST_PARQUET.exists():
        print(f"Error: missing {config.TEST_PARQUET}. Run 02_prepare.py first.")
        sys.exit(1)

    bundle = joblib.load(BUNDLE_PATH)
    features = bundle["features"]
    label_col = config.COARSE_LABEL_COLUMN

    df = pd.read_parquet(config.TEST_PARQUET, columns=features + [label_col])
    available = df[label_col].value_counts().to_dict()
    base_quotas = equal_quotas() if args.balanced else REALISTIC_QUOTAS
    quotas = apply_shortfall(base_quotas, available)

    parts = []
    for cls, n in quotas.items():
        if n == 0:
            continue
        subset = df[df[label_col] == cls]
        parts.append(subset.sample(n=n, random_state=config.RANDOM_SEED))

    picked = pd.concat(parts, ignore_index=True)
    picked = picked.sample(frac=1, random_state=config.RANDOM_SEED).reset_index(drop=True)

    print("Class counts written:")
    for cls, count in picked[label_col].value_counts().reindex(config.COARSE_CATEGORIES, fill_value=0).items():
        if count:
            print(f"  {cls:<15} {count:>3,}")

    picked[features].to_csv(DATASET_PATH, index=False)
    print(f"\nWrote {DATASET_PATH} ({len(picked)} rows, {len(features)} feature columns, no label)")

    answers = pd.DataFrame({"row": range(1, len(picked) + 1), "true_class": picked[label_col]})
    answers.to_csv(ANSWERS_PATH, index=False)
    print(f"Wrote {ANSWERS_PATH}")


if __name__ == "__main__":
    main()

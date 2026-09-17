"""
Stage 03 — Single-feature artifact / leakage check.

For each feature, train a depth-1 decision stump on that feature ALONE and
measure macro-F1 on the validation fold. A feature that alone reaches
high macro-F1 is very likely a leak/artifact rather than a genuine signal
(e.g. destination port, which alone reaches 70-100% accuracy on these
datasets — see CLAUDE.md). Anything above config.ARTIFACT_F1_CUTOFF is
flagged.

By default, identifier columns (including L4_DST_PORT) are excluded from
the candidate pool, matching the pipeline's default of holding identifiers
out of the model entirely. Pass --with-dst-port to add the destination-port
column back in as a candidate, reproducing the inflated ablation number for
the writeup's ablation table.

Run: python 03_artifact_check.py [--with-dst-port]
"""

from __future__ import annotations

import argparse
import json
import sys

import pandas as pd
from sklearn.metrics import f1_score
from sklearn.tree import DecisionTreeClassifier

import config


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--with-dst-port",
        action="store_true",
        help="Include the destination-port identifier column as a candidate feature.",
    )
    args = parser.parse_args()

    report_path = config.ARTIFACT_REPORT_WITH_DST_PORT if args.with_dst_port else config.ARTIFACT_REPORT

    if not config.COLUMNS_JSON.exists() or not config.TRAIN_PARQUET.exists():
        print("Missing work/columns.json or work/splits/train.parquet.")
        print("Run 02_prepare.py first.")
        sys.exit(1)

    columns_payload = json.loads(config.COLUMNS_JSON.read_text(encoding="utf-8"))
    label_column = columns_payload["multiclass_label"] or columns_payload["binary_label"]
    candidate_features = list(columns_payload["features"])

    if args.with_dst_port:
        dst_port_col = config.find_dst_port_column(columns_payload["identifiers"])
        if dst_port_col:
            candidate_features.append(dst_port_col)
            print(f"--with-dst-port: adding {dst_port_col!r} to the candidate pool")
        else:
            print("--with-dst-port passed but no destination-port identifier column was found.")

    train_df = pd.read_parquet(config.TRAIN_PARQUET, columns=candidate_features + [label_column])
    val_df = pd.read_parquet(config.VAL_PARQUET, columns=candidate_features + [label_column])

    y_train = train_df[label_column]
    y_val = val_df[label_column]

    results = []
    for feature in candidate_features:
        X_train = train_df[[feature]]
        X_val = val_df[[feature]]

        clf = DecisionTreeClassifier(max_depth=1, random_state=config.RANDOM_SEED)
        clf.fit(X_train, y_train)
        preds = clf.predict(X_val)
        macro_f1 = f1_score(y_val, preds, average="macro", zero_division=0)

        results.append({
            "feature": feature,
            "solo_macro_f1": macro_f1,
            "flagged": macro_f1 > config.ARTIFACT_F1_CUTOFF,
        })
        print(f"  {feature:<35} solo macro-F1 = {macro_f1:.4f}", end="\r")

    print()

    results_df = pd.DataFrame(results).sort_values("solo_macro_f1", ascending=False)
    results_df.to_csv(report_path, index=False)

    flagged = results_df[results_df["flagged"]]
    print(f"\nWrote {report_path}")
    print(f"\nCutoff: solo macro-F1 > {config.ARTIFACT_F1_CUTOFF}")
    if flagged.empty:
        print("No features flagged as likely artifacts.")
    else:
        print(f"{len(flagged)} feature(s) flagged as likely artifacts:")
        for _, row in flagged.iterrows():
            print(f"  {row['feature']:<35} {row['solo_macro_f1']:.4f}")

    print(f"\nCheck {report_path} for the full ranking, then run:")
    print("Next: python 04_select_features.py")


if __name__ == "__main__":
    main()

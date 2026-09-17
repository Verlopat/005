"""
Stage 02 — Downsample, clean, and split the raw NetFlow CSV.

Steps, in order:
  1. Chunked read; per chunk keep every attack row + BENIGN_KEEP_FRACTION of
     benign rows (seeded), downcast each numeric column to the smallest
     dtype that safely holds its actual values (range-checked per column,
     not a blanket float64->float32 / int64->int32 cast — see
     downcast_frame()).
  2. Concatenate chunks in original row order (majority-class downsampling
     does not disturb capture order — attack rows and the benign sample are
     re-sorted back into their original position within each chunk).
  3. Set +/-Inf AND finite values beyond config.NUMERIC_OUTLIER_ABS_CUTOFF to
     NaN (both are exporter divide-by-near-zero artifacts, same root cause,
     same treatment), then median-fill per feature column.
  4. Deduplicate exact-duplicate rows.
  5. Split 60/20/20 STRICTLY BY ROW POSITION — no shuffling. See
     config.SPLIT_FRACTIONS and CLAUDE.md "splits follow capture order".
  6. Write work/splits/{train,val,test}.parquet and work/columns.json.

Run: python 02_prepare.py
"""

from __future__ import annotations

import json
import sys

import numpy as np
import pandas as pd

import config


def downcast_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Downcast numeric columns to the smallest dtype that safely holds
    their actual values.

    numpy's .astype(np.int32) does NOT check whether a value fits — it
    silently wraps out-of-range integers (e.g. a throughput column with
    values above INT32_MAX becomes a negative number) and only ever emits
    a RuntimeWarning, which is easy to miss. pd.to_numeric(downcast=...)
    checks each column's real min/max against the target dtype's range
    first and falls back to a wider dtype when a value doesn't fit, so no
    column name needs to be special-cased here.

    The int branch additionally verifies the downcast round-trips exactly
    and raises if it doesn't, turning any future silent-overflow regression
    into a hard failure instead of corrupted data that passes quietly.
    """
    float_cols = df.select_dtypes(include=["float64"]).columns
    int_cols = df.select_dtypes(include=["int64"]).columns

    for column in float_cols:
        df[column] = pd.to_numeric(df[column], downcast="float")

    for column in int_cols:
        original = df[column]
        downcasted = pd.to_numeric(original, downcast="integer")
        if not np.array_equal(downcasted.to_numpy(), original.to_numpy()):
            raise OverflowError(
                f"Downcasting {column!r} changed its values — refusing to silently "
                f"corrupt data. Column range: [{original.min()}, {original.max()}]."
            )
        df[column] = downcasted

    return df


def main() -> None:
    config.ensure_dirs()

    if not config.RAW_CSV.exists():
        print(f"Raw CSV not found at {config.RAW_CSV}")
        print("Place NF-CSE-CIC-IDS2018-v2.csv in data/ and re-run.")
        sys.exit(1)

    columns = pd.read_csv(config.RAW_CSV, nrows=0).columns.tolist()
    identifiers, labels, features = config.classify_columns(columns)
    binary_label = config.find_binary_label_column(labels)
    multiclass_label = config.find_multiclass_label_column(labels)
    mask_column = binary_label or multiclass_label

    if mask_column is None:
        print("No label column detected — cannot separate attack from benign rows.")
        sys.exit(1)

    print(f"Using {mask_column!r} to identify benign rows "
          f"(binary label: {binary_label!r}, multiclass label: {multiclass_label!r})")

    kept_chunks: list[pd.DataFrame] = []
    total_seen = 0

    chunk_iter = pd.read_csv(config.RAW_CSV, chunksize=config.CHUNKSIZE, low_memory=False)
    for chunk_idx, chunk in enumerate(chunk_iter):
        total_seen += len(chunk)

        if binary_label is not None:
            is_benign = chunk[binary_label] == 0
        else:
            is_benign = chunk[multiclass_label].astype(str).isin(config.BENIGN_LABEL_VALUES)

        attack_rows = chunk.loc[~is_benign]
        benign_rows = chunk.loc[is_benign].sample(
            frac=config.BENIGN_KEEP_FRACTION, random_state=config.RANDOM_SEED
        )

        combined = pd.concat([attack_rows, benign_rows]).sort_index()
        combined = downcast_frame(combined)
        kept_chunks.append(combined)

        print(f"  chunk {chunk_idx + 1}: {total_seen:,} rows read, "
              f"{sum(len(c) for c in kept_chunks):,} kept so far", end="\r")

    print()

    df = pd.concat(kept_chunks, ignore_index=True)
    del kept_chunks
    print(f"After downsampling: {len(df):,} rows (from {total_seen:,} raw rows)")

    if multiclass_label is not None:
        df[config.COARSE_LABEL_COLUMN] = config.map_to_coarse_category(df[multiclass_label])
        print(f"Mapped {multiclass_label!r} (fine-grained, {df[multiclass_label].nunique()} values) "
              f"-> {config.COARSE_LABEL_COLUMN!r} (coarse, {df[config.COARSE_LABEL_COLUMN].nunique()} values). "
              f"{multiclass_label!r} is kept as-is for per-variant breakdown later.")

    feature_cols = [c for c in features if c in df.columns]
    numeric_feature_cols = df[feature_cols].select_dtypes(include=[np.number]).columns.tolist()

    numeric_block = df[numeric_feature_cols]
    out_of_range_mask = numeric_block.abs() > config.NUMERIC_OUTLIER_ABS_CUTOFF
    out_of_range_count = int(out_of_range_mask.to_numpy().sum())
    df[numeric_feature_cols] = numeric_block.mask(out_of_range_mask, np.nan)
    medians = df[numeric_feature_cols].median()
    df[numeric_feature_cols] = df[numeric_feature_cols].fillna(medians)
    print(f"Set {out_of_range_count:,} values exceeding the "
          f"{config.NUMERIC_OUTLIER_ABS_CUTOFF:.0e} magnitude cutoff (this also catches all "
          f"+/-Inf, since Inf exceeds any finite cutoff) to NaN, then median-filled all NaN "
          f"in numeric feature columns.")

    before_dedup = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    print(f"Deduplicated: {before_dedup:,} -> {len(df):,} rows "
          f"({before_dedup - len(df):,} duplicates dropped)")

    n = len(df)
    train_frac, val_frac, _ = config.SPLIT_FRACTIONS
    train_end = int(n * train_frac)
    val_end = train_end + int(n * val_frac)

    train_df = df.iloc[:train_end]
    val_df = df.iloc[train_end:val_end]
    test_df = df.iloc[val_end:]

    train_df.to_parquet(config.TRAIN_PARQUET, index=False)
    val_df.to_parquet(config.VAL_PARQUET, index=False)
    test_df.to_parquet(config.TEST_PARQUET, index=False)

    columns_payload = {
        "identifiers": identifiers,
        "labels": labels,
        "binary_label": binary_label,
        "multiclass_label": config.COARSE_LABEL_COLUMN if multiclass_label else None,
        "fine_grained_label": multiclass_label,
        "features": feature_cols,
    }
    config.COLUMNS_JSON.write_text(json.dumps(columns_payload, indent=2), encoding="utf-8")

    print(f"\nWrote {config.TRAIN_PARQUET} ({len(train_df):,} rows)")
    print(f"Wrote {config.VAL_PARQUET} ({len(val_df):,} rows)")
    print(f"Wrote {config.TEST_PARQUET} ({len(test_df):,} rows)")
    print(f"Wrote {config.COLUMNS_JSON}")

    coarse_label = columns_payload["multiclass_label"]
    label_for_counts = coarse_label or binary_label
    print(f"\nClass counts per split (label column: {label_for_counts!r}):")
    for name, split_df in (("train", train_df), ("val", val_df), ("test", test_df)):
        counts = split_df[label_for_counts].value_counts().sort_index()
        print(f"  {name}:")
        for value, count in counts.items():
            print(f"    {value!s:<15} {count:>10,}")

    if multiclass_label is not None:
        print(f"\nFine-grained class counts per split (label column: {multiclass_label!r}), "
              f"to catch a subtype vanishing even when its coarse category survives:")
        for name, split_df in (("train", train_df), ("val", val_df), ("test", test_df)):
            counts = split_df[multiclass_label].value_counts().sort_index()
            print(f"  {name}:")
            for value, count in counts.items():
                print(f"    {value!s:<28} {count:>10,}")

    print("\nConfirm no class vanished from val/test above, then run:")
    print("Next: python 03_artifact_check.py")


if __name__ == "__main__":
    main()

"""
Stage 01 — Inspect the raw NetFlow CSV.

Read-only: never writes to data/, never modifies the source CSV. Streams it
in chunks (config.CHUNKSIZE) so it works on a laptop with 18.9M rows.

Reports, to outputs/01_inspection.txt:
  - column classification (identifiers / labels / features)
  - whether a flow start-time column exists (decides whether a true
    time-ordered split is possible, or row order is the best proxy we have)
  - full class distribution with ratios vs benign
  - per-column NaN and Inf counts
  - duplicate row count (hash-based, exact for non-colliding hashes)
  - zero-variance columns

Run: python 01_inspect.py
"""

from __future__ import annotations

import sys

import numpy as np
import pandas as pd

import config


def main() -> None:
    config.ensure_dirs()

    if not config.RAW_CSV.exists():
        print(f"Raw CSV not found at {config.RAW_CSV}")
        print("Place NF-CSE-CIC-IDS2018-v2.csv in data/ and re-run.")
        sys.exit(1)

    columns = pd.read_csv(config.RAW_CSV, nrows=0).columns.tolist()
    identifiers, labels, features = config.classify_columns(columns)
    timestamp_columns = config.find_timestamp_columns(columns)
    label_column = config.find_multiclass_label_column(labels)

    print(f"Columns: {len(columns)} total "
          f"({len(identifiers)} identifiers, {len(labels)} labels, {len(features)} features)")
    print(f"Multiclass label column detected: {label_column!r}")
    print(f"Timestamp column(s) detected: {timestamp_columns or 'NONE'}")

    total_rows = 0
    class_counts: dict[str, int] = {}
    nan_counts = pd.Series(0, index=columns, dtype=np.int64)
    inf_counts = pd.Series(0, index=columns, dtype=np.int64)
    col_min: dict[str, float] = {}
    col_max: dict[str, float] = {}
    hash_chunks: list[np.ndarray] = []

    chunk_iter = pd.read_csv(config.RAW_CSV, chunksize=config.CHUNKSIZE, low_memory=False)
    for chunk_idx, chunk in enumerate(chunk_iter):
        total_rows += len(chunk)

        if label_column is not None:
            counts = chunk[label_column].value_counts()
            for value, count in counts.items():
                class_counts[value] = class_counts.get(value, 0) + int(count)

        nan_counts += chunk.isna().sum()

        numeric_chunk = chunk.select_dtypes(include=[np.number])
        inf_mask = np.isinf(numeric_chunk.to_numpy(dtype=np.float64, na_value=0.0))
        inf_counts[numeric_chunk.columns] += inf_mask.sum(axis=0)

        for column in numeric_chunk.columns:
            series = numeric_chunk[column]
            finite = series[np.isfinite(series)]
            if finite.empty:
                continue
            local_min, local_max = float(finite.min()), float(finite.max())
            col_min[column] = min(col_min.get(column, local_min), local_min)
            col_max[column] = max(col_max.get(column, local_max), local_max)

        row_hashes = pd.util.hash_pandas_object(chunk, index=False).to_numpy()
        hash_chunks.append(row_hashes)

        print(f"  chunk {chunk_idx + 1}: {total_rows:,} rows read so far", end="\r")

    print()

    all_hashes = np.concatenate(hash_chunks) if hash_chunks else np.array([], dtype=np.uint64)
    unique_hashes = np.unique(all_hashes).size
    duplicate_count = total_rows - unique_hashes

    zero_variance = [c for c in col_min if col_min[c] == col_max.get(c)]

    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("01_inspect.py — raw data inspection report")
    lines.append(f"Source: {config.RAW_CSV}")
    lines.append(f"Total rows: {total_rows:,}")
    lines.append("=" * 70)

    lines.append("")
    lines.append(f"COLUMN CLASSIFICATION ({len(columns)} total)")
    lines.append(f"  Identifiers ({len(identifiers)}): {identifiers}")
    lines.append(f"  Labels ({len(labels)}): {labels}")
    lines.append(f"  Features ({len(features)}): {features}")

    lines.append("")
    lines.append("TIMESTAMP / CAPTURE ORDER")
    if timestamp_columns:
        lines.append(f"  Found: {timestamp_columns} — a true time-ordered split is possible.")
    else:
        lines.append("  None found — row order in the CSV is the best available proxy for "
                      "capture order. 02_prepare.py splits by row position, not by shuffling.")

    lines.append("")
    lines.append(f"CLASS DISTRIBUTION (label column: {label_column!r})")
    if class_counts:
        benign_count = next(
            (count for value, count in class_counts.items()
             if str(value) in config.BENIGN_LABEL_VALUES),
            None,
        )
        for value, count in sorted(class_counts.items(), key=lambda kv: -kv[1]):
            ratio = f"1:{benign_count / count:,.1f}" if benign_count and count else "n/a"
            lines.append(f"  {value!s:<15} {count:>12,}   ratio vs benign = {ratio}")
    else:
        lines.append("  No label column detected.")

    lines.append("")
    lines.append("NaN COUNTS (columns with > 0 only)")
    nonzero_nan = nan_counts[nan_counts > 0]
    if nonzero_nan.empty:
        lines.append("  None.")
    else:
        for column, count in nonzero_nan.sort_values(ascending=False).items():
            lines.append(f"  {column:<30} {count:>12,}")

    lines.append("")
    lines.append("Inf COUNTS (columns with > 0 only)")
    nonzero_inf = inf_counts[inf_counts > 0]
    if nonzero_inf.empty:
        lines.append("  None.")
    else:
        for column, count in nonzero_inf.sort_values(ascending=False).items():
            lines.append(f"  {column:<30} {count:>12,}")

    lines.append("")
    lines.append(f"DUPLICATE ROWS (hash-based, {config.CHUNKSIZE:,}-row chunks): {duplicate_count:,}")

    lines.append("")
    lines.append(f"ZERO-VARIANCE COLUMNS ({len(zero_variance)})")
    lines.append(f"  {zero_variance if zero_variance else 'None.'}")

    lines.append("")
    lines.append("=" * 70)

    config.INSPECTION_REPORT.write_text("\n".join(lines), encoding="utf-8")

    print(f"\nWrote {config.INSPECTION_REPORT}")
    print("Before running 02_prepare.py, check:")
    print("  - does every expected class appear in CLASS DISTRIBUTION?")
    print("  - is there a timestamp column, or are we relying on row order?")
    print("  - any zero-variance columns or heavy NaN/Inf columns to be aware of?")
    print("\nNext: python 02_prepare.py")


if __name__ == "__main__":
    main()

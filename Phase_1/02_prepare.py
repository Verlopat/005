"""
Stage 02 — Split, downsample, clean, and write the NetFlow splits.

ORDER OF OPERATIONS (changed from the original, deliberately):

  The original downsampled benign traffic to BENIGN_KEEP_FRACTION *before*
  splitting, so val and test inherited an artificial class prior ~11x
  benign-poor. Every precision / false-positive number measured on them
  described traffic that does not exist in deployment.

  Now: dedup -> split by row position -> downsample benign in TRAIN ONLY.
  Val and test carry the natural capture prior. Training keeps the
  rebalanced prior on purpose: it is a modelling choice that helps the rare
  classes, and it is stated as such rather than leaking into evaluation.

  Median imputation values are also now fitted on the train fold alone and
  applied to val/test, instead of being computed over all rows including
  test.

Because val/test are now ~5x larger, the whole file no longer fits in
memory at once. Two passes over the CSV:

  PASS 1  hash every row (global dedup, keep-first), record the benign
          mask, and record per-column min/max after outlier masking so a
          single safe dtype can be chosen for every split.
  PASS 2  train rows accumulate in memory (small, post-downsample), then
          medians are fitted on them; val/test stream straight to parquet
          using those medians and the pass-1 dtype schema.

Splits remain STRICTLY BY ROW POSITION — no shuffling. Since train is the
first 60% of surviving rows, the whole train fold is seen before any val
row, which is what makes the single streaming pass possible.

Run: python 02_prepare.py
"""

from __future__ import annotations

import json
import sys

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

import config


# ---------------------------------------------------------------------------
# dtype selection
# ---------------------------------------------------------------------------
def choose_int_dtype(col_min: float, col_max: float) -> np.dtype:
    """Smallest signed integer dtype that provably holds [col_min, col_max].

    Chosen from the whole file's observed range in pass 1, so no chunk can
    later contain a value that silently wraps — the failure mode that
    produced the negative-throughput bug in the raw exporter output.
    """
    for candidate in (np.int8, np.int16, np.int32, np.int64):
        info = np.iinfo(candidate)
        if col_min >= info.min and col_max <= info.max:
            return np.dtype(candidate)
    return np.dtype(np.int64)


def choose_float_dtype(abs_max: float) -> np.dtype:
    return np.dtype(np.float32) if abs_max <= np.finfo(np.float32).max else np.dtype(np.float64)


def mask_outliers(frame: pd.DataFrame, numeric_feature_cols: list[str]) -> tuple[pd.DataFrame, int]:
    """Set +/-Inf and finite values beyond the magnitude cutoff to NaN.

    Both are exporter divide-by-near-zero artifacts with the same root
    cause; Inf is caught automatically since it exceeds any finite cutoff.
    """
    block = frame[numeric_feature_cols]
    mask = block.abs() > config.NUMERIC_OUTLIER_ABS_CUTOFF
    count = int(mask.to_numpy().sum())
    frame = frame.copy()
    frame[numeric_feature_cols] = block.mask(mask, np.nan)
    return frame, count


# ---------------------------------------------------------------------------
# PASS 1
# ---------------------------------------------------------------------------
def pass_one(binary_label, multiclass_label, numeric_feature_cols):
    """Scan the whole CSV once. Returns row hashes, benign mask, and the
    per-column min/max needed to pick a file-wide safe dtype."""
    hashes: list[np.ndarray] = []
    benign_flags: list[np.ndarray] = []
    col_min: dict[str, float] = {}
    col_max: dict[str, float] = {}
    total = 0

    reader = pd.read_csv(config.RAW_CSV, chunksize=config.CHUNKSIZE, low_memory=False)
    for index, chunk in enumerate(reader):
        total += len(chunk)

        # Hash the raw row, before any cleaning. Median-filling can make two
        # genuinely different source rows identical; those are not duplicates
        # and must not be dropped.
        hashes.append(pd.util.hash_pandas_object(chunk, index=False).to_numpy())

        if binary_label is not None:
            is_benign = (chunk[binary_label] == 0).to_numpy()
        else:
            is_benign = chunk[multiclass_label].astype(str).isin(
                config.BENIGN_LABEL_VALUES).to_numpy()
        benign_flags.append(is_benign)

        masked, _ = mask_outliers(chunk, numeric_feature_cols)
        for column in chunk.select_dtypes(include=[np.number]).columns:
            series = masked[column] if column in numeric_feature_cols else chunk[column]
            low, high = series.min(), series.max()
            if pd.notna(low):
                col_min[column] = min(col_min.get(column, low), low)
            if pd.notna(high):
                col_max[column] = max(col_max.get(column, high), high)

        print(f"  pass 1: {total:,} rows scanned", end="\r")

    print()
    return (np.concatenate(hashes), np.concatenate(benign_flags),
            col_min, col_max, total)


def build_row_plan(row_hashes, is_benign, total):
    """Decide, for every raw row, which split it belongs to (or that it is
    dropped). Returns an int8 array: -1 dropped, 0 train, 1 val, 2 test."""
    # keep-first deduplication
    _, first_occurrence = np.unique(row_hashes, return_index=True)
    keep = np.zeros(total, dtype=bool)
    keep[first_occurrence] = True
    n_kept = int(keep.sum())
    print(f"Deduplicated: {total:,} -> {n_kept:,} rows "
          f"({total - n_kept:,} duplicates dropped)")

    train_frac, val_frac, _ = config.SPLIT_FRACTIONS
    train_end = int(n_kept * train_frac)
    val_end = train_end + int(n_kept * val_frac)

    plan = np.full(total, -1, dtype=np.int8)
    kept_positions = np.flatnonzero(keep)
    plan[kept_positions[:train_end]] = 0
    plan[kept_positions[train_end:val_end]] = 1
    plan[kept_positions[val_end:]] = 2

    # benign downsampling, TRAIN ONLY
    train_benign = np.flatnonzero((plan == 0) & is_benign)
    rng = np.random.default_rng(config.RANDOM_SEED)
    n_keep_benign = int(round(len(train_benign) * config.BENIGN_KEEP_FRACTION))
    drop = rng.choice(train_benign, size=len(train_benign) - n_keep_benign, replace=False)
    plan[drop] = -1

    print(f"Train benign downsampled to {config.BENIGN_KEEP_FRACTION:.2f}: "
          f"{len(train_benign):,} -> {n_keep_benign:,}")
    print(f"Split sizes — train {int((plan == 0).sum()):,} | "
          f"val {int((plan == 1).sum()):,} | test {int((plan == 2).sum()):,}")
    print("Val and test retain the natural capture prior (no downsampling).")
    return plan


# ---------------------------------------------------------------------------
# PASS 2
# ---------------------------------------------------------------------------
def cast_to_schema(frame: pd.DataFrame, target: dict[str, np.dtype]) -> pd.DataFrame:
    for column, dtype in target.items():
        if column not in frame.columns:
            continue
        if np.issubdtype(dtype, np.integer):
            original = frame[column]
            converted = original.astype(dtype)
            if not np.array_equal(converted.to_numpy(), original.to_numpy()):
                raise OverflowError(
                    f"Casting {column!r} to {dtype} changed its values — refusing to "
                    f"silently corrupt data."
                )
            frame[column] = converted
        else:
            frame[column] = frame[column].astype(dtype)
    return frame


def main() -> None:
    config.ensure_dirs()

    if not config.RAW_CSV.exists():
        print(f"Raw CSV not found at {config.RAW_CSV}")
        sys.exit(1)

    columns = pd.read_csv(config.RAW_CSV, nrows=0).columns.tolist()
    identifiers, labels, features = config.classify_columns(columns)
    binary_label = config.find_binary_label_column(labels)
    multiclass_label = config.find_multiclass_label_column(labels)

    if binary_label is None and multiclass_label is None:
        print("No label column detected.")
        sys.exit(1)

    probe = pd.read_csv(config.RAW_CSV, nrows=50_000, low_memory=False)
    feature_cols = [c for c in features if c in probe.columns]
    numeric_feature_cols = probe[feature_cols].select_dtypes(
        include=[np.number]).columns.tolist()

    print(f"Benign identified via {binary_label or multiclass_label!r}")
    print(f"{len(feature_cols)} feature columns, {len(numeric_feature_cols)} numeric\n")

    row_hashes, is_benign, col_min, col_max, total = pass_one(
        binary_label, multiclass_label, numeric_feature_cols)
    print(f"Raw rows: {total:,}  ({int(is_benign.sum()):,} benign, "
          f"{int((~is_benign).sum()):,} attack)")

    plan = build_row_plan(row_hashes, is_benign, total)
    del row_hashes, is_benign

    # file-wide safe dtype per numeric column
    target_dtypes: dict[str, np.dtype] = {}
    for column in col_min:
        if pd.api.types.is_integer_dtype(probe[column]):
            target_dtypes[column] = choose_int_dtype(col_min[column], col_max[column])
        else:
            target_dtypes[column] = choose_float_dtype(
                max(abs(col_min[column]), abs(col_max[column])))
    del probe

    # ---- pass 2 --------------------------------------------------------
    train_parts: list[pd.DataFrame] = []
    writers: dict[int, pq.ParquetWriter] = {}
    paths = {1: config.VAL_PARQUET, 2: config.TEST_PARQUET}
    counts: dict[int, list[pd.Series]] = {0: [], 1: [], 2: []}
    fine_counts: dict[int, list[pd.Series]] = {0: [], 1: [], 2: []}
    medians: pd.Series | None = None
    outliers_total = 0
    offset = 0

    reader = pd.read_csv(config.RAW_CSV, chunksize=config.CHUNKSIZE, low_memory=False)
    for chunk in reader:
        chunk_plan = plan[offset:offset + len(chunk)]
        offset += len(chunk)
        chunk = chunk.reset_index(drop=True)

        chunk, n_out = mask_outliers(chunk, numeric_feature_cols)
        outliers_total += n_out
        if multiclass_label is not None:
            chunk[config.COARSE_LABEL_COLUMN] = config.map_to_coarse_category(
                chunk[multiclass_label])

        # train rows accumulate; medians cannot be fitted until the fold ends
        train_rows = chunk.loc[chunk_plan == 0]
        if len(train_rows):
            train_parts.append(train_rows)

        for split_id in (1, 2):
            rows = chunk.loc[chunk_plan == split_id]
            if not len(rows):
                continue

            if medians is None:
                # first val row reached => train fold is complete
                train_df = pd.concat(train_parts, ignore_index=True)
                train_parts = []
                medians = train_df[numeric_feature_cols].median()
                train_df[numeric_feature_cols] = train_df[numeric_feature_cols].fillna(medians)
                train_df = cast_to_schema(train_df, target_dtypes)
                train_df.to_parquet(config.TRAIN_PARQUET, index=False)
                counts[0].append(train_df[config.COARSE_LABEL_COLUMN].value_counts())
                if multiclass_label:
                    fine_counts[0].append(train_df[multiclass_label].value_counts())
                print(f"\nFitted medians on the train fold ({len(train_df):,} rows) "
                      f"and wrote {config.TRAIN_PARQUET}")
                del train_df

            rows = rows.copy()
            rows[numeric_feature_cols] = rows[numeric_feature_cols].fillna(medians)
            rows = cast_to_schema(rows, target_dtypes)
            counts[split_id].append(rows[config.COARSE_LABEL_COLUMN].value_counts())
            if multiclass_label:
                fine_counts[split_id].append(rows[multiclass_label].value_counts())

            table = pa.Table.from_pandas(rows, preserve_index=False)
            if split_id not in writers:
                writers[split_id] = pq.ParquetWriter(paths[split_id], table.schema)
            writers[split_id].write_table(table)

        print(f"  pass 2: {offset:,} rows processed", end="\r")

    print()
    for writer in writers.values():
        writer.close()

    print(f"Masked {outliers_total:,} values beyond "
          f"{config.NUMERIC_OUTLIER_ABS_CUTOFF:.0e} (includes all +/-Inf), "
          f"then filled with TRAIN-fold medians.")

    columns_payload = {
        "identifiers": identifiers,
        "labels": labels,
        "binary_label": binary_label,
        "multiclass_label": config.COARSE_LABEL_COLUMN if multiclass_label else None,
        "fine_grained_label": multiclass_label,
        "features": feature_cols,
        "benign_downsampled_in": "train_only",
        "benign_keep_fraction": config.BENIGN_KEEP_FRACTION,
        "median_fit_fold": "train",
    }
    config.COLUMNS_JSON.write_text(json.dumps(columns_payload, indent=2), encoding="utf-8")

    print(f"\nWrote {config.TRAIN_PARQUET}")
    print(f"Wrote {config.VAL_PARQUET}")
    print(f"Wrote {config.TEST_PARQUET}")
    print(f"Wrote {config.COLUMNS_JSON}")

    def show(title, store):
        print(f"\n{title}")
        for split_id, name in ((0, "train"), (1, "val"), (2, "test")):
            if not store[split_id]:
                continue
            merged = pd.concat(store[split_id]).groupby(level=0).sum().sort_index()
            print(f"  {name}:")
            for value, count in merged.items():
                print(f"    {value!s:<28} {count:>12,}")

    show(f"Class counts per split ({config.COARSE_LABEL_COLUMN!r}):", counts)
    if multiclass_label:
        show(f"Fine-grained counts per split ({multiclass_label!r}):", fine_counts)

    print("\nConfirm no class vanished from val/test above, then run:")
    print("Next: python 03_artifact_check.py")


if __name__ == "__main__":
    main()

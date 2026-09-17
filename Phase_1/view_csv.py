"""
Terminal CSV viewer for files too large or too wide for Excel/Sheets.

  python view_csv.py file.csv
  python view_csv.py file.csv --rows 50
  python view_csv.py file.csv --cols OUT_BYTES,PROTOCOL
  python view_csv.py file.csv --info
  python view_csv.py file.csv --tail
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

import pandas as pd

CELL_WIDTH = 18
ROW_COL_WIDTH = 10


def fast_row_count(path: Path) -> int:
    with open(path, "rb") as fh:
        lines = sum(chunk.count(b"\n") for chunk in iter(lambda: fh.read(1 << 20), b""))
    return max(lines - 1, 0)  # minus the header line


def get_header(path: Path) -> list[str]:
    return pd.read_csv(path, nrows=0).columns.tolist()


def resolve_columns(requested: str, header: list[str]) -> tuple[list[str], list[str]]:
    norm = {c.strip().lower(): c for c in header}
    matched, missing = [], []
    for name in requested.split(","):
        real = norm.get(name.strip().lower())
        (matched if real else missing).append(real or name.strip())
    return matched, missing


def truncate(value, width: int = CELL_WIDTH) -> str:
    text = "" if pd.isna(value) else str(value)
    return text if len(text) <= width else text[: width - 3] + "..."


def print_table(df: pd.DataFrame, row_numbers: range) -> None:
    term_width = shutil.get_terminal_size(fallback=(100, 24)).columns

    # The row-number label must not collide with a real column name (e.g.
    # predict_csv.py's own output CSVs have a column literally called "row").
    row_label = "row"
    while row_label in df.columns:
        row_label = "#" + row_label

    col_widths = {}
    for col in df.columns:
        cells = [truncate(v) for v in df[col]]
        col_widths[col] = max(len(str(col)), max((len(c) for c in cells), default=0))

    groups: list[list[str]] = []
    current: list[str] = []
    current_width = ROW_COL_WIDTH
    for col in df.columns:
        w = col_widths[col] + 2
        if current and current_width + w > term_width:
            groups.append(current)
            current, current_width = [], ROW_COL_WIDTH
        current.append(col)
        current_width += w
    if current:
        groups.append(current)

    for group_idx, group in enumerate(groups):
        if len(groups) > 1:
            print(f"\n-- columns {group_idx + 1}/{len(groups)} " + "-" * 40)
        header = row_label.ljust(ROW_COL_WIDTH) + "".join(
            str(c).ljust(col_widths[c] + 2) for c in group
        )
        print(header)
        for row_num, (_, row) in zip(row_numbers, df.iterrows()):
            line = str(row_num).ljust(ROW_COL_WIDTH) + "".join(
                truncate(row[c]).ljust(col_widths[c] + 2) for c in group
            )
            print(line)


def print_info(df: pd.DataFrame) -> None:
    print(f"{'column':<30}{'dtype':<12}{'nulls':<10}{'distinct':<10}{'min':<15}{'max':<15}")
    for col in df.columns:
        series = df[col]
        nulls = int(series.isna().sum())
        distinct = int(series.nunique())
        if pd.api.types.is_numeric_dtype(series):
            mn = series.min(skipna=True)
            mx = series.max(skipna=True)
            mn_s = "" if pd.isna(mn) else f"{mn:g}"
            mx_s = "" if pd.isna(mx) else f"{mx:g}"
        else:
            mn_s = mx_s = ""
        print(f"{str(col):<30}{str(series.dtype):<12}{nulls:<10}{distinct:<10}{mn_s:<15}{mx_s:<15}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("file_csv")
    parser.add_argument("--rows", type=int, default=20)
    parser.add_argument("--cols", default=None)
    parser.add_argument("--info", action="store_true")
    parser.add_argument("--tail", action="store_true")
    args = parser.parse_args()

    path = Path(args.file_csv)
    if not path.exists():
        print(f"Error: file not found: {path}")
        sys.exit(1)

    try:
        header = get_header(path)

        total_rows = fast_row_count(path)
        print(f"{total_rows:,} row(s), {len(header):,} column(s)\n")

        usecols = None
        if args.cols:
            matched, missing = resolve_columns(args.cols, header)
            if missing:
                print(f"Column(s) not found, skipping: {missing}")
            if not matched:
                print("Error: none of the requested columns were found.")
                sys.exit(1)
            usecols = matched

        if args.info:
            print("Reading the full file for --info ...")
            df = pd.read_csv(path, usecols=usecols)
            print_info(df)
            return

        if args.tail:
            print("Reading the full file for --tail ...")
            df = pd.read_csv(path, usecols=usecols)
            df = df.tail(args.rows).reset_index(drop=True)
            row_numbers = range(total_rows - len(df) + 1, total_rows + 1)
        else:
            df = pd.read_csv(path, usecols=usecols, nrows=args.rows)
            row_numbers = range(1, len(df) + 1)
    except pd.errors.EmptyDataError:
        print(f"Error: file is empty: {path}")
        sys.exit(1)
    except (pd.errors.ParserError, UnicodeDecodeError) as e:
        print(f"Error: could not parse {path} as CSV: {e}")
        sys.exit(1)

    print_table(df, row_numbers)


if __name__ == "__main__":
    main()

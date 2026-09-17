"""
Single source of truth for paths, thresholds, and column-classification
rules used by every pipeline stage script (01_*.py .. 04_*.py).

Nothing in the stage scripts should hardcode a path, fraction, or column
name pattern — it belongs here so the whole pipeline stays auditable from
one file.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
WORK_DIR = BASE_DIR / "work"
OUTPUTS_DIR = BASE_DIR / "outputs"
SPLITS_DIR = WORK_DIR / "splits"

RAW_CSV = DATA_DIR / "NF-CSE-CIC-IDS2018-v2.csv"
COLUMNS_JSON = WORK_DIR / "columns.json"

TRAIN_PARQUET = SPLITS_DIR / "train.parquet"
VAL_PARQUET = SPLITS_DIR / "val.parquet"
TEST_PARQUET = SPLITS_DIR / "test.parquet"

INSPECTION_REPORT = OUTPUTS_DIR / "01_inspection.txt"
ARTIFACT_REPORT = OUTPUTS_DIR / "03_artifacts.csv"
ARTIFACT_REPORT_WITH_DST_PORT = OUTPUTS_DIR / "03_artifacts_with_dst_port.csv"
SELECTED_FEATURES_JSON = OUTPUTS_DIR / "selected_features.json"
LGBM_IMPORTANCE_CSV = OUTPUTS_DIR / "lgbm_importance.csv"
PERMUTATION_IMPORTANCE_CSV = OUTPUTS_DIR / "permutation_importance.csv"

# ---------------------------------------------------------------------------
# Column classification — matched case-insensitively as substrings against
# raw column names, so minor header variations (e.g. "IPV4_SRC_ADDR" vs
# "ipv4_src_addr" vs "Ipv4SrcAddr") still classify correctly.
# ---------------------------------------------------------------------------

# Never allowed to reach the model. Travel alongside the feature vector as
# alert metadata instead (see CLAUDE.md "the rule that matters most").
IDENTIFIER_PATTERNS = [
    "ipv4_src_addr",
    "ipv4_dst_addr",
    "ipv6_src_addr",
    "ipv6_dst_addr",
    "l4_src_port",
    "l4_dst_port",
    "src_ip",
    "dst_ip",
]

# The single pattern within IDENTIFIER_PATTERNS that is the destination-port
# column, used by 03_artifact_check.py's --with-dst-port ablation flag.
DST_PORT_PATTERN = "l4_dst_port"

# Label / target columns (dataset ships both a binary "Label" and a
# multiclass "Attack" column). Both are excluded from features.
LABEL_COLUMN_PATTERNS = [
    "label",
    "attack",
]

# Used only to decide whether a true time-ordered split is possible, or
# whether row order in the CSV is the best available proxy for capture
# order. Not treated as a feature or an identifier.
TIMESTAMP_COLUMN_PATTERNS = [
    "flow_start",
    "flow_end",
    "first_switched",
    "last_switched",
    "timestamp",
]

# Raw string values in the multiclass label column that mean "benign".
BENIGN_LABEL_VALUES = ["Benign", "BENIGN", "benign"]

# ---------------------------------------------------------------------------
# Fine-grained -> coarse threat category mapping.
#
# The raw "Attack" column has 15 fine-grained values; the alert contract's
# threat_class and CLAUDE.md's class-distribution table both operate on the
# 7 coarse categories below. This is the ONLY place that mapping is defined.
# Every raw value the dataset can produce must be listed here explicitly —
# map_to_coarse_category() raises on anything unmapped rather than letting
# it silently become NaN.
#
# NOTE: "Brute Force -Web" and "Brute Force -XSS" map to "Web Attacks", NOT
# "BruteForce" — they're web-application attacks (name collision with the
# SSH/FTP credential-brute-force category is a dataset-naming artifact).
# ---------------------------------------------------------------------------
COARSE_LABEL_COLUMN = "THREAT_CATEGORY"

ATTACK_MAP: dict[str, str] = {
    "Benign": "Benign",
    "DDOS attack-HOIC": "DDoS",
    "DDoS attacks-LOIC-HTTP": "DDoS",
    "DDOS attack-LOIC-UDP": "DDoS",
    "DoS attacks-Hulk": "DoS",
    "DoS attacks-GoldenEye": "DoS",
    "DoS attacks-SlowHTTPTest": "DoS",
    "DoS attacks-Slowloris": "DoS",
    "Bot": "Bot",
    "Infilteration": "Infiltration",
    "SSH-Bruteforce": "BruteForce",
    "FTP-BruteForce": "BruteForce",
    "Brute Force -Web": "Web Attacks",
    "Brute Force -XSS": "Web Attacks",
    "SQL Injection": "Web Attacks",
}

COARSE_CATEGORIES = ["Benign", "DDoS", "DoS", "Bot", "BruteForce", "Infiltration", "Web Attacks"]

# ---------------------------------------------------------------------------
# Sampling / splitting / thresholds
# ---------------------------------------------------------------------------
BENIGN_KEEP_FRACTION = 0.09
CHUNKSIZE = 500_000
SPLIT_FRACTIONS = (0.60, 0.20, 0.20)  # train, val, test — must sum to 1.0
CORRELATION_CUTOFF = 0.95
ARTIFACT_F1_CUTOFF = 0.90
RANDOM_SEED = 42

# Magnitude cutoff for treating a finite numeric feature value as an exporter
# artifact rather than a real measurement. +/-Inf is always caught by this
# too (Inf's magnitude exceeds any finite cutoff), so this single threshold
# replaces separate Inf-only handling.
#
# Empirically chosen, not a physical bound: SRC_TO_DST_SECOND_BYTES and
# DST_TO_SRC_SECOND_BYTES (bytes/sec on very short flows — a divide-by-
# near-zero artifact in the flow exporter) are the only features anywhere
# near this range. Percentile analysis of the prepared splits found real
# values plateau by ~1.7e13 (DST_TO_SRC_SECOND_BYTES has a repeated exact
# value at 1.160712e+13 shared by ~5,888 rows — almost certainly the
# exporter's minimum-duration clamp, not blowup) while genuine artifacts
# start at 2.4e13+ and run up past 1e300. 2e13 sits in the gap between the
# two. Every other numeric feature column tops out under 5e9, so this cutoff
# does not affect them.
NUMERIC_OUTLIER_ABS_CUTOFF = 2e13

assert abs(sum(SPLIT_FRACTIONS) - 1.0) < 1e-9, "SPLIT_FRACTIONS must sum to 1.0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _matches_any(column: str, patterns: list[str]) -> bool:
    lowered = column.lower()
    return any(pattern in lowered for pattern in patterns)


def classify_columns(columns) -> tuple[list[str], list[str], list[str]]:
    """Split a list of raw column names into (identifiers, labels, features).

    Identifiers and labels are matched first (identifiers take priority in
    the unlikely case a column name matches both patterns); everything else
    is a feature.
    """
    identifiers, labels, features = [], [], []
    for column in columns:
        if _matches_any(column, IDENTIFIER_PATTERNS):
            identifiers.append(column)
        elif _matches_any(column, LABEL_COLUMN_PATTERNS):
            labels.append(column)
        else:
            features.append(column)
    return identifiers, labels, features


def find_timestamp_columns(columns) -> list[str]:
    """Columns that look like a flow start/end time, if any exist."""
    return [c for c in columns if _matches_any(c, TIMESTAMP_COLUMN_PATTERNS)]


def find_multiclass_label_column(labels: list[str]) -> str | None:
    """Of the detected label columns, return the multiclass one ("Attack"),
    preferring an exact case-insensitive match on "attack" over "label"."""
    for column in labels:
        if column.lower() == "attack":
            return column
    for column in labels:
        if "attack" in column.lower():
            return column
    return labels[0] if labels else None


def find_binary_label_column(labels: list[str]) -> str | None:
    """Of the detected label columns, return the binary one ("Label"),
    preferring an exact case-insensitive match over a substring match."""
    for column in labels:
        if column.lower() == "label":
            return column
    for column in labels:
        if "label" in column.lower():
            return column
    return None


def map_to_coarse_category(raw_attack_series):
    """Map raw fine-grained Attack values to the 7 coarse threat categories
    in ATTACK_MAP. Raises if any raw value isn't in the map, rather than
    letting an unmapped label silently become NaN."""
    unmapped = sorted(set(raw_attack_series.unique()) - set(ATTACK_MAP))
    assert not unmapped, f"Unmapped Attack value(s): {unmapped} — add to config.ATTACK_MAP"
    return raw_attack_series.map(ATTACK_MAP)


def find_dst_port_column(identifiers: list[str]) -> str | None:
    for column in identifiers:
        if DST_PORT_PATTERN in column.lower():
            return column
    return None


def ensure_dirs() -> None:
    """Create the working directories this pipeline writes to, if missing."""
    for directory in (DATA_DIR, WORK_DIR, SPLITS_DIR, OUTPUTS_DIR):
        directory.mkdir(parents=True, exist_ok=True)

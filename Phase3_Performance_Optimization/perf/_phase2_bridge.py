"""Shared sys.path bootstrap so Phase 3 modules can import Phase 2's
canonicalisation, signing, storage, ledger, and pipeline code.

Every other module in this package that needs Phase 2 functionality calls
`ensure_phase2_importable()` before importing anything from `src.*`. This
is centralised here rather than repeated per-module so there is exactly
one place that encodes the directory layout assumption
(`Phase3_Performance_Optimization/` and `Phase2_Blockchain_Logging/` are
sibling directories under the repository root).
"""
from __future__ import annotations

import sys
from pathlib import Path

PHASE3_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PHASE3_ROOT.parent
PHASE2_ROOT = REPO_ROOT / "Phase2_Blockchain_Logging"
#: The Phase 1 detection layer. Named `Phase_1` in this repository; an earlier
#: `Phase1_Submission` directory described a different detector (PyTorch binary
#: classifier on CICIoT2023) and no longer exists.
PHASE1_ROOT = REPO_ROOT / "Phase_1"


def ensure_phase2_importable() -> Path:
    """Insert Phase2_Blockchain_Logging onto sys.path (once) so that
    `from src.pipeline import Phase2Pipeline` etc. resolve to Phase 2's
    package, not this package's own `perf/`. Returns PHASE2_ROOT for
    convenience."""
    path_str = str(PHASE2_ROOT)
    if path_str not in sys.path:
        sys.path.insert(0, path_str)
    if not PHASE2_ROOT.is_dir():
        raise RuntimeError(
            f"Expected Phase2_Blockchain_Logging at {PHASE2_ROOT}, but it does not exist. "
            "Phase 3 depends on Phase 2's canonicalisation, signing, storage, and ledger code."
        )
    return PHASE2_ROOT

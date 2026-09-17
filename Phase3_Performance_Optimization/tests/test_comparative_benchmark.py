import pytest

from perf.comparative_benchmark import (
    SOURCES,
    format_table,
    literature_rows,
    protocol_notes,
    this_framework_row,
    this_framework_rows,
)

PHASE2_RESULTS = {
    "integrity": {"failure_rate_pct": 0.0},
    "storage": {"reduction_pct": 45.2, "on_chain_bytes_mean": 762},
    "benchmark": {"latency_ms_p95": 7.9},
}

# Phase 1's committed figures (outputs/07_metrics/metrics_table.csv,
# flat_tuned_tau / as_sampled) and model card.
PHASE1_ACCURACY = 0.995360224377559
PHASE1_MACRO_F1 = 0.8171522873728747
PHASE1_WEIGHTED_F1 = 0.9942282576954334
PHASE1_BINARY_F1 = 0.9808856495927725
PHASE1_FPR_PCT = 0.02810147909956249


def test_literature_rows_cover_all_three_categories():
    categories = {r.category for r in literature_rows()}
    assert "standalone_ml" in categories
    assert "blockchain_only" in categories
    assert "hybrid_published" in categories


def test_every_literature_row_has_a_valid_source():
    for r in literature_rows():
        assert r.source is not None
        assert r.source in SOURCES
        assert SOURCES[r.source].url.startswith("http")


def test_matched_dataset_comparison_exists():
    """Objective 3 requires a matched-protocol comparison where one is possible."""
    matched = [r for r in literature_rows() if r.matched_dataset]
    assert matched, "no published baseline on NF-CSE-CIC-IDS2018-v2 is included"
    for r in matched:
        assert r.dataset == "NF-CSE-CIC-IDS2018-v2"


def test_every_row_declares_its_dataset():
    for r in literature_rows():
        assert r.dataset, f"{r.system} does not state which dataset it was evaluated on"


def test_own_framework_uses_phase1_measured_figures():
    row = this_framework_row(PHASE2_RESULTS)
    assert row.source is None
    assert row.category == "this_framework"
    assert row.detection_accuracy == pytest.approx(PHASE1_ACCURACY)
    assert row.false_positive_rate_pct == pytest.approx(PHASE1_FPR_PCT, rel=1e-6)
    assert row.matched_dataset is True
    assert row.dataset == "NF-CSE-CIC-IDS2018-v2"


def test_own_framework_does_not_report_the_other_models_figures():
    """Guards against the CICIoT2023/STAHN figures reappearing.

    0.9862 accuracy and 0.9959 attack precision belong to a different model on a
    different dataset and are not measurements of this framework.
    """
    for row in this_framework_rows(PHASE2_RESULTS):
        assert row.detection_accuracy != pytest.approx(0.9862, abs=1e-6)
        assert row.f1_score != pytest.approx(0.9959, abs=1e-6)


def test_weighted_macro_and_binary_are_all_reported():
    rows = this_framework_rows(PHASE2_RESULTS)
    by_kind = {r.f1_kind: r.f1_score for r in rows}
    assert by_kind["weighted"] == pytest.approx(PHASE1_WEIGHTED_F1)
    assert by_kind["macro"] == pytest.approx(PHASE1_MACRO_F1)
    assert by_kind["binary"] == pytest.approx(PHASE1_BINARY_F1)
    # The macro figure must be the lower one; presenting only it against
    # weighted-F1 baselines would understate the work, and presenting only the
    # weighted one would overstate class-balanced performance.
    assert by_kind["macro"] < by_kind["weighted"]


def test_missing_metrics_raise_rather_than_substituting_a_placeholder():
    with pytest.raises(RuntimeError, match="will not substitute a placeholder"):
        this_framework_rows(PHASE2_RESULTS, metrics={})


def test_protocol_notes_disclose_f1_definition_and_mock_ledger():
    notes = " ".join(protocol_notes()).lower()
    assert "weighted" in notes and "macro" in notes
    assert "mockledger" in notes or "mock ledger" in notes
    assert "capture order" in notes


def test_format_table_renders_sources_and_missing_fields():
    rows = literature_rows()
    table = format_table(rows)
    assert "not reported" in table
    assert "| System |" in table
    for r in rows:
        assert SOURCES[r.source].url in table


def test_format_table_includes_own_rows_and_dataset_column():
    rows = literature_rows() + this_framework_rows(PHASE2_RESULTS)
    table = format_table(rows)
    assert "NF-CSE-CIC-IDS2018-v2" in table
    assert "this project (measured)" in table

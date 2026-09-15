from perf.comparative_benchmark import SOURCES, format_table, literature_rows, this_framework_row


def test_literature_rows_cover_all_three_categories():
    rows = literature_rows()
    categories = {r.category for r in rows}
    assert "standalone_ml" in categories
    assert "blockchain_only" in categories
    assert "hybrid_published" in categories


def test_every_literature_row_has_a_valid_source():
    rows = literature_rows()
    for r in rows:
        assert r.source is not None
        assert r.source in SOURCES
        assert SOURCES[r.source].url.startswith("http")


def test_this_framework_row_has_no_source_key():
    row = this_framework_row(
        phase1_accuracy=0.9862,
        phase1_attack_precision=0.9959,
        phase2_results={
            "integrity": {"failure_rate_pct": 0.0},
            "storage": {"reduction_pct": 45.2, "on_chain_bytes_mean": 762},
            "benchmark": {"latency_ms_p95": 7.9},
        },
    )
    assert row.source is None
    assert row.category == "this_framework"
    assert row.detection_accuracy == 0.9862


def test_format_table_renders_not_reported_for_missing_fields():
    rows = literature_rows()
    table = format_table(rows)
    assert "not reported" in table
    assert "| System |" in table
    for r in rows:
        assert SOURCES[r.source].url in table

import tempfile
from pathlib import Path

from perf.scalability_harness import run_arrival_rate_sweep, run_instance_count_sweep


def test_instance_count_sweep_runs_and_scales_without_penalty(tmp_path):
    results = run_instance_count_sweep([50, 500], events_per_run=40, store_root=tmp_path)
    assert len(results) == 2
    for r in results:
        assert r.events_processed == 40
        assert r.throughput_eps > 0
        assert r.latency_ms_p50 >= 0
    # No inherent per-resource-cardinality penalty: throughput at 500
    # simulated instances should not collapse relative to 50 instances.
    ratio = results[1].throughput_eps / results[0].throughput_eps
    assert ratio > 0.5


def test_arrival_rate_sweep_reports_keeping_up_at_low_rate(tmp_path):
    results = run_arrival_rate_sweep([20], duration_sec=1.0, num_workers=2, store_root=tmp_path)
    assert len(results) == 1
    r = results[0]
    assert r.submitted > 0
    assert r.committed + r.dead_lettered <= r.submitted + 5  # allow small in-flight tail
    assert r.keeping_up is True


def test_arrival_rate_sweep_output_fields_are_consistent(tmp_path):
    results = run_arrival_rate_sweep([30, 60], duration_sec=1.0, num_workers=2, store_root=tmp_path)
    for r in results:
        assert r.achieved_arrival_rate_eps >= 0
        assert r.achieved_commit_rate_eps >= 0
        assert r.max_queue_depth_observed >= 0

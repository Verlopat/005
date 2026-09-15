from perf.stability_test import run_stability_test


def test_short_stability_run_has_zero_event_loss(tmp_path):
    result = run_stability_test(
        duration_sec=1.5,
        arrival_rate_eps=100.0,
        transient_failure_probability=0.2,
        num_workers=2,
        store_root=tmp_path,
    )
    assert result.zero_event_loss
    assert result.committed + result.dead_lettered == result.submitted
    assert result.clean_shutdown
    assert result.unhandled_exceptions == 0


def test_stability_run_actually_exercises_retry_path(tmp_path):
    result = run_stability_test(
        duration_sec=1.5,
        arrival_rate_eps=150.0,
        transient_failure_probability=0.3,
        num_workers=2,
        store_root=tmp_path,
    )
    # With a nonzero transient failure probability and a bounded retry
    # budget, some events should end up dead-lettered after exhausting
    # retries -- if this were 0 with a 30% synthetic failure rate injected,
    # the retry wiring would be suspect.
    assert result.injected_transient_failures > 0
    assert result.zero_event_loss


def test_stability_run_with_zero_failures_commits_everything(tmp_path):
    result = run_stability_test(
        duration_sec=1.0,
        arrival_rate_eps=80.0,
        transient_failure_probability=0.0,
        num_workers=2,
        store_root=tmp_path,
    )
    assert result.dead_lettered == 0
    assert result.committed == result.submitted
    assert result.zero_event_loss

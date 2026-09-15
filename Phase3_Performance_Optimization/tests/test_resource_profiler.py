import time

from perf.resource_profiler import ResourceMonitor, ResourceProfile, overhead_pct


def test_resource_monitor_captures_wall_clock_and_samples():
    with ResourceMonitor(interval_sec=0.01) as monitor:
        time.sleep(0.1)
    profile = monitor.result()
    assert profile.wall_clock_sec >= 0.09
    assert len(profile.cpu_percent_samples) >= 1
    assert len(profile.rss_mb_samples) >= 1
    assert profile.rss_mb_peak > 0


def test_resource_monitor_measures_cpu_time_for_busy_work():
    with ResourceMonitor() as monitor:
        x = 0
        for i in range(1_000_000):
            x += i
    profile = monitor.result()
    assert profile.cpu_time_sec >= 0.0
    assert profile.cpu_utilisation_fraction >= 0.0


def test_overhead_pct_positive_when_integrated_uses_more_cpu():
    baseline = ResourceProfile(wall_clock_sec=1.0, cpu_time_sec=0.1)
    integrated = ResourceProfile(wall_clock_sec=1.0, cpu_time_sec=0.11)
    pct = overhead_pct(baseline, integrated)
    assert 9.0 < pct < 11.0  # 10% increase


def test_overhead_pct_handles_near_zero_baseline():
    baseline = ResourceProfile(wall_clock_sec=1.0, cpu_time_sec=0.0)
    integrated_same = ResourceProfile(wall_clock_sec=1.0, cpu_time_sec=0.0)
    integrated_more = ResourceProfile(wall_clock_sec=1.0, cpu_time_sec=0.05)
    assert overhead_pct(baseline, integrated_same) == 0.0
    assert overhead_pct(baseline, integrated_more) == float("inf")

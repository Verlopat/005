"""CPU/memory resource profiling.

Objective 3 success metric: "Processor overhead of the integrated
framework | < 15% additional utilisation against the detection-only
baseline." This module measures wall-clock CPU-time and peak RSS memory
for a block of code via a context manager, sampling `psutil` at a fixed
interval on a background thread so short-lived blocks still get at least
one sample.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

import psutil


@dataclass
class ResourceProfile:
    wall_clock_sec: float
    cpu_percent_samples: list[float] = field(default_factory=list)
    rss_mb_samples: list[float] = field(default_factory=list)
    cpu_time_sec: float = 0.0  # process CPU time consumed (user+system), independent of sampling cadence

    @property
    def cpu_percent_mean(self) -> float:
        return sum(self.cpu_percent_samples) / len(self.cpu_percent_samples) if self.cpu_percent_samples else 0.0

    @property
    def rss_mb_peak(self) -> float:
        return max(self.rss_mb_samples) if self.rss_mb_samples else 0.0

    @property
    def cpu_utilisation_fraction(self) -> float:
        """CPU-seconds consumed per wall-clock-second, e.g. 0.5 == half of
        one core busy on average over the measured interval. This is the
        quantity compared before/after to get an "additional utilisation"
        percentage, since it is independent of psutil's sampling cadence
        (unlike cpu_percent_mean, which depends on how often we happened
        to sample)."""
        return self.cpu_time_sec / self.wall_clock_sec if self.wall_clock_sec > 0 else 0.0


class ResourceMonitor:
    """Context manager: samples the current process's CPU% and RSS memory
    on a background thread at `interval_sec` while the `with` block runs,
    and also records total process CPU time (user+system) via
    `psutil.Process.cpu_times()` so `cpu_utilisation_fraction` is accurate
    even for sub-second blocks."""

    def __init__(self, interval_sec: float = 0.05):
        self.interval_sec = interval_sec
        self._process = psutil.Process()
        self._samples_cpu: list[float] = []
        self._samples_rss: list[float] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._t0 = 0.0
        self._t1 = 0.0
        self._cpu_time_start = 0.0
        self._cpu_time_end = 0.0

    def __enter__(self) -> "ResourceMonitor":
        self._process.cpu_percent(interval=None)  # prime the internal counter
        self._cpu_time_start = sum(self._process.cpu_times()[:2])
        self._t0 = time.perf_counter()
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._thread.start()
        return self

    def _sample_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._samples_cpu.append(self._process.cpu_percent(interval=None))
                self._samples_rss.append(self._process.memory_info().rss / (1024 * 1024))
            except psutil.Error:
                pass
            self._stop_event.wait(self.interval_sec)

    def __exit__(self, exc_type, exc, tb) -> None:
        self._t1 = time.perf_counter()
        self._cpu_time_end = sum(self._process.cpu_times()[:2])
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)

    def result(self) -> ResourceProfile:
        return ResourceProfile(
            wall_clock_sec=self._t1 - self._t0,
            cpu_percent_samples=list(self._samples_cpu),
            rss_mb_samples=list(self._samples_rss),
            cpu_time_sec=self._cpu_time_end - self._cpu_time_start,
        )


def overhead_pct(baseline: ResourceProfile, integrated: ResourceProfile) -> float:
    """Percentage additional CPU utilisation of `integrated` over
    `baseline`, per Objective 3's "< 15% additional utilisation against
    the detection-only baseline" metric. Guards against a near-zero
    baseline (e.g. a trivial detection-only workload) producing a
    meaningless divide-by-near-zero blow-up."""
    if baseline.cpu_utilisation_fraction <= 1e-9:
        return float("inf") if integrated.cpu_utilisation_fraction > 1e-9 else 0.0
    return 100.0 * (integrated.cpu_utilisation_fraction - baseline.cpu_utilisation_fraction) / baseline.cpu_utilisation_fraction

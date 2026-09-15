#!/usr/bin/env python3
"""Scalability / load test CLI: runs both sweeps from perf.scalability_harness
and prints + saves the results. Used standalone or by
scripts/generate_phase3_results.py (which re-runs a curated subset for the
paper report).
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

PHASE3_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PHASE3_ROOT))

from perf.scalability_harness import run_arrival_rate_sweep, run_instance_count_sweep  # noqa: E402

OUTPUTS_DIR = PHASE3_ROOT / "outputs"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Objective 3 scalability/load test sweeps")
    parser.add_argument("--instance-counts", type=int, nargs="+", default=[100, 500, 1000, 5000, 10000])
    parser.add_argument("--events-per-run", type=int, default=200)
    parser.add_argument("--arrival-rates", type=float, nargs="+", default=[100, 500, 1000, 2000, 5000, 10000])
    parser.add_argument("--arrival-duration-sec", type=float, default=4.0)
    parser.add_argument("--num-workers", type=int, default=3)
    args = parser.parse_args()

    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

    print(f"[*] Instance-count sweep: {args.instance_counts} ({args.events_per_run} events each)")
    instance_results = run_instance_count_sweep(args.instance_counts, events_per_run=args.events_per_run)
    for r in instance_results:
        print(f"    instances={r.num_instances:6d}  throughput={r.throughput_eps:8.1f} eps  "
              f"p50={r.latency_ms_p50:6.2f}ms  p95={r.latency_ms_p95:6.2f}ms  "
              f"cpu_util={r.cpu_utilisation_fraction:5.2f}  rss_peak={r.rss_mb_peak:6.1f}MB")

    print()
    print(f"[*] Arrival-rate sweep: {args.arrival_rates} events/sec, {args.arrival_duration_sec}s each")
    arrival_results = run_arrival_rate_sweep(args.arrival_rates, duration_sec=args.arrival_duration_sec, num_workers=args.num_workers)
    for r in arrival_results:
        print(f"    target={r.target_arrival_rate_eps:8.0f} eps  achieved={r.achieved_arrival_rate_eps:8.1f} eps  "
              f"committed_rate={r.achieved_commit_rate_eps:8.1f} eps  backlog_at_end={r.backlog_at_end:6d}  "
              f"keeping_up={r.keeping_up}")

    out = {
        "instance_count_sweep": [asdict(r) for r in instance_results],
        "arrival_rate_sweep": [asdict(r) for r in arrival_results],
    }
    out_path = OUTPUTS_DIR / "load_test_results.json"
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\n[ok] Results saved to: {out_path}")


if __name__ == "__main__":
    main()

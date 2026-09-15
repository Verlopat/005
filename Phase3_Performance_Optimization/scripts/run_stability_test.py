#!/usr/bin/env python3
"""Sustained-load stability test CLI.

Default: a short representative run (see --duration-sec). For the full
24-hour soak Objective 3 specifies, run on a host that can stay up that
long:

    python3 Phase3_Performance_Optimization/scripts/run_stability_test.py \\
        --duration-hours 24 --arrival-rate 1000 --failure-probability 0.05

Writes a checkpoint every --checkpoint-minutes to
.phase3_runtime/stability_checkpoint.json so progress is visible without
waiting for completion, and a final result to
Phase3_Performance_Optimization/outputs/stability_result.json.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PHASE3_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PHASE3_ROOT))

from perf.stability_test import run_stability_test  # noqa: E402

RUNTIME_DIR = PHASE3_ROOT / ".phase3_runtime"
OUTPUTS_DIR = PHASE3_ROOT / "outputs"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Objective 3 sustained-load stability test")
    parser.add_argument("--duration-sec", type=float, default=None, help="run duration in seconds")
    parser.add_argument("--duration-hours", type=float, default=None, help="run duration in hours (overrides --duration-sec)")
    parser.add_argument("--arrival-rate", type=float, default=200.0, help="target aggregate arrival rate, events/sec")
    parser.add_argument("--failure-probability", type=float, default=0.15, help="injected transient commit failure probability")
    parser.add_argument("--num-workers", type=int, default=3)
    parser.add_argument("--checkpoint-minutes", type=float, default=5.0)
    args = parser.parse_args()

    duration_sec = args.duration_hours * 3600.0 if args.duration_hours is not None else (args.duration_sec or 20.0)

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
    checkpoint_path = RUNTIME_DIR / "stability_checkpoint.json"

    print(f"[*] Running stability test for {duration_sec:.0f}s at target {args.arrival_rate} events/sec "
          f"with {args.failure_probability:.0%} injected transient failure probability ({args.num_workers} workers)")
    if duration_sec >= 3600:
        print(f"[*] Checkpointing every {args.checkpoint_minutes} minute(s) to {checkpoint_path}")

    def checkpoint(snapshot: dict) -> None:
        checkpoint_path.write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
        pct = 100.0 * snapshot["elapsed_sec"] / snapshot["duration_sec"]
        print(f"    [checkpoint] {pct:.1f}% complete: submitted={snapshot['submitted']} "
              f"committed={snapshot['committed']} dead_lettered={snapshot['dead_lettered']} "
              f"zero_loss_so_far={snapshot['zero_loss_so_far']}")

    result = run_stability_test(
        duration_sec=duration_sec,
        arrival_rate_eps=args.arrival_rate,
        transient_failure_probability=args.failure_probability,
        num_workers=args.num_workers,
        checkpoint_callback=checkpoint,
        checkpoint_interval_sec=args.checkpoint_minutes * 60.0,
    )

    print()
    print("=" * 70)
    print("Stability test result")
    print("=" * 70)
    print(f"  duration_sec               : {result.duration_sec:.1f}")
    print(f"  submitted                  : {result.submitted}")
    print(f"  committed                  : {result.committed}")
    print(f"  dead_lettered              : {result.dead_lettered}")
    print(f"  zero_event_loss            : {result.zero_event_loss}")
    print(f"  clean_shutdown             : {result.clean_shutdown}")
    print(f"  injected_transient_failures: {result.injected_transient_failures}")
    print(f"  max_consecutive_dead_letters: {result.max_consecutive_dead_letters}")
    print(f"  unhandled_exceptions       : {result.unhandled_exceptions}")
    passed = result.zero_event_loss and result.clean_shutdown and result.unhandled_exceptions == 0
    print(f"  OVERALL: {'PASSED' if passed else 'FAILED'}")

    out_path = OUTPUTS_DIR / "stability_result.json"
    out_path.write_text(json.dumps(result.__dict__, indent=2), encoding="utf-8")
    print(f"\n[ok] Result saved to: {out_path}")

    if not passed:
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Discover and launch Phase 2 blockchain-logging scripts from the repository root."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PHASE2 = ROOT / "Phase2_Blockchain_Logging"


def run(command: list[str]) -> int:
    print("\n+", " ".join(command))
    return subprocess.run(command, cwd=PHASE2, check=False).returncode


def python_scripts() -> list[Path]:
    excluded = {".venv", "venv", "__pycache__"}
    return sorted(
        path.relative_to(PHASE2)
        for path in PHASE2.rglob("*.py")
        if not any(part in excluded for part in path.parts)
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Phase 2 locally or prepare its Hyperledger Fabric environment."
    )
    parser.add_argument(
        "script",
        nargs="?",
        help="Relative path to a Phase 2 Python script, e.g. scripts/demo.py.",
    )
    parser.add_argument(
        "--install-deps",
        action="store_true",
        help="Install local Phase 2 requirements before running a script.",
    )
    parser.add_argument(
        "--install-fabric-deps",
        action="store_true",
        help="Also install Fabric gateway dependencies from requirements-fabric.txt.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available Phase 2 Python scripts without running one.",
    )
    args = parser.parse_args()

    if not PHASE2.is_dir():
        print(f"Phase 2 directory not found: {PHASE2}", file=sys.stderr)
        return 1

    scripts = python_scripts()
    if args.list or not args.script:
        print("Available Phase 2 Python scripts:")
        for script in scripts:
            print(f"  {script.as_posix()}")
        if not args.script:
            print("\nRun one with:")
            print("  python run_phase2.py --install-deps path/to/script.py")
        return 0

    if args.install_deps:
        result = run([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        if result:
            return result

    if args.install_fabric_deps:
        fabric_requirements = PHASE2 / "requirements-fabric.txt"
        if not fabric_requirements.is_file():
            print(f"Fabric requirements file not found: {fabric_requirements}", file=sys.stderr)
            return 1
        result = run([sys.executable, "-m", "pip", "install", "-r", "requirements-fabric.txt"])
        if result:
            return result

    target = (PHASE2 / args.script).resolve()
    try:
        target.relative_to(PHASE2.resolve())
    except ValueError:
        print("The script must be inside Phase2_Blockchain_Logging.", file=sys.stderr)
        return 1

    if not target.is_file() or target.suffix != ".py":
        print(f"Python script not found: {target}", file=sys.stderr)
        print("Use --list to see available scripts.", file=sys.stderr)
        return 1

    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PHASE2) + os.pathsep + environment.get("PYTHONPATH", "")
    command = [sys.executable, str(target.relative_to(PHASE2))]
    print("\n+", " ".join(command))
    return subprocess.run(command, cwd=PHASE2, env=environment, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())

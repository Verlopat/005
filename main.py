#!/usr/bin/env python3
"""Unified launcher for the three project phases."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"

PHASES = {
    "phase1": {
        "requirements": [ROOT / "Phase1_Submission" / "requirements.txt"],
        "commands": [[ROOT / "Phase1_Submission" / "interactive_inference.py"]],
    },
    "phase2": {
        "requirements": [ROOT / "Phase2_Blockchain_Logging" / "requirements.txt"],
        "commands": [
            [ROOT / "Phase2_Blockchain_Logging" / "scripts" / "run_phase2_demo.py"],
            [ROOT / "Phase2_Blockchain_Logging" / "scripts" / "tamper_demo.py"],
        ],
    },
    "phase3": {
        "requirements": [ROOT / "Phase3_Performance_Optimization" / "requirements.txt"],
        "commands": [[ROOT / "Phase3_Performance_Optimization" / "scripts" / "run_load_test.py"]],
    },
}


def venv_python() -> Path:
    return VENV_DIR / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def run(command: list[str], *, cwd: Path | None = None) -> None:
    print("+", " ".join(map(str, command)))
    subprocess.run(command, check=True, cwd=cwd)


def ensure_venv() -> Path:
    python = venv_python()
    if not python.exists():
        run([sys.executable, "-m", "venv", str(VENV_DIR)])
    return python


def install_requirements(python: Path, requirements: list[Path]) -> None:
    run([str(python), "-m", "pip", "install", "--upgrade", "pip"])
    for requirement_file in requirements:
        if not requirement_file.is_file():
            raise FileNotFoundError(f"Requirements file not found: {requirement_file}")
        run([str(python), "-m", "pip", "install", "-r", str(requirement_file)])


def launch(phase: str) -> None:
    config = PHASES[phase]
    python = ensure_venv()
    install_requirements(python, config["requirements"])
    for command in config["commands"]:
        entry_point = command[0]
        if not entry_point.is_file():
            raise FileNotFoundError(f"Entry point not found: {entry_point}")
        run([str(python), *map(str, command)], cwd=entry_point.parent)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "phase",
        choices=[*PHASES, "all"],
        help="Phase to install and run",
    )
    args = parser.parse_args()
    selected = PHASES if args.phase == "all" else [args.phase]
    for phase in selected:
        print(f"\n=== Running {phase} ===")
        launch(phase)


if __name__ == "__main__":
    main()

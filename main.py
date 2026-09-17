#!/usr/bin/env python3
"""Reproducible Phase_1 -> evidence logging -> asynchronous replay launcher."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PHASES = ("phase1", "phase2", "phase3")
TRAIN_STAGES = (
    "01_inspect.py", "02_prepare.py", "03_artifact_check.py",
    "04_select_features.py", "05_compare_models.py", "06_tune.py",
    "07_metrics_report.py", "08_calibration_icr.py", "09_export_model.py",
    "10_alert_contract.py",
)
PHASE_DIRS = ("Phase_1", "Phase2_Blockchain_Logging", "Phase3_Performance_Optimization")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def positive(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Phases are cumulative, so each command is a superset of the one before it:

  python main.py phase1     run Phase 1 only
  python main.py phase2     run Phase 1, then Phase 2
  python main.py phase3     run Phase 1, then Phase 2, then Phase 3
  python main.py all        same as phase3

That ordering is enforced, not merely suggested: Phase 2 consumes the alert
stream and provenance Phase 1 exports, and Phase 3 replays the events Phase 2
anchored, with a digest check at each boundary.

Use --only to run a single phase in isolation (--only phase3 additionally needs
--run-dir pointing at a completed Phase 2 run).
""",
    )
    result.add_argument("phase", choices=(*PHASES, "all"),
                        help="highest phase to run; earlier phases run first unless --only")
    result.add_argument("--only", action="store_true",
                        help="run just the named phase instead of every phase up to it")
    result.add_argument("--mode", choices=("existing", "train", "smoke"), default="existing",
                        help="existing artifacts (default), full training, or synthetic smoke test")
    result.add_argument("--run-dir", type=Path, help="new output directory; phase3 reuses a phase2 run")
    result.add_argument("--alerts", type=Path, help="Phase 1 full sample_alerts.jsonl (existing mode)")
    result.add_argument("--limit", type=positive, default=100,
                        help="maximum alerts to log and replay (default: 100)")
    result.add_argument("--repeats", type=positive, default=3,
                        help="independent synchronous/asynchronous replay pairs")
    result.add_argument("--install", action="store_true",
                        help="create .venv and install requirements once before execution")
    result.add_argument("--python", type=Path, help="existing interpreter; incompatible with --install")
    result.add_argument("--dry-run", action="store_true", help="print commands without side effects")
    result.add_argument("--check", action="store_true", help="validate prerequisite files, then exit")
    return result


def selected_phases(args) -> tuple[str, ...]:
    """Phases to run, cumulative unless ``--only`` was given.

    ``phase2`` means "Phase 1 then Phase 2", because the phases form a pipeline
    rather than a menu: running Phase 2 against a stale handoff is exactly the
    reproducibility failure the digest checks exist to prevent.
    """
    if args.phase == "all":
        return PHASES
    if args.only:
        return (args.phase,)
    return PHASES[: PHASES.index(args.phase) + 1]


def resumes_previous_run(args) -> bool:
    """True when the plan consumes a previous run's Phase 2 output.

    Only possible with ``--only phase3``; a cumulative run produces that output
    itself earlier in the same run directory.
    """
    selected = selected_phases(args)
    return "phase3" in selected and "phase2" not in selected


def preflight(args) -> list[Path]:
    selected = selected_phases(args)
    required = [ROOT / "pipeline" / "run_stage.py"]
    if "phase1" in selected and args.mode == "train":
        required += [ROOT / "Phase_1" / script for script in TRAIN_STAGES]
        required.append(ROOT / "Phase_1" / "data" / "NF-CSE-CIC-IDS2018-v2.csv")
    elif args.mode != "smoke" and any(p in selected for p in ("phase1", "phase2")):
        required += [
            args.alerts,
            ROOT / "Phase_1" / "outputs" / "09_model" / "detector_bundle.joblib",
            ROOT / "Phase_1" / "outputs" / "09_model" / "model_card.json",
        ]
    if resumes_previous_run(args):
        required += [args.run_dir / "phase2" / name for name in
                     ("events.jsonl", "handoff.json", "mapping.json", "results.json")]
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        raise FileNotFoundError(
            "Missing prerequisites:\n  " + "\n  ".join(missing) + "\n" + remedy(missing)
        )
    return required


def remedy(missing: list[str]) -> str:
    """Advice naming only the recovery steps the missing files actually imply.

    A single absent alert stream used to print the full three-mode recovery
    blurb, which reads as "retrain the detector" when the trained bundle is
    present and healthy.
    """
    hints = []
    if any("run_stage.py" in item for item in missing):
        hints.append("pipeline/run_stage.py is absent; the checkout is incomplete.")
    if any(item.endswith(".csv") for item in missing):
        hints.append("Restore the Phase_1 dataset CSV into Phase_1/data/.")
    if any("detector_bundle" in item or "model_card" in item for item in missing):
        hints.append("Restore the exported Phase_1 model bundle, or rebuild it with "
                     "--mode train.")
    if any("sample_alerts" in item for item in missing):
        hints.append("Export the alert stream with Phase_1/10_alert_contract.py (it "
                     "reuses the trained bundle and does not retrain), or pass --alerts "
                     "to point at an existing stream.")
    if any("phase2" in item for item in missing):
        hints.append("--only phase3 replays a finished phase2; check --run-dir names a "
                     "run that completed phase2.")
    if not hints:
        hints.append("Use --mode smoke to exercise the pipeline on synthetic data.")
    return "\n".join(hints)


def commands(args, python: str) -> list[tuple[str, list[str], Path]]:
    plan = []
    for phase in selected_phases(args):
        if phase == "phase1" and args.mode == "train":
            plan.extend((f"phase1-{script[:2]}", [python, str(ROOT / "Phase_1" / script)],
                         ROOT / "Phase_1") for script in TRAIN_STAGES)
        # Phase 1 finishes by checking/exporting the same handoff consumed by Phase 2.
        plan.append((phase, [
            python, str(ROOT / "pipeline" / "run_stage.py"), phase,
            "--mode", args.mode, "--run-dir", str(args.run_dir),
            "--alerts", str(args.alerts), "--limit", str(args.limit),
            "--repeats", str(args.repeats),
        ], ROOT))
    return plan


def execute(name: str, command: list[str], cwd: Path, run_dir: Path, manifest: dict) -> None:
    step = {"name": name, "command": command, "cwd": str(cwd), "status": "running"}
    manifest["steps"].append(step)
    write_manifest(run_dir, manifest)
    start = time.monotonic()
    print(f"\n=== {name} ===", flush=True)
    try:
        with (run_dir / f"{name}.log").open("w", encoding="utf-8") as log:
            proc = subprocess.Popen(command, cwd=cwd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, errors="replace",
                                    env={**os.environ, "PYTHONUNBUFFERED": "1"})
            try:
                for line in proc.stdout:
                    print(line, end="", flush=True)
                    log.write(line)
                code = proc.wait()
            except BaseException:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                raise
        step["returncode"] = code
        if code:
            raise subprocess.CalledProcessError(code, command)
        step["status"] = "completed"
    except BaseException:
        step["status"] = "failed"
        raise
    finally:
        step["elapsed_seconds"] = time.monotonic() - start
        write_manifest(run_dir, manifest)


def write_manifest(run_dir: Path, manifest: dict) -> None:
    temporary = run_dir / "manifest.tmp"
    temporary.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    temporary.replace(run_dir / "manifest.json")


def main(argv=None) -> int:
    cli = parser()
    args = cli.parse_args(argv)
    if args.install and args.python:
        cli.error("--install and --python are mutually exclusive")
    if args.alerts and args.mode != "existing":
        cli.error("--alerts is only supported with --mode existing")
    if resumes_previous_run(args) and args.run_dir is None:
        cli.error("--only phase3 requires --run-dir pointing to a completed phase2 run")
    if args.mode == "train" and "phase1" not in selected_phases(args):
        cli.error("--mode train trains the Phase 1 detector, so phase1 must be in the "
                  "plan; drop --only or select phase1")
    args.run_dir = (args.run_dir or ROOT / "runs" /
                    datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")).resolve()
    args.alerts = (args.alerts or ROOT / "Phase_1" / "outputs" /
                   "10_contract" / "sample_alerts.jsonl").resolve()
    interpreter = (ROOT / ".venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
    # Do not resolve interpreter symlinks: venv/bin/python often links to the
    # system executable, and resolving it silently discards the virtualenv.
    python = str(args.python.absolute()) if args.python else (
        str(interpreter) if args.install or interpreter.is_file() else sys.executable)
    plan = commands(args, python)
    if args.dry_run:
        for name, command, cwd in plan:
            print(f"{name} (cwd={cwd}): {subprocess.list2cmdline(command)}")
        return 0
    try:
        inputs = preflight(args)
        if args.check:
            print("Prerequisite files present. This is not a validation of research results.")
            return 0
        if resumes_previous_run(args):
            if (args.run_dir / "phase3").exists():
                raise FileExistsError("phase3 output already exists; use a fresh phase2 run")
        else:
            args.run_dir.mkdir(parents=True, exist_ok=False)
        manifest_path = args.run_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {"steps": []}
        manifest.update({
            "status": "running", "mode": args.mode, "platform": platform.platform(),
            "launcher_python": sys.version, "requested_interpreter": python,
            "started_utc": datetime.now(timezone.utc).isoformat(),
            "arguments": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
            "input_sha256": {str(p.relative_to(ROOT) if p.is_relative_to(ROOT) else p): sha256(p)
                             for p in inputs},
            "code_sha256": {str(p.relative_to(ROOT)): sha256(p)
                            for folder in (*PHASE_DIRS, "pipeline")
                            for p in (ROOT / folder).rglob("*.py")},
        })
        manifest["code_sha256"]["main.py"] = sha256(ROOT / "main.py")
        try:
            if args.install:
                if not interpreter.is_file():
                    execute("environment", [sys.executable, "-m", "venv", str(ROOT / ".venv")],
                            ROOT, args.run_dir, manifest)
                # Downstream layers depend on Phase 2; smoke does not install the ML stack.
                folders = {"Phase2_Blockchain_Logging"}
                if "phase3" in selected_phases(args):
                    folders.add("Phase3_Performance_Optimization")
                if args.mode == "train":
                    folders.add("Phase_1")
                install = [python, "-m", "pip", "install"]
                for folder in sorted(folders):
                    install += ["-r", str(ROOT / folder / "requirements.txt")]
                execute("install", install, ROOT, args.run_dir, manifest)
            execute("environment-info", [python, "-c",
                    "import sys,importlib.metadata,json; print(sys.version); "
                    "print(json.dumps(sorted((d.metadata['Name'],d.version) "
                    "for d in importlib.metadata.distributions()),indent=2))"],
                    ROOT, args.run_dir, manifest)
            for name, command, cwd in plan:
                execute(name, command, cwd, args.run_dir, manifest)
            manifest["status"] = "completed"
        except BaseException as exc:
            manifest["status"] = "failed"
            manifest["error"] = str(exc)
            raise
        finally:
            manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
            write_manifest(args.run_dir, manifest)
        print(f"\nCompleted. Logs and manifest: {args.run_dir}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"Pipeline failed: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Pipeline interrupted; downstream phases were not started.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

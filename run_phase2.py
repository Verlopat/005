from __future__ import annotations

import importlib.metadata
import runpy
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
PHASE2_DIR = ROOT_DIR / "Phase2_Blockchain_Logging"
ENTRY_SCRIPT = PHASE2_DIR / "scripts" / "generate_phase2_results.py"
REQUIREMENTS_FILE = PHASE2_DIR / "requirements.txt"


def requirement_name(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith("#") or line.startswith(("-r", "--", "git+", "http://", "https://")):
        return None
    for marker in (";", "[", "=", "<", ">", "!", "~"):
        line = line.split(marker, 1)[0]
    return line.strip() or None


def missing_dependencies(requirements_path: Path) -> list[str]:
    if not requirements_path.is_file():
        print(f"[!] Requirements file not found: {requirements_path}")
        return []

    missing = []
    for raw_line in requirements_path.read_text(encoding="utf-8").splitlines():
        package = requirement_name(raw_line)
        if not package:
            continue
        try:
            importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            missing.append(package)
    return missing


def main() -> None:
    print("[*] Checking Phase 2 dependencies...")

    if not ENTRY_SCRIPT.is_file():
        sys.exit(f"[!] Error: Could not find {ENTRY_SCRIPT}")

    missing = missing_dependencies(REQUIREMENTS_FILE)
    if missing:
        print("[!] Missing required package(s): " + ", ".join(missing))
        print("[!] Install them with:")
        print(f"    {sys.executable} -m pip install -r {REQUIREMENTS_FILE}")
        sys.exit(1)

    print("[*] Dependencies found. Running the Objective 2 (Phase 2) results pipeline...")
    print("[*] This produces Phase2_Blockchain_Logging/outputs/phase2_results.md — the report to use in your paper.")
    print()
    sys.argv = [str(ENTRY_SCRIPT)]  # generate_phase2_results.py's own argparse defaults apply
    runpy.run_path(str(ENTRY_SCRIPT), run_name="__main__")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user.")

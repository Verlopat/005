from pathlib import Path
import os
import runpy
import sys

ROOT_DIR = Path(__file__).resolve().parent
PHASE1_DIR = ROOT_DIR / "Phase1_Submission"
ENTRY_SCRIPT = PHASE1_DIR / "interactive_inference.py"

if not ENTRY_SCRIPT.is_file():
    sys.exit(f"Error: Could not find {ENTRY_SCRIPT}")

os.chdir(PHASE1_DIR)

try:
    runpy.run_path(str(ENTRY_SCRIPT), run_name="__main__")
except KeyboardInterrupt:
    print("\nStopped by user.")

"""Regression tests for the new root launcher and frozen-contract handoff."""
import copy
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import main
from pipeline import run_stage as stage


def options(tmp_path, **kwargs):
    defaults = dict(phase="all", mode="smoke", run_dir=tmp_path / "run",
                    alerts=tmp_path / "unused.jsonl", limit=7, repeats=1)
    return SimpleNamespace(**(defaults | kwargs))


def test_training_order(tmp_path):
    plan = main.commands(options(tmp_path, mode="train"), sys.executable)
    assert [name for name, _, _ in plan] == [
        *(f"phase1-{i:02d}" for i in range(1, 11)), "phase1", "phase2", "phase3"]
    assert not any("Phase1_Submission" in str(command) for _, command, _ in plan)


def test_dry_run_has_no_side_effects(tmp_path):
    destination = tmp_path / "absent"
    assert main.main(["all", "--dry-run", "--run-dir", str(destination)]) == 0
    assert not destination.exists()


def test_missing_inputs_fail_before_creating_run(tmp_path):
    destination = tmp_path / "absent"
    assert main.main(["all", "--alerts", str(tmp_path / "missing"), "--run-dir", str(destination)]) == 1
    assert not destination.exists()


@pytest.mark.parametrize("value", ["0", "-1"])
def test_invalid_limit(value):
    with pytest.raises(SystemExit):
        main.main(["all", "--limit", value])


def test_failure_is_recorded_and_stops(tmp_path, monkeypatch):
    args = options(tmp_path)
    monkeypatch.setattr(main, "commands", lambda *a: [
        ("fail", [sys.executable, "-c", "raise SystemExit(4)"], ROOT),
        ("never", [sys.executable, "-c", "print('should not run')"], ROOT)])
    assert main.main(["all", "--mode", "smoke", "--run-dir", str(args.run_dir)]) == 1
    manifest = json.loads((args.run_dir / "manifest.json").read_text())
    assert manifest["status"] == "failed"
    assert manifest["steps"][-1]["returncode"] == 4
    assert not (args.run_dir / "never.log").exists()


def test_contract_vectors():
    vectors = json.loads((stage.CONTRACT / "hash_test_vectors.json").read_text())["vectors"]
    assert all(stage.event_hash(v["alert"]) == v["expected_sha256"] for v in vectors)


@pytest.mark.parametrize("index", range(7))
def test_all_categories_and_digests(index):
    alert = stage.fixture(7)[index]
    schema = json.loads((stage.CONTRACT / "alert_schema.json").read_text())
    stage.validate_alert(alert, schema)
    event = stage.adapt(alert, "a" * 64, synthetic=True)
    target = stage.Phase2Pipeline._load_default_schema()
    stage.jsonschema.validate(event, target)
    # Phase 2's contract now uses Phase 1's own categories, so the handoff
    # carries the threat class through unchanged rather than translating it.
    assert event["threat_category"] == alert["threat_class"]
    assert event["threat_category"] in stage.CATEGORIES
    assert event["calibrated_confidence"] == alert["confidence"]
    assert event["calibration"] == {"is_calibrated": False, "method": "none"}
    # Severity is the producer's decision, only renamed.
    assert event["severity"] == {
        "NONE": "informational", "LOW": "low", "MEDIUM": "medium",
        "HIGH": "high", "CRITICAL": "critical",
    }[alert["severity"]]
    # The producer's digest travels with the event and is verified on arrival.
    assert event["detection_contract"]["event_hash"] == alert["event_hash"]
    assert event["detection_contract"]["digest_verified_by_consumer"] is True


@pytest.mark.parametrize("field", ["features", "confidence"])
def test_reject_tampering(field):
    alert = copy.deepcopy(stage.fixture(1)[0])
    if field == "features":
        alert["features"][next(iter(alert["features"]))] += 1
    else:
        alert["confidence"] = 0.7
    with pytest.raises(ValueError, match="digest mismatch|hash mismatch"):
        stage.validate_alert(alert, json.loads((stage.CONTRACT / "alert_schema.json").read_text()))


def test_source_anchor_is_preserved_even_for_normal():
    alert = stage.fixture(1)[0]
    alert["anchor"] = True
    event = stage.adapt(alert, "a" * 64)
    policy = stage.SourceAnchorPolicy({alert["event_id"]: True})
    assert policy.decide(event) == stage.AnchoringDecision.BATCH


def test_smoke_end_to_end_from_other_directory(tmp_path):
    run = tmp_path / "run"
    process = subprocess.run([
        sys.executable, str(ROOT / "main.py"), "all", "--mode", "smoke",
        "--python", sys.executable, "--limit", "7", "--repeats", "1",
        "--run-dir", str(run),
    ], cwd=tmp_path, text=True, capture_output=True)
    assert process.returncode == 0, process.stdout + process.stderr
    manifest = json.loads((run / "manifest.json").read_text())
    assert manifest["status"] == "completed"
    assert [s["name"] for s in manifest["steps"]][-3:] == ["phase1", "phase2", "phase3"]
    result = json.loads((run / "phase3" / "results.json").read_text())
    assert result["synthetic"] is True
    assert len(result["trials"]) == 2
    assert all(t["audit"]["verified"] == 6 for t in result["trials"])


def test_phase3_rejects_changed_handoff(tmp_path):
    args = options(tmp_path)
    stage.phase2(args)
    with (args.run_dir / "phase2" / "events.jsonl").open("a") as stream:
        stream.write("\n")
    with pytest.raises(ValueError, match="handoff digest"):
        stage.phase3(args)


def test_mode_cannot_relabel_synthetic_as_real(tmp_path):
    args = options(tmp_path)
    stage.phase2(args)
    args.mode = "existing"
    with pytest.raises(ValueError, match="mode does not match"):
        stage.phase3(args)


def test_phase2_rejects_changed_source(tmp_path):
    args = options(tmp_path)
    stage.prepare(args)
    with (args.run_dir / "phase1" / "alerts.jsonl").open("a") as stream:
        stream.write("\n")
    with pytest.raises(ValueError, match="handoff digest"):
        stage.phase2(args)


def test_refuse_overwrite(tmp_path):
    directory = tmp_path / "run"
    directory.mkdir()
    assert main.main(["all", "--mode", "smoke", "--run-dir", str(directory)]) == 1


def test_empty_and_duplicate_inputs(tmp_path):
    path = tmp_path / "alerts"
    path.write_text("")
    with pytest.raises(ValueError, match="Empty"):
        stage.read_alerts(path, 2)
    stage.save_lines(path, [stage.fixture(1)[0]] * 2)
    with pytest.raises(ValueError, match="Duplicate"):
        stage.read_alerts(path, 2)

import hashlib
from pathlib import Path

from src.model_provenance import build_provenance_record, compute_model_digest, sha256_file


def test_sha256_file_matches_hashlib(tmp_path):
    p = tmp_path / "artifact.bin"
    p.write_bytes(b"fake model weights" * 1000)
    expected = hashlib.sha256(p.read_bytes()).hexdigest()
    assert sha256_file(p) == expected


def test_model_digest_is_deterministic_regardless_of_dict_order():
    d1 = compute_model_digest("aa", ["f1", "f2"], ["BENIGN", "ATTACK"], {"lr": 0.1, "depth": 6}, {"BENIGN": 0.5})
    d2 = compute_model_digest("aa", ["f1", "f2"], ["BENIGN", "ATTACK"], {"depth": 6, "lr": 0.1}, {"BENIGN": 0.5})
    assert d1 == d2


def test_model_digest_changes_if_feature_order_changes():
    d1 = compute_model_digest("aa", ["f1", "f2"], ["BENIGN", "ATTACK"], {}, {})
    d2 = compute_model_digest("aa", ["f2", "f1"], ["BENIGN", "ATTACK"], {}, {})
    assert d1 != d2  # reordering features silently changes predictions; the digest must catch it


def test_build_provenance_record_end_to_end(tmp_path):
    model_path = tmp_path / "model.pth"
    model_path.write_bytes(b"weights")
    record = build_provenance_record(
        model_path=model_path,
        model_id="fa8d2667cc39cea50abe78f813133ead89e9dea3a317da436c14dcfc41fbf820",
        version_label="v1",
        feature_order=["Rate"],
        label_order=["BENIGN", "ATTACK"],
        artifact_content_address="local:model.pth",
        anchored_at="2026-09-15T18:00:00.000Z",
    )
    assert len(record.model_digest) == 64
    recomputed = compute_model_digest(
        sha256_file(model_path), record.feature_order, record.label_order, record.hyperparameters, record.thresholds
    )
    assert recomputed == record.model_digest

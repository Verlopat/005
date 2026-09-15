"""Model provenance: the "immutable birth certificate" for the deployed model.

Directed by Phase1_Submission/blockchain_handoff_document.md ("Generate a
SHA-256 hash of the stahn_model.pth file. Store this hash in a Smart
Contract") and formalised by Objective 2 ("The model identifier established
in Objective 1 is anchored on-chain once per retraining cycle and
referenced by every alert emitted under that model").

Two digests matter and must not be confused:

* ``artifact_sha256`` — the SHA-256 of the raw model file bytes
  (stahn_model.pth). This is what the handoff document asks for directly
  and is sufficient to detect a swapped or corrupted weights file.
* ``model_digest`` — the SHA-256 over every prediction-affecting
  component (artifact bytes + feature order + label order + hyperparameters
  + thresholds), per Objective 1's fuller provenance definition. A file
  hash alone cannot catch a deployment that loads the right weights with
  the wrong feature ordering; ``model_digest`` can. ``model_digest`` is
  the value carried in every alert's ``model.model_digest`` field.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .canonical import canonicalise
from .digest import digest_bytes


def sha256_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """Stream a file through SHA-256 without loading it entirely into memory.

    Suitable for the 10.9 MB stahn_model.pth today and for a much larger
    artifact under a future model family without a code change.
    """
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


@dataclass(frozen=True)
class ModelProvenanceRecord:
    contract_version: str
    model_id: str
    model_digest: str
    version_label: str
    artifact_content_address: str
    feature_order: list[str]
    label_order: list[str]
    hyperparameters: dict = field(default_factory=dict)
    thresholds: dict = field(default_factory=dict)
    training_summary: dict = field(default_factory=dict)
    anchored_at: str = ""

    def to_dict(self) -> dict:
        return {
            "contract_version": self.contract_version,
            "model_id": self.model_id,
            "model_digest": self.model_digest,
            "version_label": self.version_label,
            "artifact_content_address": self.artifact_content_address,
            "feature_order": self.feature_order,
            "label_order": self.label_order,
            "hyperparameters": self.hyperparameters,
            "thresholds": self.thresholds,
            "training_summary": self.training_summary,
            "anchored_at": self.anchored_at,
        }


def compute_model_digest(
    artifact_sha256: str,
    feature_order: list[str],
    label_order: list[str],
    hyperparameters: dict,
    thresholds: dict,
) -> str:
    """SHA-256 over every prediction-affecting component, canonically
    serialised so the digest is deterministic regardless of dict/list
    construction order in the caller."""
    components = {
        "artifact_sha256": artifact_sha256,
        "feature_order": list(feature_order),
        "label_order": list(label_order),
        "hyperparameters": hyperparameters,
        "thresholds": thresholds,
    }
    canonical = canonicalise(components)
    return digest_bytes(canonical.encode("utf-8"))


def build_provenance_record(
    model_path: Path,
    model_id: str,
    version_label: str,
    feature_order: list[str],
    label_order: list[str],
    artifact_content_address: str,
    anchored_at: str,
    hyperparameters: dict | None = None,
    thresholds: dict | None = None,
    training_summary: dict | None = None,
) -> ModelProvenanceRecord:
    artifact_sha256 = sha256_file(model_path)
    hyperparameters = hyperparameters or {}
    thresholds = thresholds or {}
    training_summary = training_summary or {}
    model_digest = compute_model_digest(
        artifact_sha256, feature_order, label_order, hyperparameters, thresholds
    )
    return ModelProvenanceRecord(
        contract_version="1.0.0",
        model_id=model_id,
        model_digest=model_digest,
        version_label=version_label,
        artifact_content_address=artifact_content_address,
        feature_order=feature_order,
        label_order=label_order,
        hyperparameters=hyperparameters,
        thresholds=thresholds,
        training_summary=training_summary,
        anchored_at=anchored_at,
    )


def save_provenance_record(record: ModelProvenanceRecord, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

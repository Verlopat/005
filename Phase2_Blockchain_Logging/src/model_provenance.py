"""Model provenance: the "immutable birth certificate" for the deployed model.

Formalised by Objective 2: "The model identifier established in Objective 1 is
anchored on-chain once per retraining cycle and referenced by every alert
emitted under that model."

The deployed model is the Phase 1 LightGBM multiclass detector
(``Phase_1/outputs/09_model/``), trained on NF-CSE-CIC-IDS2018-v2. Its identity
is read from Phase 1's own model card rather than restated here - see
:func:`build_provenance_from_phase1`.

Two digests matter and must not be confused:

* ``artifact_sha256`` — the SHA-256 of the raw serialised model bytes
  (Phase 1's exported ``booster.txt``, or the joblib bundle). Sufficient to
  detect a swapped or corrupted model file.
* ``model_digest`` — the SHA-256 over every prediction-affecting
  component (artifact bytes + feature order + label order + hyperparameters
  + thresholds), per Objective 1's fuller provenance definition. A file
  hash alone cannot catch a deployment that loads the right weights with
  the wrong feature ordering; ``model_digest`` can. ``model_digest`` is
  the value carried in every alert's ``model.model_digest`` field.

Phase 1 independently computes an equivalent identity as
``model_card.json:model_id_sha256`` (booster bytes + ordered features + label
order + hyperparameters + per-class thresholds). The two are computed over the
same components but with different serialisations, so they are deliberately not
asserted equal; both are recorded, and ``model_id`` carries Phase 1's value so
an auditor can trace an alert to the producer's own identifier.
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


def build_provenance_from_phase1(
    anchored_at: str,
    *,
    artifact_path: Path | None = None,
    model_path: Path | None = None,
) -> ModelProvenanceRecord:
    """Build the provenance record for the Phase 1 detector from its model card.

    Every field is read from artefacts Phase 1 produced; nothing is restated
    here. Raises ``DetectionLayerUnavailable`` if Phase 1's model card or
    exported artifact is absent, rather than anchoring a placeholder identity.

    ``model_path`` is accepted as an alias for ``artifact_path`` so existing
    callers keep working.
    """
    from .detection_layer import (  # imported here to avoid a circular import
        artifact_path as phase1_artifact_path,
        model_identity,
        training_summary,
    )

    identity = model_identity()
    resolved = artifact_path or model_path or phase1_artifact_path()
    resolved = Path(resolved)

    return build_provenance_record(
        model_path=resolved,
        model_id=identity.model_id,
        version_label=identity.version_label,
        feature_order=list(identity.features),
        label_order=list(identity.labels),
        artifact_content_address=f"sha256:{sha256_file(resolved)}",
        anchored_at=anchored_at,
        hyperparameters=identity.hyperparameters,
        thresholds={
            "class_thresholds": identity.class_thresholds,
            "anchoring_gate": identity.anchoring_gate,
        },
        training_summary=training_summary(),
    )


def save_provenance_record(record: ModelProvenanceRecord, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

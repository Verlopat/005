"""Facts about the deployed detection layer, read from Phase 1 itself.

This module exists so that no file in Phase 2 or Phase 3 ever hard-codes a
claim about the detector. Every such claim (label space, feature order,
calibration method, anchoring gate, reported metrics, dataset) is read from
artefacts Phase 1 actually produced:

* ``Phase_1/outputs/09_model/model_card.json``      - model identity, features,
  labels, hyperparameters, per-class thresholds, gate, test metrics
* ``Phase_1/outputs/10_contract/severity_map.json`` - threat class -> severity
* ``Phase_1/outputs/08_calibration_icr/``           - calibration / ICR evidence

Why this module was added
------------------------
Phase 2 and Phase 3 were originally written against a *different* detector: a
PyTorch binary classifier ("STAHN") trained on CICIoT2023 and reported at
98.62% accuracy. The detection layer of record is the Phase 1 LightGBM
multiclass model trained on NF-CSE-CIC-IDS2018-v2 (macro-F1 0.8172, isotonic
calibrated). Those two describe different architectures, different datasets and
different label spaces, so any figure inherited from the former is not a
statement about this project. Phase 1 is authoritative and is not modified;
Phases 2 and 3 now read from it.

Nothing here invents a value. If Phase 1 has not produced an artefact, the
corresponding accessor raises rather than substituting a default, so a missing
model card can never silently become a published number.
"""
from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

PHASE2_ROOT = Path(__file__).resolve().parent.parent
REPO_ROOT = PHASE2_ROOT.parent
PHASE1_ROOT = REPO_ROOT / "Phase_1"

PHASE1_OUTPUTS = PHASE1_ROOT / "outputs"
MODEL_DIR = PHASE1_OUTPUTS / "09_model"
CONTRACT_DIR = PHASE1_OUTPUTS / "10_contract"
CALIBRATION_DIR = PHASE1_OUTPUTS / "08_calibration_icr"

METRICS_DIR = PHASE1_OUTPUTS / "07_metrics"
METRICS_TABLE_PATH = METRICS_DIR / "metrics_table.csv"

MODEL_CARD_PATH = MODEL_DIR / "model_card.json"
DETECTOR_BUNDLE_PATH = MODEL_DIR / "detector_bundle.joblib"
BOOSTER_PATH = MODEL_DIR / "booster.txt"
SEVERITY_MAP_PATH = CONTRACT_DIR / "severity_map.json"
ALERT_SCHEMA_PATH = CONTRACT_DIR / "alert_schema.json"
SAMPLE_ALERTS_PATH = CONTRACT_DIR / "sample_alerts.jsonl"
HASH_VECTORS_PATH = CONTRACT_DIR / "hash_test_vectors.json"

# The seven coarse threat categories of Phase 1's contract, in the order
# Phase 1 declares them (config.COARSE_CATEGORIES). Asserted against the model
# card's own label order in ``model_identity()`` so the two cannot drift apart.
THREAT_CATEGORIES: tuple[str, ...] = (
    "Benign",
    "DDoS",
    "DoS",
    "Bot",
    "BruteForce",
    "Infiltration",
    "Web Attacks",
)

BENIGN_CATEGORY = "Benign"

#: Phase 1 emits NONE/LOW/MEDIUM/HIGH/CRITICAL; Phase 2's ledger record and
#: schema use lowercase operational severities. This is a pure renaming of the
#: producer's decision - Phase 2 never re-derives severity, so an auditor
#: comparing the two representations sees the same ordering.
SEVERITY_TRANSLATION = {
    "NONE": "informational",
    "LOW": "low",
    "MEDIUM": "medium",
    "HIGH": "high",
    "CRITICAL": "critical",
}

DATASET_NAME = "NF-CSE-CIC-IDS2018-v2"

#: Total NetFlow records in the published dataset, as stated by Phase 1's
#: README/CLAUDE.md and the dataset's distribution page. Recorded here so the
#: on-chain provenance record states the corpus size even when Phase 1's model
#: card omits it (the card reports fold metrics, not corpus totals).
DATASET_RECORD_COUNT = 18_893_708

DATASET_SOURCE_URL = "https://staff.itee.uq.edu.au/marius/NIDS_datasets/"

DATASET_CITATION = (
    "Sarhan, Layeghy & Portmann, 'Towards a Standard Feature Set for Network "
    "Intrusion Detection System Datasets', Mobile Networks and Applications, "
    "2022. https://doi.org/10.1007/s11036-021-01843-0"
)


class DetectionLayerUnavailable(FileNotFoundError):
    """Raised when a required Phase 1 artefact is absent.

    Deliberately a hard error: Phase 2/3 must not fall back to a placeholder
    detector, because a placeholder that reaches a results table is
    indistinguishable from a measurement.
    """


@dataclass(frozen=True)
class ModelIdentity:
    """Identity of the deployed Phase 1 detector, as Phase 1 recorded it."""

    model_id: str
    version_label: str
    variant: str
    architecture: str
    features: tuple[str, ...]
    labels: tuple[str, ...]
    hyperparameters: dict
    class_thresholds: dict
    calibration: str
    dataset: str
    reported_metrics: dict
    anchoring_gate: dict

    @property
    def is_calibrated(self) -> bool:
        """True when Phase 1 documents a fitted calibrator for this artifact.

        Phase 1's model card records ``"isotonic, fitted on the validation
        fold"``. This matters downstream: Objective 3's anchoring gate is a
        probability threshold, and is only interpretable against a calibrated
        score.
        """
        return self.calibration_method != "none"

    @property
    def calibration_method(self) -> str:
        text = str(self.calibration).strip().lower()
        if text.startswith("isotonic"):
            return "isotonic"
        if text.startswith("platt") or "sigmoid" in text:
            return "platt"
        return "none"

    @property
    def expected_calibration_error(self) -> float | None:
        for key in ("expected_calibration_error", "ece"):
            if key in self.reported_metrics:
                return float(self.reported_metrics[key])
        return None

    @property
    def gate_tau(self) -> float:
        if "tau" not in self.anchoring_gate:
            raise DetectionLayerUnavailable(
                f"{MODEL_CARD_PATH} has no anchoring_gate.tau; run Phase 1 stage 08/09 first."
            )
        return float(self.anchoring_gate["tau"])


def _require(path: Path, what: str) -> Path:
    if not path.is_file():
        raise DetectionLayerUnavailable(
            f"Missing {what}: {path}\n"
            "Phase 2/3 read the detection layer from Phase 1's own artefacts. "
            "Run the Phase 1 stages (see Phase_1/README.md) or use the "
            "explicitly-synthetic smoke mode of main.py."
        )
    return path


@lru_cache(maxsize=1)
def load_model_card() -> dict:
    """Phase 1's model card, verbatim."""
    path = _require(MODEL_CARD_PATH, "Phase 1 model card")
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_severity_map() -> dict[str, str]:
    """Phase 1's threat class -> severity mapping, verbatim."""
    path = _require(SEVERITY_MAP_PATH, "Phase 1 severity map")
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def model_identity() -> ModelIdentity:
    """Build the detector identity from Phase 1's model card.

    Also cross-checks the card against this module's declared label space, so a
    Phase 1 retrain that changed the categories fails loudly here instead of
    silently producing alerts Phase 2's schema would reject.
    """
    card = load_model_card()
    labels = tuple(card["labels"])
    unexpected = set(labels) ^ set(THREAT_CATEGORIES)
    if unexpected:
        raise ValueError(
            "Phase 1's label space no longer matches the cross-layer contract. "
            f"Model card labels={labels}, contract categories={THREAT_CATEGORIES}, "
            f"difference={sorted(unexpected)}. Update THREAT_CATEGORIES and the "
            "alert contract enum together, and bump the contract version."
        )

    metrics = dict(card.get("test_metrics", {}))
    calibration_metrics = _calibration_metrics()
    if calibration_metrics:
        metrics.update(calibration_metrics)

    return ModelIdentity(
        model_id=str(card["model_id_sha256"]),
        version_label=str(card["model_version"]),
        variant=str(card.get("variant", "")),
        architecture=str(card.get("architecture", "")),
        features=tuple(card["features"]),
        labels=labels,
        hyperparameters=dict(card.get("hyperparameters", {})),
        class_thresholds=dict(card.get("class_thresholds", {})),
        calibration=str(card.get("calibration", "none")),
        dataset=str(card.get("training", {}).get("dataset", DATASET_NAME)),
        reported_metrics=metrics,
        anchoring_gate=dict(card.get("anchoring_gate", {})),
    )


def _calibration_metrics() -> dict:
    """Expected calibration error from Phase 1 stage 08, when present.

    Read from ``calibration_metrics.csv`` rather than restated, so the ECE that
    justifies treating confidence as a probability is traceable to the run that
    measured it.
    """
    path = CALIBRATION_DIR / "calibration_metrics.csv"
    if not path.is_file():
        return {}
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(lines) < 2:
        return {}
    header = [column.strip().lower() for column in lines[0].split(",")]
    if "ece" not in header:
        return {}
    ece_index = header.index("ece")
    name_index = 0
    best: float | None = None
    for line in lines[1:]:
        cells = line.split(",")
        if len(cells) <= ece_index:
            continue
        method = cells[name_index].strip().lower()
        try:
            value = float(cells[ece_index])
        except ValueError:
            continue
        if "isotonic" in method:
            return {"expected_calibration_error": value}
        best = value if best is None else min(best, value)
    return {"expected_calibration_error": best} if best is not None else {}


def severity_for(threat_category: str) -> str:
    """Phase 2 severity for a Phase 1 threat category.

    Uses Phase 1's severity map as the single source of truth. Note that Phase 1
    rates Infiltration CRITICAL despite its low mean confidence (0.303),
    because a missed post-compromise intrusion costs more than a missed flood;
    Phase 2 must not "correct" that with a confidence-derived severity.
    """
    mapping = load_severity_map()
    if threat_category not in mapping:
        raise KeyError(
            f"Threat category {threat_category!r} is absent from {SEVERITY_MAP_PATH}. "
            f"Known categories: {sorted(mapping)}"
        )
    phase1_severity = mapping[threat_category]
    if phase1_severity not in SEVERITY_TRANSLATION:
        raise ValueError(
            f"Phase 1 emitted severity {phase1_severity!r}, which has no Phase 2 "
            f"equivalent. Known: {sorted(SEVERITY_TRANSLATION)}"
        )
    return SEVERITY_TRANSLATION[phase1_severity]


def verdict_for(threat_category: str) -> str:
    """ATTACK/BENIGN verdict implied by a Phase 1 threat category."""
    return "BENIGN" if threat_category == BENIGN_CATEGORY else "ATTACK"


def training_summary() -> dict:
    """``training_summary`` block for the on-chain model provenance record."""
    identity = model_identity()
    card = load_model_card()
    training = dict(card.get("training", {}))
    record_count = int(training.get("record_count") or DATASET_RECORD_COUNT)
    return {
        "dataset": identity.dataset,
        "record_count": record_count,
        "reported_metrics": {
            **identity.reported_metrics,
            "calibration": identity.calibration,
            "split": training.get("split", ""),
            "benign_downsampling": training.get("benign_downsampling", ""),
            "dataset_source_url": DATASET_SOURCE_URL,
            "dataset_citation": DATASET_CITATION,
        },
    }


@lru_cache(maxsize=1)
def per_class_confidence() -> dict[str, dict[str, float]]:
    '''Per-attack-category support and mean calibrated confidence, from Phase 1.

    Read from ``outputs/08_calibration_icr/icr_per_class.csv``. Support and mean
    confidence are tau-independent, so the first block in the file is used.

    This is what makes Infiltration's difficulty a measured property rather than
    an assertion: Phase 1 records its mean confidence at 0.303 against >0.99 for
    every other attack category.
    '''
    path = CALIBRATION_DIR / 'icr_per_class.csv'
    if not path.is_file():
        return {}
    profile: dict[str, dict[str, float]] = {}
    with path.open(encoding='utf-8', newline='') as stream:
        for row in csv.DictReader(stream):
            name = (row.get('class') or '').strip()
            if not name or name in profile:
                continue
            try:
                profile[name] = {
                    'support': float(row['support']),
                    'mean_confidence': float(row['mean_confidence']),
                }
            except (KeyError, TypeError, ValueError):
                continue
    return profile


def detection_metrics(view: str = 'as_sampled') -> dict:
    '''Full metric row for the deployed variant, from Phase 1 stage 07.

    ``view`` selects between Phase 1's two reporting views:

    ``as_sampled``    - the held-out test fold as evaluated. This is the view
                        Phase 1's model card reports, and the one used for
                        comparison against published results.
    ``natural_prior`` - reweighted to the untouched population prior.

    Returned so a comparison table never restates a detection figure by hand.
    Includes ``FPR``, which the model card omits.
    '''
    if not METRICS_TABLE_PATH.is_file():
        return {}
    identity = model_identity()
    with METRICS_TABLE_PATH.open(encoding='utf-8', newline='') as stream:
        for row in csv.DictReader(stream):
            if row.get('model') == identity.variant and row.get('view') == view:
                metrics: dict = {'model': identity.variant, 'view': view}
                for key, value in row.items():
                    if key in ('model', 'view') or value in (None, ''):
                        continue
                    try:
                        metrics[key] = float(value)
                    except ValueError:
                        continue
                return metrics
    return {}


def has_trained_artifacts() -> bool:
    """True when Phase 1's exported bundle and alert stream are both present."""
    return DETECTOR_BUNDLE_PATH.is_file() and SAMPLE_ALERTS_PATH.is_file()


def artifact_path() -> Path:
    """The Phase 1 artifact whose bytes enter the provenance digest.

    Prefers the exported LightGBM booster text (a stable, inspectable
    serialisation) and falls back to the joblib bundle.
    """
    if BOOSTER_PATH.is_file():
        return BOOSTER_PATH
    return _require(DETECTOR_BUNDLE_PATH, "Phase 1 exported detector")

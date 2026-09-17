"""Event stream generator for scalability, load and stability testing.

Objective 3: "Systematic load testing evaluates performance across simulated
instance counts from 100 to 10,000, arrival rates from 100 to 10,000 events per
second, and varying anomalous-to-normal ratios."

Two sources, one code path
--------------------------
``replay``    - Phase 1's real emitted alerts (``sample_alerts.jsonl``, 9,233
                alerts from the held-out test fold) are replayed, re-tagged with
                a synthetic ``resource_id`` and a fresh ``event_id`` so one
                capture can drive a 10,000-instance profile. Feature vectors,
                categories and calibrated confidences are Phase 1's own.
``synthetic`` - used only when Phase 1's alert stream is absent (it is excluded
                from version control by ``Phase_1/.gitignore``). Alerts are
                generated over Phase 1's real feature names, label space, class
                priors and per-class confidence distributions, all read from
                Phase 1's committed outputs.

Both sources produce *Phase 1-shaped* alerts, digest them with Phase 1's frozen
canonical rules, and then pass them through the same
``build_alert_from_phase1_alert`` adapter the production path uses. Phase 3
therefore exercises the real ingestion path, including cross-layer digest
verification, rather than a parallel one that could drift from it.

Honesty of labelling
--------------------
Synthetic alerts carry a ``version_label`` ending in ``-SYNTHETIC-LOAD`` and a
``detection_contract.producer`` naming this module, so a generated event can
never be mistaken for a measured detection. This generator makes no detection
accuracy claim; it produces *load* with realistic shape.

Earlier revisions read ``Phase1_Submission/CICIoT2023_Sample.csv`` and tagged a
hard category of "Spoofing". Neither exists in this project: that path belonged
to a different detector on a different dataset. The hard category here is
Infiltration, which Phase 1 measures at mean calibrated confidence 0.303.

No load-testing framework (Locust/k6) is installed in this environment; this
module is a lightweight, dependency-free generator sufficient to drive
``perf.scalability_harness`` and ``perf.stability_test`` directly, playing the
role Locust/k6 would play in a distributed deployment.
"""
from __future__ import annotations

import csv
import hashlib
import random
import uuid
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterator

from ._phase2_bridge import PHASE1_ROOT, ensure_phase2_importable

ensure_phase2_importable()

from src.alert_builder import build_alert_from_phase1_alert  # noqa: E402
from src.detection_layer import (  # noqa: E402
    BENIGN_CATEGORY,
    CALIBRATION_DIR,
    MODEL_DIR,
    SAMPLE_ALERTS_PATH,
    THREAT_CATEGORIES,
    load_model_card,
    load_severity_map,
)
from src.phase1_contract import (  # noqa: E402
    PHASE1_SCHEMA_VERSION,
    event_hash,
    feature_digest,
    load_alerts,
)

#: Phase 1's hardest category: mean calibrated confidence 0.303 on the held-out
#: fold (outputs/08_calibration_icr/icr_per_class.csv). Exercising it is what
#: makes the class-aware gate flooring in Phase 2's anchoring policy measurable.
HARD_CATEGORY = "Infiltration"

#: Natural benign prior of Phase 1's held-out test fold (Phase_1/README.md:
#: "held-out test fold, 3,778,631 records, natural 88% benign prior").
DEFAULT_BENIGN_SHARE = 0.88

SYNTHETIC_VERSION_SUFFIX = "-SYNTHETIC-LOAD"

FEATURE_STATS_PATH = MODEL_DIR / "feature_stats.csv"
ICR_PER_CLASS_PATH = CALIBRATION_DIR / "icr_per_class.csv"


@dataclass
class LoadProfile:
    num_instances: int
    arrival_rate_eps: float  # aggregate events/sec across all simulated instances
    anomalous_ratio: float | None = None  # None = use Phase 1's natural prior

    def __post_init__(self) -> None:
        if self.num_instances < 1:
            raise ValueError("num_instances must be >= 1")
        if self.anomalous_ratio is not None and not 0.0 <= self.anomalous_ratio <= 1.0:
            raise ValueError("anomalous_ratio must be in [0, 1]")


@lru_cache(maxsize=1)
def _feature_stats() -> dict[str, dict[str, float]]:
    """Per-feature median/p05/p95 from Phase 1's exported statistics.

    Used to give synthetic feature vectors realistic magnitudes. Falls back to a
    unit range only if Phase 1 has not exported the file.
    """
    if not FEATURE_STATS_PATH.is_file():
        return {}
    stats: dict[str, dict[str, float]] = {}
    with FEATURE_STATS_PATH.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        name_field = reader.fieldnames[0] if reader.fieldnames else ""
        for row in reader:
            name = row.get(name_field) or ""
            if not name:
                continue

            def number(key: str, default: float) -> float:
                try:
                    return float(row.get(key, default))
                except (TypeError, ValueError):
                    return default

            median = number("median", 0.0)
            stats[name] = {
                "median": median,
                "p05": number("p05", median),
                "p95": number("p95", median),
            }
    return stats


@lru_cache(maxsize=1)
def _class_profile() -> dict[str, dict[str, float]]:
    """Per-attack-category support and mean calibrated confidence from Phase 1.

    Read from ``icr_per_class.csv`` so the synthetic class mix reproduces the
    measured class imbalance and the measured confidence spread rather than an
    invented one. The file lists one block per tau; the first block is used, as
    support and mean confidence are tau-independent.
    """
    if not ICR_PER_CLASS_PATH.is_file():
        return {}
    profile: dict[str, dict[str, float]] = {}
    with ICR_PER_CLASS_PATH.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            name = (row.get("class") or "").strip()
            if not name or name in profile:
                continue
            try:
                profile[name] = {
                    "support": float(row["support"]),
                    "mean_confidence": float(row["mean_confidence"]),
                }
            except (KeyError, TypeError, ValueError):
                continue
    return profile


class Phase1AlertStream:
    """Draws Phase 1-shaped alerts and adapts them to the Objective 2 contract.

    ``source`` is ``"replay"`` when Phase 1's emitted alerts are available and
    ``"synthetic"`` otherwise; the attribute is exposed so every results file can
    state which one produced its numbers.
    """

    def __init__(
        self,
        profile: LoadProfile,
        model_digest: str = "0" * 64,
        model_id: str = "phase3-load-generator",
        seed: int = 1234,
        prefer_replay: bool = True,
    ):
        self.profile = profile
        self.model_digest = model_digest
        self.model_id = model_id
        self._rng = random.Random(seed)
        self._counter = 0

        card = load_model_card()
        self._features: list[str] = list(card["features"])
        self._version_label: str = str(card["model_version"])
        self._severity_map = load_severity_map()

        self._replay_pool: list[dict] = []
        if prefer_replay and SAMPLE_ALERTS_PATH.is_file():
            self._replay_pool = load_alerts(SAMPLE_ALERTS_PATH)
        self.source = "replay" if self._replay_pool else "synthetic"

        if self.source == "replay":
            self._benign_pool = [a for a in self._replay_pool if a["threat_class"] == BENIGN_CATEGORY]
            self._attack_pool = [a for a in self._replay_pool if a["threat_class"] != BENIGN_CATEGORY]
        else:
            self._benign_pool = []
            self._attack_pool = []
            self._attack_categories, self._attack_weights = self._synthetic_class_mix()

    # -- synthetic construction ------------------------------------------------

    def _synthetic_class_mix(self) -> tuple[list[str], list[float]]:
        profile = _class_profile()
        categories = [c for c in THREAT_CATEGORIES if c != BENIGN_CATEGORY]
        weights = [profile.get(c, {}).get("support", 1.0) for c in categories]
        if not any(weights):
            weights = [1.0] * len(categories)
        return categories, weights

    def _synthetic_confidence(self, category: str) -> float:
        """Confidence drawn around Phase 1's measured per-class mean.

        Benign flows are given a low P(attack); attack categories are centred on
        the mean confidence Phase 1 measured for that category, so Infiltration
        remains the hard, low-confidence class it actually is.
        """
        profile = _class_profile()
        if category == BENIGN_CATEGORY:
            return round(min(max(self._rng.betavariate(1.0, 40.0), 0.0), 1.0), 6)
        mean = profile.get(category, {}).get("mean_confidence", 0.95)
        spread = 0.15 if category == HARD_CATEGORY else 0.01
        value = self._rng.gauss(mean, spread)
        return round(min(max(value, 0.0), 1.0), 6)

    def _synthetic_features(self) -> dict[str, float]:
        stats = _feature_stats()
        values: dict[str, float] = {}
        for name in self._features:
            entry = stats.get(name)
            if entry is None:
                values[name] = round(self._rng.random(), 6)
                continue
            low, high = entry["p05"], entry["p95"]
            if high < low:
                low, high = high, low
            if high == low:
                values[name] = round(entry["median"], 6)
            else:
                values[name] = round(self._rng.uniform(low, high), 6)
        return values

    def _synthetic_alert(self, index: int, category: str) -> dict:
        confidence = self._synthetic_confidence(category)
        features = self._synthetic_features()
        alert = {
            "event_id": str(uuid.uuid5(uuid.NAMESPACE_URL, f"phase3-load/{index}")),
            "schema_version": PHASE1_SCHEMA_VERSION,
            "timestamp": "2026-01-01T00:00:00.000Z",
            "verdict": "NORMAL" if category == BENIGN_CATEGORY else "ANOMALY",
            "threat_class": category,
            "severity": self._severity_map[category],
            "confidence": confidence,
            "model_version": f"{self._version_label}{SYNTHETIC_VERSION_SUFFIX}",
            "src_ip": None,
            "src_port": None,
            "dst_ip": None,
            "dst_port": None,
            "cloud_resource_id": self._resource_id(index),
            "features": features,
            "feature_digest": feature_digest(features),
            "anchor": category != BENIGN_CATEGORY,
            "anchor_gate_tau": 0.0,
            "inference_latency_ms": 0.0,
        }
        alert["event_hash"] = event_hash(alert)
        return alert

    # -- replay construction ---------------------------------------------------

    def _replayed_alert(self, index: int, category_is_attack: bool | None) -> dict:
        if category_is_attack is None:
            pool = self._replay_pool
        elif category_is_attack:
            pool = self._attack_pool or self._replay_pool
        else:
            pool = self._benign_pool or self._replay_pool
        original = dict(self._rng.choice(pool))

        # Re-tag identity and placement so one capture can drive many simulated
        # instances. The feature vector, category and calibrated confidence are
        # Phase 1's own and are never altered; the digest is recomputed because
        # event_id and cloud_resource_id are inside Phase 1's digest scope.
        original["event_id"] = str(uuid.uuid5(uuid.NAMESPACE_URL, f"phase3-replay/{index}"))
        original["cloud_resource_id"] = self._resource_id(index)
        original["event_hash"] = event_hash(original)
        return original

    def _resource_id(self, index: int) -> str:
        return f"i-load-{index % self.profile.num_instances:06d}"

    # -- public API ------------------------------------------------------------

    def next_phase1_alert(self) -> dict:
        """One Phase 1-shaped alert, honouring the profile's class mix."""
        self._counter += 1
        index = self._counter

        if self.profile.anomalous_ratio is not None:
            is_attack = self._rng.random() < self.profile.anomalous_ratio
        else:
            is_attack = self._rng.random() >= DEFAULT_BENIGN_SHARE

        if self.source == "replay":
            return self._replayed_alert(index, is_attack)

        if is_attack:
            category = self._rng.choices(self._attack_categories, weights=self._attack_weights, k=1)[0]
        else:
            category = BENIGN_CATEGORY
        return self._synthetic_alert(index, category)

    def next_event(self) -> dict:
        """One Objective 2 contract event, built through the production adapter."""
        alert = self.next_phase1_alert()
        event = build_alert_from_phase1_alert(
            alert,
            model_id=self.model_id,
            model_digest=self.model_digest,
        )
        event["detection_contract"]["producer"] = (
            f"Phase3_Performance_Optimization/perf/load_generator.py ({self.source})"
        )
        # payload_digest covers detection_contract, so it must be recomputed
        # after the producer field is stamped.
        from src.digest import digest_event  # local import keeps module import cheap

        event.pop("payload_digest", None)
        event["payload_digest"] = digest_event(event)
        return event

    def iter_events(self, n: int) -> Iterator[dict]:
        for _ in range(n):
            yield self.next_event()

    def inter_arrival_delay_sec(self) -> float:
        """One inter-arrival gap from an exponential distribution.

        The Poisson-process model is the standard one for an aggregate stream of
        independent per-instance arrivals.
        """
        rate = max(self.profile.arrival_rate_eps, 1e-6)
        return self._rng.expovariate(rate)

    def describe_source(self) -> dict:
        """Provenance block for a results file."""
        return {
            "source": self.source,
            "phase1_alerts_path": str(SAMPLE_ALERTS_PATH) if self.source == "replay" else None,
            "replay_pool_size": len(self._replay_pool) or None,
            "model_version": self._version_label
            + ("" if self.source == "replay" else SYNTHETIC_VERSION_SUFFIX),
            "feature_count": len(self._features),
            "label_space": list(THREAT_CATEGORIES),
            "hard_category": HARD_CATEGORY,
            "benign_share": (
                self.profile.anomalous_ratio is None and DEFAULT_BENIGN_SHARE
            )
            or (1.0 - (self.profile.anomalous_ratio or 0.0)),
            "makes_detection_accuracy_claim": False,
        }


#: Backwards-compatible alias. The previous name described a CICIoT2023 row
#: sampler; the class above supersedes it.
SyntheticEventStream = Phase1AlertStream


def digest_of_stream(events: list[dict]) -> str:
    """Stable digest over a generated event sequence, for reproducibility."""
    hasher = hashlib.sha256()
    for event in events:
        hasher.update(event["payload_digest"].encode("utf-8"))
    return hasher.hexdigest()

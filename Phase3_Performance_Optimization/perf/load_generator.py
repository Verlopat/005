"""Synthetic event stream generator for scalability/load testing.

Objective 3: "Systematic load testing evaluates performance across
simulated instance counts from 100 to 10,000, arrival rates from 100 to
10,000 events per second, and varying anomalous-to-normal ratios."

This generates contract-conformant alert events (reusing
`Phase2_Blockchain_Logging/src/alert_builder.py`) built from real
`CICIoT2023_Sample.csv` rows, tagged with a synthetic `resource_id` drawn
uniformly from `num_instances` simulated cloud instances, at a target
aggregate arrival rate modelled as a Poisson process — the standard
arrival model for aggregating many independent per-instance event streams
(consistent with MBID's device-transmission model cited in
docs/comparative_benchmark.md).

No load-testing framework (Locust/k6) is installed in this sandbox; this
module is a lightweight, dependency-free generator sufficient to drive
`perf.scalability_harness` and `perf.stability_test` directly. It plays
the same role Locust/k6 would play in a distributed deployment.
"""
from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass
from typing import Iterator

import pandas as pd

from ._phase2_bridge import PHASE1_ROOT, ensure_phase2_importable

ensure_phase2_importable()

from src.alert_builder import build_alert_from_oracle_response  # noqa: E402

SAMPLE_CSV = PHASE1_ROOT / "CICIoT2023_Sample.csv"
HARD_CATEGORY = "Spoofing"  # see Phase2_Blockchain_Logging/scripts/generate_phase2_results.py


@dataclass
class LoadProfile:
    num_instances: int
    arrival_rate_eps: float  # aggregate events/sec across all simulated instances
    anomalous_ratio: float | None = None  # None = use the sample's natural ratio


def _confidence_for(is_attack: bool, attack_class: str | None, noise: float) -> float:
    if not is_attack:
        return round(min(0.85 + noise * 0.149, 0.999), 4)
    if attack_class == HARD_CATEGORY:
        return round(min(0.25 + noise * 0.40, 0.999), 4)
    return round(min(0.95 + noise * 0.049, 0.999), 4)


class SyntheticEventStream:
    """Draws rows (with replacement) from the real sample CSV and tags each
    with a synthetic resource_id in [0, num_instances), so a single 50,000
    row dataset can drive a 10,000-simulated-instance load profile without
    needing 10,000x the raw capture data."""

    def __init__(self, profile: LoadProfile, model_digest: str = "0" * 64, seed: int = 1234):
        self.profile = profile
        self.model_digest = model_digest
        self._rng = random.Random(seed)
        self._df = pd.read_csv(SAMPLE_CSV)
        label_col = "label" if "label" in self._df.columns else "Label"
        self._label_col = label_col
        self._feature_cols = [c for c in self._df.columns if c not in ("label", "Label", "attack_class")]

        if profile.anomalous_ratio is not None:
            attacks = self._df[self._df[label_col] == 1]
            benign = self._df[self._df[label_col] == 0]
            self._attack_rows = attacks.to_dict("records") if len(attacks) else []
            self._benign_rows = benign.to_dict("records") if len(benign) else []
        else:
            self._attack_rows = None
            self._benign_rows = None
        self._all_rows = self._df.to_dict("records")
        self._counter = 0

    def _next_row(self) -> dict:
        if self.profile.anomalous_ratio is not None and self._attack_rows and self._benign_rows:
            if self._rng.random() < self.profile.anomalous_ratio:
                return self._rng.choice(self._attack_rows)
            return self._rng.choice(self._benign_rows)
        return self._rng.choice(self._all_rows)

    def next_event(self) -> dict:
        row = self._next_row()
        self._counter += 1
        idx = self._counter
        features = [float(row[c]) for c in self._feature_cols]
        true_label = int(row[self._label_col]) if str(row[self._label_col]).strip().lstrip("-").isdigit() else (
            0 if str(row[self._label_col]) == "BenignTraffic" else 1
        )
        is_attack = bool(true_label == 1)
        raw_category = row.get("attack_class")
        h = int(hashlib.sha256(f"synthetic-{idx}".encode()).hexdigest(), 16)
        noise = (h % 1000) / 1000.0
        confidence = _confidence_for(is_attack, raw_category if is_attack else None, noise)
        category = raw_category if (is_attack and raw_category not in (None, "Benign")) else None

        resource_id = f"i-load-{idx % self.profile.num_instances:06d}"
        oracle_response = {
            "is_attack": is_attack,
            "confidence_score": confidence,
            "model_version": "stahn_v1_98.62_acc-SYNTHETIC-LOAD",
        }
        return build_alert_from_oracle_response(
            oracle_response=oracle_response,
            feature_names=self._feature_cols,
            feature_values=features,
            model_id="stahn-phase1",
            model_digest=self.model_digest,
            resource_id=resource_id,
            inference_latency_ms=0.3,
            threat_category=category,
            event_id=f"load-{idx:012d}",
        )

    def iter_events(self, n: int) -> Iterator[dict]:
        for _ in range(n):
            yield self.next_event()

    def inter_arrival_delay_sec(self) -> float:
        """Draws one inter-arrival gap from an exponential distribution
        with rate `arrival_rate_eps`, the standard Poisson-process model for
        an aggregate stream of independent arrivals."""
        rate = max(self.profile.arrival_rate_eps, 1e-6)
        return self._rng.expovariate(rate)

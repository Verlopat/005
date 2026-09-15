"""Calibrated, confidence-gated anchoring policy.

Objective 1 introduces Integrity Coverage Ratio and a calibrated confidence
gate; Objective 2's amendment records Merkle batching as a throughput
dependency of anchoring at the measured 11.43% gate rate; Objective 3 adds
class-aware gate flooring so that low-confidence-but-real categories (the
docx measures Infiltration at mean confidence 0.303) are not silently
excluded by a single global threshold. This module implements the policy
surface that Objective 2 depends on and that Objective 3 will tune further;
gate values here are configuration, not hard-coded, matching
config/anchoring-policy.example.yaml.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class AnchoringDecision(str, Enum):
    IMMEDIATE = "immediate"  # anchor now, on its own transaction
    BATCH = "batch"  # aggregate into the next Merkle batch window
    OFF_CHAIN_ONLY = "off_chain_only"  # store evidence, do not anchor


@dataclass(frozen=True)
class AnchoringPolicy:
    anchor_attack_only: bool = True
    confidence_threshold: float = 0.0
    category_thresholds: dict[str, float] = None  # type: ignore[assignment]
    immediate_confidence_threshold: float = 0.99
    severity_by_threat: dict[str, str] = None  # type: ignore[assignment]

    def __post_init__(self):
        if self.category_thresholds is None:
            object.__setattr__(self, "category_thresholds", {})
        if self.severity_by_threat is None:
            object.__setattr__(self, "severity_by_threat", {"ATTACK": "high", "BENIGN": "informational"})

    @classmethod
    def from_dict(cls, raw: dict) -> "AnchoringPolicy":
        return cls(
            anchor_attack_only=bool(raw.get("anchor_attack_only", True)),
            confidence_threshold=float(raw.get("confidence_threshold", 0.0)),
            category_thresholds=dict(raw.get("category_thresholds", {}) or {}),
            immediate_confidence_threshold=float(raw.get("immediate_confidence_threshold", 0.99)),
            severity_by_threat=dict(raw.get("severity_by_threat", {}) or {}),
        )

    def gate_for(self, threat_category: str) -> float:
        """Per-category threshold overrides the global threshold when set
        (config/anchoring-policy.example.yaml: 'A category-specific
        threshold takes precedence over the global confidence threshold
        when it is configured')."""
        return self.category_thresholds.get(threat_category, self.confidence_threshold)

    def decide(self, event: dict) -> AnchoringDecision:
        verdict = event["verdict"]
        confidence = event["calibrated_confidence"]
        category = event["threat_category"]

        if self.anchor_attack_only and verdict != "ATTACK":
            return AnchoringDecision.OFF_CHAIN_ONLY

        gate = self.gate_for(category)
        if confidence < gate:
            return AnchoringDecision.OFF_CHAIN_ONLY

        if confidence >= self.immediate_confidence_threshold:
            return AnchoringDecision.IMMEDIATE
        return AnchoringDecision.BATCH


def integrity_coverage_ratio(events: list[dict], gate: float, true_attack_key: str = "verdict") -> dict:
    """Compute the Integrity Coverage Ratio at ``gate`` per Objective 1/3.

    ICR(gate) = (# true attack flows with calibrated_confidence >= gate)
                / (# true attack flows)

    reported alongside on-chain volume = (# flows with confidence >= gate)
    / (# total flows), so the trade-off between evidentiary completeness
    and ledger cost is visible in one call. This is a diagnostic used by
    the anchoring-policy tuning workflow (Objective 3), included in Phase 2
    so the policy above can be evaluated against real event batches rather
    than tuned blind.
    """
    attacks = [e for e in events if e[true_attack_key] == "ATTACK"]
    total = len(events)
    if not attacks:
        return {"gate": gate, "integrity_coverage_ratio": None, "on_chain_volume": 0.0, "attack_count": 0}
    covered = sum(1 for e in attacks if e["calibrated_confidence"] >= gate)
    anchored_total = sum(1 for e in events if e["calibrated_confidence"] >= gate)
    return {
        "gate": gate,
        "integrity_coverage_ratio": covered / len(attacks),
        "on_chain_volume": anchored_total / total if total else 0.0,
        "attack_count": len(attacks),
    }

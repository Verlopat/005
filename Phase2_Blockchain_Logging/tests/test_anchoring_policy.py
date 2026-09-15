from src.anchoring_policy import AnchoringDecision, AnchoringPolicy, integrity_coverage_ratio


def make_event(verdict, category, confidence):
    return {"verdict": verdict, "threat_category": category, "calibrated_confidence": confidence}


def test_benign_is_off_chain_only_by_default():
    policy = AnchoringPolicy.from_dict({"anchor_attack_only": True})
    decision = policy.decide(make_event("BENIGN", "BENIGN", 0.99))
    assert decision == AnchoringDecision.OFF_CHAIN_ONLY


def test_high_confidence_attack_is_immediate():
    policy = AnchoringPolicy.from_dict({"anchor_attack_only": True, "confidence_threshold": 0.5})
    decision = policy.decide(make_event("ATTACK", "DDoS", 0.995))
    assert decision == AnchoringDecision.IMMEDIATE


def test_medium_confidence_attack_is_batched():
    policy = AnchoringPolicy.from_dict({"anchor_attack_only": True, "confidence_threshold": 0.5})
    decision = policy.decide(make_event("ATTACK", "DDoS", 0.8))
    assert decision == AnchoringDecision.BATCH


def test_below_gate_attack_is_off_chain_only():
    policy = AnchoringPolicy.from_dict({"anchor_attack_only": True, "confidence_threshold": 0.9})
    decision = policy.decide(make_event("ATTACK", "DDoS", 0.5))
    assert decision == AnchoringDecision.OFF_CHAIN_ONLY


def test_category_threshold_overrides_global_threshold():
    # Infiltration mean confidence is measured at 0.303 in the docx; a
    # per-category floor lets it clear the gate where the global
    # threshold would exclude it almost entirely.
    policy = AnchoringPolicy.from_dict(
        {"anchor_attack_only": True, "confidence_threshold": 0.9, "category_thresholds": {"Infiltration": 0.2}}
    )
    decision = policy.decide(make_event("ATTACK", "Infiltration", 0.3))
    assert decision != AnchoringDecision.OFF_CHAIN_ONLY


def test_integrity_coverage_ratio_matches_measured_operating_point():
    events = []
    for i in range(100):
        is_attack = i < 50
        # Roughly emulate the docx's measured 95.68% ICR at ~11.43% on-chain volume.
        confidence = 0.99 if (is_attack and i < 48) else (0.3 if is_attack else 0.05)
        events.append(make_event("ATTACK" if is_attack else "BENIGN", "DDoS" if is_attack else "BENIGN", confidence))
    result = integrity_coverage_ratio(events, gate=0.9)
    assert result["attack_count"] == 50
    assert abs(result["integrity_coverage_ratio"] - 0.96) < 1e-9
    assert result["on_chain_volume"] == 0.48


def test_integrity_coverage_ratio_with_no_attacks_returns_none():
    events = [make_event("BENIGN", "BENIGN", 0.99) for _ in range(5)]
    result = integrity_coverage_ratio(events, gate=0.9)
    assert result["integrity_coverage_ratio"] is None

from perf.load_generator import LoadProfile, SyntheticEventStream


def test_generates_schema_conformant_events():
    import json
    from pathlib import Path

    import jsonschema

    from perf._phase2_bridge import PHASE2_ROOT

    schema = json.loads((PHASE2_ROOT / "contracts" / "alert_event.schema.json").read_text(encoding="utf-8"))
    stream = SyntheticEventStream(LoadProfile(num_instances=50, arrival_rate_eps=10))
    for event in stream.iter_events(20):
        jsonschema.validate(instance=event, schema=schema)


def test_resource_ids_bounded_by_num_instances():
    stream = SyntheticEventStream(LoadProfile(num_instances=10, arrival_rate_eps=10))
    resource_ids = {e["resource_id"] for e in stream.iter_events(200)}
    assert len(resource_ids) <= 10


def test_deterministic_with_fixed_seed():
    s1 = SyntheticEventStream(LoadProfile(num_instances=100, arrival_rate_eps=10), seed=99)
    s2 = SyntheticEventStream(LoadProfile(num_instances=100, arrival_rate_eps=10), seed=99)
    events1 = [e["verdict"] for e in s1.iter_events(30)]
    events2 = [e["verdict"] for e in s2.iter_events(30)]
    assert events1 == events2


def test_anomalous_ratio_is_approximately_honoured():
    stream = SyntheticEventStream(LoadProfile(num_instances=100, arrival_rate_eps=10, anomalous_ratio=0.8), seed=5)
    events = list(stream.iter_events(500))
    attack_fraction = sum(1 for e in events if e["verdict"] == "ATTACK") / len(events)
    assert 0.65 < attack_fraction < 0.95  # loose bounds; exact ratio depends on draw-with-replacement sampling


def test_inter_arrival_delay_is_positive_and_scales_with_rate():
    slow = SyntheticEventStream(LoadProfile(num_instances=10, arrival_rate_eps=10), seed=1)
    fast = SyntheticEventStream(LoadProfile(num_instances=10, arrival_rate_eps=1000), seed=1)
    slow_samples = [slow.inter_arrival_delay_sec() for _ in range(200)]
    fast_samples = [fast.inter_arrival_delay_sec() for _ in range(200)]
    assert all(d >= 0 for d in slow_samples + fast_samples)
    assert (sum(slow_samples) / len(slow_samples)) > (sum(fast_samples) / len(fast_samples))

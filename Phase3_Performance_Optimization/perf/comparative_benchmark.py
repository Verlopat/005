"""Comparative benchmarking against existing solutions.

Objective 3: "The integrated framework is benchmarked against three
categories of prior work: standalone machine learning intrusion detection
without blockchain, blockchain-only logging without detection, and
published hybrid frameworks. Comparative metrics span detection accuracy,
false positive rate, end-to-end latency, storage overhead and resource
consumption. Comparison is conducted under matched evaluation protocol
wherever the source publication reports sufficient methodological detail,
and protocol differences are stated explicitly where it does not."

This module holds the literature figures used for that comparison (each
with its source URL — see `SOURCES` and every entry's `source` key) and a
function that assembles the comparison table against this project's own
measured Phase 1 (detection) and Phase 2 (logging) figures. Every entry
below is a number reported in the cited publication itself, not an
estimate; where a paper did not report a given metric, the field is
`None` and the table renders "not reported" rather than a fabricated
value.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Citation:
    label: str
    url: str
    note: str = ""


SOURCES = {
    "cic_iot2023_origin": Citation(
        label="Neto et al., \"CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment\", Sensors 23(13):5941, 2023",
        url="https://www.mdpi.com/1424-8220/23/13/5941",
        note="Origin paper of the dataset used by this project's Phase 1 STAHN model; binary-classification baselines reported here are the most directly comparable standalone-ML figures available.",
    ),
    "fabric_perf_model_2025": Citation(
        label="\"Performance Modeling and Evaluation of Hyperledger Fabric\", arXiv:2502.08755, 2025",
        url="https://arxiv.org/html/2502.08755v1",
        note="Real-system measurement on a basic Fabric 2.5 network (1 peer-org config, Docker), 4-core/8GB host.",
    ),
    "fabric_dlps_2021": Citation(
        label="\"An In-Depth Investigation of Performance Characteristics of Hyperledger Fabric\", arXiv:2102.07731, 2021",
        url="https://arxiv.org/pdf/2102.07731v1",
        note="Large-scale DLPS study: ~2,000 hours, ~1,500 Fabric networks, >200M transactions, AWS m5.large (2 vCPU/8GiB) nodes.",
    ),
    "smartsecchain_sdn_2025": Citation(
        label="\"SmartSecChain-SDN: A Blockchain-Integrated Intelligent Framework...\", arXiv:2511.05156, 2025",
        url="https://arxiv.org/pdf/2511.05156",
        note="Hybrid ML+blockchain IDS for SDN, evaluated on the InSDN dataset via Mininet/OVS/Ryu simulation with a 2-peer Hyperledger Fabric network.",
    ),
    "mbid_2025": Citation(
        label="\"MBID: A Scalable Multi-Tier Blockchain Architecture with Physics-Informed...\", Computer Modeling in Engineering & Sciences 144(2), 2025",
        url="https://www.techscience.com/CMES/v144n2/63732/html",
        note="Hybrid ML+blockchain IDS for IoT, evaluated on BoT-IoT and CICIoT2023 via a simulated 1,000-device, 10-edge-gateway, 3-shard fog deployment.",
    ),
    "ml_blockchain_framework_informatica_2025": Citation(
        label="\"A Machine Learning and Blockchain-Based Framework for...\", Informatica, 2025",
        url="https://www.informatica.si/index.php/informatica/article/view/9421/5823",
        note="Hybrid ML+blockchain logging framework evaluated on CSE-CIC-IDS2018 with a private PoA Ganache blockchain, 5-node virtualised environment.",
    ),
}


@dataclass(frozen=True)
class BenchmarkRow:
    system: str
    category: str  # "standalone_ml", "blockchain_only", "hybrid_published", "this_framework"
    detection_accuracy: float | None
    false_positive_rate_pct: float | None
    f1_score: float | None
    end_to_end_latency_ms: float | None
    tx_or_commit_latency_ms: float | None
    storage_overhead_note: str | None
    source: str | None  # key into SOURCES, or None for this project's own measured figures


def literature_rows() -> list[BenchmarkRow]:
    return [
        # --- Category 1: standalone ML intrusion detection, no blockchain ---
        BenchmarkRow(
            system="Random Forest, binary (CICIoT2023 origin paper)",
            category="standalone_ml",
            detection_accuracy=0.99680798,
            false_positive_rate_pct=None,
            f1_score=0.965279544,
            end_to_end_latency_ms=None,
            tx_or_commit_latency_ms=None,
            storage_overhead_note="n/a (no blockchain component)",
            source="cic_iot2023_origin",
        ),
        BenchmarkRow(
            system="Deep Neural Network, binary (CICIoT2023 origin paper)",
            category="standalone_ml",
            detection_accuracy=0.994422814,
            false_positive_rate_pct=None,
            f1_score=0.940305998,
            end_to_end_latency_ms=None,
            tx_or_commit_latency_ms=None,
            storage_overhead_note="n/a (no blockchain component)",
            source="cic_iot2023_origin",
        ),
        # --- Category 2: blockchain-only logging, no detection ---
        BenchmarkRow(
            system="Hyperledger Fabric 2.5, basic network, asset-creation tx (arXiv:2502.08755)",
            category="blockchain_only",
            detection_accuracy=None,
            false_positive_rate_pct=None,
            f1_score=None,
            end_to_end_latency_ms=None,
            tx_or_commit_latency_ms=1110.0,  # at 10 tps arrival; rises to 20,000 ms at 100 tps unbatched
            storage_overhead_note="not reported (per-event); illustrates unbatched-commit latency blow-up motivating this project's Merkle batching",
            source="fabric_perf_model_2025",
        ),
        BenchmarkRow(
            system="Hyperledger Fabric 2.0, DLPS large-scale study, LevelDB (arXiv:2102.07731)",
            category="blockchain_only",
            detection_accuracy=None,
            false_positive_rate_pct=None,
            f1_score=None,
            end_to_end_latency_ms=None,
            tx_or_commit_latency_ms=None,
            storage_overhead_note="~750 simple reads/s/peer (LevelDB) vs ~400 (CouchDB); LevelDB ~3x write throughput of CouchDB",
            source="fabric_dlps_2021",
        ),
        # --- Category 3: published hybrid ML + blockchain frameworks ---
        BenchmarkRow(
            system="SmartSecChain-SDN (InSDN dataset)",
            category="hybrid_published",
            detection_accuracy=0.9743,
            false_positive_rate_pct=1.82,
            f1_score=None,
            end_to_end_latency_ms=42.3,
            tx_or_commit_latency_ms=134.2,  # at 10 tx/block; 228.4 ms at 300 tx/block
            storage_overhead_note="not reported (per-event)",
            source="smartsecchain_sdn_2025",
        ),
        BenchmarkRow(
            system="MBID (BoT-IoT / CICIoT2023, simulated 1,000-device fog deployment)",
            category="hybrid_published",
            detection_accuracy=0.9984,
            false_positive_rate_pct=0.01,
            f1_score=0.9984,
            end_to_end_latency_ms=200.0,  # "under 200 ms" typical; worst-case full-consensus up to 5,100 ms
            tx_or_commit_latency_ms=0.40,  # edge event -> validated fog block
            storage_overhead_note=">80% projected storage reduction via IPFS off-chain placement",
            source="mbid_2025",
        ),
        BenchmarkRow(
            system="ML + PoA blockchain logging framework (CSE-CIC-IDS2018, XGBoost)",
            category="hybrid_published",
            detection_accuracy=0.98,
            false_positive_rate_pct=None,
            f1_score=0.98,  # weighted-average F1; macro-average F1 was 0.78
            end_to_end_latency_ms=None,
            tx_or_commit_latency_ms=324.0,
            storage_overhead_note="not reported; 100% tamper-hash detection rate reported instead",
            source="ml_blockchain_framework_informatica_2025",
        ),
    ]


def this_framework_row(
    phase1_accuracy: float,
    phase1_attack_precision: float,
    phase2_results: dict,
) -> BenchmarkRow:
    """Builds the comparison row for this project's own measured figures,
    combining Phase 1's reported test metrics (handoff document) with
    Phase 2's measured logging figures (Phase2_Blockchain_Logging/outputs/phase2_results.json),
    so the comparison table's own-framework row is never hand-typed
    separately from what those two phases actually measured."""
    integrity = phase2_results.get("integrity", {})
    storage = phase2_results.get("storage", {})
    bench = phase2_results.get("benchmark", {})
    return BenchmarkRow(
        system="This framework (STAHN detection + blockchain evidence logging, Phase 1 + Phase 2)",
        category="this_framework",
        detection_accuracy=phase1_accuracy,
        false_positive_rate_pct=None,  # Phase 1 handoff reports attack precision/benign recall, not an aggregate FPR
        f1_score=None,
        end_to_end_latency_ms=bench.get("latency_ms_p95"),  # software-layer only; see Phase 2 report caveats
        tx_or_commit_latency_ms=bench.get("latency_ms_p95"),
        storage_overhead_note=(
            f"{storage.get('reduction_pct', float('nan')):.1f}% on-chain size reduction vs full payload "
            f"(mean on-chain record {storage.get('on_chain_bytes_mean', float('nan')):.0f} bytes); "
            f"integrity verification failure rate {integrity.get('failure_rate_pct', float('nan')):.2f}%"
        ),
        source=None,
    )


def format_table(rows: list[BenchmarkRow]) -> str:
    header = "| System | Category | Detection accuracy | FPR (%) | F1 | End-to-end latency (ms) | Tx/commit latency (ms) | Storage overhead | Source |"
    sep = "|---|---|---|---|---|---|---|---|---|"
    lines = [header, sep]
    for r in rows:
        source_cell = "this project (measured)" if r.source is None else f"[{SOURCES[r.source].label}]({SOURCES[r.source].url})"
        lines.append(
            "| {system} | {category} | {acc} | {fpr} | {f1} | {e2e} | {tx} | {storage} | {source} |".format(
                system=r.system,
                category=r.category,
                acc=f"{r.detection_accuracy:.4f}" if r.detection_accuracy is not None else "not reported",
                fpr=f"{r.false_positive_rate_pct:.2f}" if r.false_positive_rate_pct is not None else "not reported",
                f1=f"{r.f1_score:.4f}" if r.f1_score is not None else "not reported",
                e2e=f"{r.end_to_end_latency_ms:.1f}" if r.end_to_end_latency_ms is not None else "not reported",
                tx=f"{r.tx_or_commit_latency_ms:.2f}" if r.tx_or_commit_latency_ms is not None else "not reported",
                storage=r.storage_overhead_note or "not reported",
                source=source_cell,
            )
        )
    return "\n".join(lines)

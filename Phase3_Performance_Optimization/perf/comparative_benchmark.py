"""Comparative benchmarking against existing solutions.

Objective 3: "The integrated framework is benchmarked against three categories
of prior work: standalone machine learning intrusion detection without
blockchain, blockchain-only logging without detection, and published hybrid
frameworks. Comparative metrics span detection accuracy, false positive rate,
end-to-end latency, storage overhead and resource consumption. Comparison is
conducted under matched evaluation protocol wherever the source publication
reports sufficient methodological detail, and protocol differences are stated
explicitly where it does not."

Every literature figure below is a number reported in the cited publication
itself, not an estimate. Where a paper did not report a metric the field is
``None`` and the table renders "not reported" rather than a fabricated value.

Matched protocol
----------------
This project's detection layer is evaluated on **NF-CSE-CIC-IDS2018-v2**, so the
matched-dataset comparison is the group of published results on that same
dataset (``matched_dataset=True``). Results on CICIoT2023, InSDN, BoT-IoT and
CSE-CIC-IDS2018 remain useful prior work and are retained, but they are labelled
with their own dataset and must not be read as like-for-like.

Two protocol differences are load-bearing and are stated on every row:

1. **Which F1.** Published NF-CSE-CIC-IDS2018-v2 results almost universally
   report *weighted* F1, which on a corpus that is ~88% benign is dominated by
   the benign class. This project targets *macro* F1 (0.8172), which weights the
   665-flow Web Attacks class equally with the 278,227-flow DDoS class. Phase 1's
   own weighted F1 is 0.9942 - the directly comparable figure. Comparing 0.8172
   against a published 0.99x weighted F1 would understate this work; comparing
   0.9942 against it is the honest comparison, and both are reported.
2. **Binary vs multiclass.** Several published rows are binary
   attack/benign. Phase 1's comparable binary F1 is 0.9809.

Earlier revisions of this module compared against CICIoT2023 baselines using a
detection accuracy of 0.9862 and attack precision of 0.9959. Those figures
belong to a different model (a PyTorch binary classifier) on a different
dataset, and are not measurements of this framework. The own-framework row is
now read from Phase 1's committed metrics table rather than passed in by hand.
"""
from __future__ import annotations

from dataclasses import dataclass

from ._phase2_bridge import ensure_phase2_importable

ensure_phase2_importable()

from src.detection_layer import (  # noqa: E402
    DATASET_NAME,
    detection_metrics,
    model_identity,
)


@dataclass(frozen=True)
class Citation:
    label: str
    url: str
    note: str = ""


SOURCES = {
    "nf_datasets_origin": Citation(
        label="Sarhan, Layeghy & Portmann, \"Towards a Standard Feature Set for Network Intrusion Detection System Datasets\", Mobile Networks and Applications, 2022",
        url="https://doi.org/10.1007/s11036-021-01843-0",
        note="Origin paper of the NF-CSE-CIC-IDS2018-v2 dataset used by this project's detection layer. Distribution: https://staff.itee.uq.edu.au/marius/NIDS_datasets/",
    ),
    "fsllm_scirep_2025": Citation(
        label="\"An IoT intrusion detection framework based on feature selection and large language models fine-tuning\", Scientific Reports 15:21158, 2025",
        url="https://www.nature.com/articles/s41598-025-08905-3",
        note="Table 10 collates published NF-CSE-CIC-IDS2018-v2 results (Nguyen et al., Sarhan et al.) alongside the authors' own FSLLM model. All figures are weighted F1 and accuracy; no macro F1 is reported for this dataset.",
    ),
    "cic_iot2023_origin": Citation(
        label="Neto et al., \"CICIoT2023: A Real-Time Dataset and Benchmark for Large-Scale Attacks in IoT Environment\", Sensors 23(13):5941, 2023",
        url="https://www.mdpi.com/1424-8220/23/13/5941",
        note="Standalone-ML baselines on CICIoT2023. Different dataset and different capture environment from this project's NF-CSE-CIC-IDS2018-v2; retained as prior work, not as a matched comparison.",
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
        note="Hybrid ML+blockchain logging framework evaluated on CSE-CIC-IDS2018 (the packet-level parent capture of this project's NetFlow variant) with a private PoA Ganache blockchain, 5-node virtualised environment.",
    ),
}


@dataclass(frozen=True)
class BenchmarkRow:
    system: str
    category: str  # standalone_ml | blockchain_only | hybrid_published | this_framework
    detection_accuracy: float | None
    false_positive_rate_pct: float | None
    f1_score: float | None
    end_to_end_latency_ms: float | None
    tx_or_commit_latency_ms: float | None
    storage_overhead_note: str | None
    source: str | None  # key into SOURCES, or None for this project's own figures
    dataset: str | None = None
    classification: str | None = None  # "binary" | "multiclass" | None
    f1_kind: str | None = None  # "weighted" | "macro" | None
    matched_dataset: bool = False


def literature_rows() -> list[BenchmarkRow]:
    return [
        # --- Category 1a: standalone ML on the SAME dataset (matched protocol) ---
        BenchmarkRow(
            system="Nguyen et al., all features (as collated by Scientific Reports 2025, Table 10)",
            category="standalone_ml",
            detection_accuracy=0.995,
            false_positive_rate_pct=None,
            f1_score=0.995,
            end_to_end_latency_ms=None,
            tx_or_commit_latency_ms=None,
            storage_overhead_note="n/a (no blockchain component)",
            source="fsllm_scirep_2025",
            dataset="NF-CSE-CIC-IDS2018-v2",
            classification="binary",
            f1_kind="weighted",
            matched_dataset=True,
        ),
        BenchmarkRow(
            system="Nguyen et al., all features, multiclass (Scientific Reports 2025, Table 10)",
            category="standalone_ml",
            detection_accuracy=None,
            false_positive_rate_pct=None,
            f1_score=0.992,
            end_to_end_latency_ms=None,
            tx_or_commit_latency_ms=None,
            storage_overhead_note="n/a (no blockchain component)",
            source="fsllm_scirep_2025",
            dataset="NF-CSE-CIC-IDS2018-v2",
            classification="multiclass",
            f1_kind="weighted",
            matched_dataset=True,
        ),
        BenchmarkRow(
            system="Sarhan et al. baseline, all features (Scientific Reports 2025, Table 10)",
            category="standalone_ml",
            detection_accuracy=0.891,
            false_positive_rate_pct=None,
            f1_score=0.889,
            end_to_end_latency_ms=None,
            tx_or_commit_latency_ms=None,
            storage_overhead_note="n/a (no blockchain component)",
            source="fsllm_scirep_2025",
            dataset="NF-CSE-CIC-IDS2018-v2",
            classification="binary",
            f1_kind="weighted",
            matched_dataset=True,
        ),
        BenchmarkRow(
            system="FSLLM, 9 selected features, multiclass",
            category="standalone_ml",
            detection_accuracy=0.988,
            false_positive_rate_pct=None,
            f1_score=0.988,
            end_to_end_latency_ms=None,
            tx_or_commit_latency_ms=None,
            storage_overhead_note="n/a (no blockchain component)",
            source="fsllm_scirep_2025",
            dataset="NF-CSE-CIC-IDS2018-v2",
            classification="multiclass",
            f1_kind="weighted",
            matched_dataset=True,
        ),
        # --- Category 1b: standalone ML on a different dataset ---
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
            dataset="CICIoT2023",
            classification="binary",
            f1_kind="weighted",
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
            dataset="CICIoT2023",
            classification="binary",
            f1_kind="weighted",
        ),
        # --- Category 2: blockchain-only logging, no detection ---
        BenchmarkRow(
            system="Hyperledger Fabric 2.5, basic network, asset-creation tx (arXiv:2502.08755)",
            category="blockchain_only",
            detection_accuracy=None,
            false_positive_rate_pct=None,
            f1_score=None,
            end_to_end_latency_ms=None,
            tx_or_commit_latency_ms=1110.0,  # at 10 tps arrival; 20,000 ms at 100 tps unbatched
            storage_overhead_note="not reported (per-event); illustrates the unbatched-commit latency blow-up motivating this project's Merkle batching",
            source="fabric_perf_model_2025",
            dataset="n/a (no detection component)",
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
            dataset="n/a (no detection component)",
        ),
        # --- Category 3: published hybrid ML + blockchain frameworks ---
        BenchmarkRow(
            system="SmartSecChain-SDN",
            category="hybrid_published",
            detection_accuracy=0.9743,
            false_positive_rate_pct=1.82,
            f1_score=None,
            end_to_end_latency_ms=42.3,
            tx_or_commit_latency_ms=134.2,  # at 10 tx/block; 228.4 ms at 300 tx/block
            storage_overhead_note="not reported (per-event)",
            source="smartsecchain_sdn_2025",
            dataset="InSDN",
        ),
        BenchmarkRow(
            system="MBID (simulated 1,000-device fog deployment)",
            category="hybrid_published",
            detection_accuracy=0.9984,
            false_positive_rate_pct=0.01,
            f1_score=0.9984,
            end_to_end_latency_ms=200.0,  # "under 200 ms" typical; worst case up to 5,100 ms
            tx_or_commit_latency_ms=0.40,  # edge event -> validated fog block
            storage_overhead_note=">80% projected storage reduction via IPFS off-chain placement",
            source="mbid_2025",
            dataset="BoT-IoT / CICIoT2023",
            f1_kind="weighted",
        ),
        BenchmarkRow(
            system="ML + PoA blockchain logging framework (XGBoost)",
            category="hybrid_published",
            detection_accuracy=0.98,
            false_positive_rate_pct=None,
            f1_score=0.98,
            end_to_end_latency_ms=None,
            tx_or_commit_latency_ms=324.0,
            storage_overhead_note="not reported; 100% tamper-hash detection rate reported instead",
            source="ml_blockchain_framework_informatica_2025",
            dataset="CSE-CIC-IDS2018",
            f1_kind="weighted",
        ),
    ]


def this_framework_rows(phase2_results: dict, metrics: dict | None = None) -> list[BenchmarkRow]:
    """Own-framework rows, read from Phase 1's and Phase 2's committed outputs.

    Two rows are emitted deliberately, because a single F1 cannot be compared
    fairly against this literature: one carrying the *weighted* F1 that matches
    how published NF-CSE-CIC-IDS2018-v2 results report themselves, and one
    carrying the *macro* F1 this project actually optimises. Reporting only the
    macro figure against weighted baselines would understate the work; reporting
    only the weighted figure would overstate the class-balanced performance.
    """
    measured = metrics if metrics is not None else detection_metrics()
    if not measured:
        raise RuntimeError(
            "Phase 1's metrics table is unavailable, so this framework's detection "
            "figures cannot be read. Run Phase 1 stage 07, or pass `metrics=` "
            "explicitly. This function will not substitute a placeholder."
        )

    identity = model_identity()
    integrity = phase2_results.get("integrity", {})
    storage = phase2_results.get("storage", {})
    bench = phase2_results.get("benchmark", {})

    accuracy = measured.get("accuracy")
    fpr_pct = measured.get("FPR")
    fpr_pct = fpr_pct * 100.0 if fpr_pct is not None else None
    latency_p95 = bench.get("latency_ms_p95")

    storage_note = (
        f"{storage.get('reduction_pct', float('nan')):.1f}% on-chain size reduction vs full payload "
        f"(mean on-chain record {storage.get('on_chain_bytes_mean', float('nan')):.0f} bytes); "
        f"{identity.anchoring_gate.get('write_reduction', float('nan')) * 100:.1f}% ledger write "
        f"reduction from selective anchoring at ICR "
        f"{identity.anchoring_gate.get('icr', float('nan')):.4f}; "
        f"integrity verification failure rate {integrity.get('failure_rate_pct', float('nan')):.2f}%"
    )

    common = {
        "category": "this_framework",
        "detection_accuracy": accuracy,
        "false_positive_rate_pct": fpr_pct,
        "end_to_end_latency_ms": latency_p95,
        "tx_or_commit_latency_ms": latency_p95,
        "storage_overhead_note": storage_note,
        "source": None,
        "dataset": DATASET_NAME,
        "matched_dataset": True,
    }

    return [
        BenchmarkRow(
            system="This framework (Phase 1 LightGBM detection + Phase 2 evidence logging) - weighted F1, comparable to the rows above",
            f1_score=measured.get("f1_weighted"),
            classification="multiclass (7 classes)",
            f1_kind="weighted",
            **common,
        ),
        BenchmarkRow(
            system="This framework - macro F1, the metric this project optimises (not comparable to weighted-F1 rows)",
            f1_score=measured.get("f1_macro"),
            classification="multiclass (7 classes)",
            f1_kind="macro",
            **common,
        ),
        BenchmarkRow(
            system="This framework - binary attack/benign view, comparable to the binary rows above",
            f1_score=measured.get("binary_f1"),
            classification="binary",
            f1_kind="binary",
            **common,
        ),
    ]


def this_framework_row(phase2_results: dict, metrics: dict | None = None) -> BenchmarkRow:
    """The single weighted-F1 own-framework row, for callers wanting just one."""
    return this_framework_rows(phase2_results, metrics)[0]


def protocol_notes() -> list[str]:
    """Protocol differences that must be published alongside the table."""
    identity = model_identity()
    return [
        "Dataset: rows marked matched_dataset=True are evaluated on "
        f"{DATASET_NAME}, the same dataset as this framework's detection layer. "
        "Rows on CICIoT2023, InSDN, BoT-IoT or CSE-CIC-IDS2018 are prior work on "
        "different captures and are not like-for-like.",
        "F1 definition: published NF-CSE-CIC-IDS2018-v2 results report weighted "
        "F1, which is dominated by the ~88% benign class. This framework's "
        "weighted F1 is the comparable figure; its macro F1 is lower by "
        "construction because it weights the 665-flow Web Attacks class equally "
        "with the 278,227-flow DDoS class. Both are reported.",
        "Class granularity: several published rows are binary attack/benign, "
        "whereas this framework resolves seven coarse categories. The binary row "
        "is provided for that comparison.",
        "Split protocol: this framework splits by capture order without "
        f"shuffling ({identity.dataset}), and applies benign downsampling to the "
        "training fold only. Published rows generally do not state whether their "
        "splits preserve temporal order, so a shuffled-split baseline may be "
        "optimistically biased relative to this one.",
        "Latency and logging figures for this framework are single-host, "
        "software-layer measurements against MockLedger, not a deployed "
        "Hyperledger Fabric network, and carry no consensus or network cost. They "
        "are not comparable to the real-system Fabric measurements in the "
        "blockchain_only rows without that caveat.",
        "Calibration: this framework reports isotonic-calibrated confidence with "
        f"measured ECE {identity.expected_calibration_error:.2e}. None of the "
        "cited works reports a calibration error, so the anchoring-gate argument "
        "has no published comparator.",
    ]


def format_table(rows: list[BenchmarkRow]) -> str:
    header = (
        "| System | Category | Dataset | Matched | Class | Detection accuracy | FPR (%) | "
        "F1 | F1 type | End-to-end latency (ms) | Tx/commit latency (ms) | Storage overhead | Source |"
    )
    sep = "|---|---|---|---|---|---|---|---|---|---|---|---|---|"
    lines = [header, sep]
    for r in rows:
        source_cell = (
            "this project (measured)"
            if r.source is None
            else f"[{SOURCES[r.source].label}]({SOURCES[r.source].url})"
        )
        lines.append(
            "| {system} | {category} | {dataset} | {matched} | {cls} | {acc} | {fpr} | {f1} | "
            "{f1kind} | {e2e} | {tx} | {storage} | {source} |".format(
                system=r.system,
                category=r.category,
                dataset=r.dataset or "not stated",
                matched="yes" if r.matched_dataset else "no",
                cls=r.classification or "not stated",
                acc=f"{r.detection_accuracy:.4f}" if r.detection_accuracy is not None else "not reported",
                fpr=f"{r.false_positive_rate_pct:.4f}" if r.false_positive_rate_pct is not None else "not reported",
                f1=f"{r.f1_score:.4f}" if r.f1_score is not None else "not reported",
                f1kind=r.f1_kind or "n/a",
                e2e=f"{r.end_to_end_latency_ms:.1f}" if r.end_to_end_latency_ms is not None else "not reported",
                tx=f"{r.tx_or_commit_latency_ms:.2f}" if r.tx_or_commit_latency_ms is not None else "not reported",
                storage=r.storage_overhead_note or "not reported",
                source=source_cell,
            )
        )
    return "\n".join(lines)

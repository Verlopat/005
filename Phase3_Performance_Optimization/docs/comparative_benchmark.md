# Comparative Analysis Against Existing Solutions

Objective 3: "The integrated framework is benchmarked against three
categories of prior work: standalone machine learning intrusion detection
without blockchain, blockchain-only logging without detection, and
published hybrid frameworks... Comparison is conducted under matched
evaluation protocol wherever the source publication reports sufficient
methodological detail, and protocol differences are stated explicitly
where it does not, since partitioning strategy and class rebalancing
account for a large share of the variance in reported figures on this
dataset."

## Matched-dataset detection comparison

The detection layer is evaluated on **NF-CSE-CIC-IDS2018-v2**, and published
results exist on that same dataset, so the detection half of the comparison *is*
matched on dataset. Those rows are marked `matched=yes` in the generated table
and are collated in Table 10 of ["An IoT intrusion detection framework based on
feature selection and large language models fine-tuning", *Scientific Reports*
15:21158, 2025](https://www.nature.com/articles/s41598-025-08905-3):

| System | Class | Weighted F1 | Accuracy |
|---|---|---|---|
| Nguyen et al., all features | binary | 0.995 | 0.995 |
| Nguyen et al., all features | multiclass | 0.992 | not reported |
| Sarhan et al. baseline, all features | binary | 0.889 | 0.891 |
| FSLLM, 9 features | multiclass | 0.988 | 0.988 |
| **This framework** | multiclass (7) | **0.9942** | **0.9954** |
| **This framework** | binary view | **0.9809** | **0.9954** |

**Which F1 is being compared matters, and is the single most important caveat
in this document.** Every published figure above is a *weighted* F1, which on a
corpus that is ~88% benign is dominated by the benign class. This project targets
*macro* F1 (0.8172), which weights the 665-flow Web Attacks class equally with
the 278,227-flow DDoS class. Those two numbers are not comparable:

- Comparing this project's macro F1 (0.8172) against a published weighted F1
  (0.99x) **understates** this work by comparing two different metrics.
- Reporting only the weighted F1 (0.9942) **overstates** class-balanced
  performance and hides the genuinely hard classes.

The generated table therefore emits three own-framework rows - weighted, macro
and binary - and labels each with its `F1 type`. Cite the weighted row against
these baselines, and cite the macro row as this project's own optimisation
target, with the distinction stated.

A further difference: this project splits by **capture order without shuffling**
and downsamples benign traffic in the training fold only. The published rows
generally do not state whether their splits preserve temporal order; a shuffled
split on flow data can leak near-duplicate flows between folds and is
optimistically biased relative to a time-ordered split. This is a reason to treat
the gap between 0.889 and 0.995 in the published rows with caution as well.

## Protocol differences that must be stated explicitly

Beyond the dataset-matched detection rows above, the systems compared were not
evaluated under an identical protocol to this project's pipeline. In particular:

- **Dataset, for the non-matched rows.** The cited hybrid frameworks use InSDN
  (SmartSecChain-SDN), BoT-IoT + CICIoT2023 (MBID), or CSE-CIC-IDS2018 (the
  Informatica framework), and the standalone-ML rows from the CICIoT2023 origin
  paper are on that dataset. Detection figures across different datasets are
  **not** a controlled comparison of model quality — they are reported side by
  side because Objective 3 explicitly calls for this comparison, with the caveat
  stated up front rather than implied. Rows carry their dataset in the table.
- **Latency and storage are not matched at all.** This project's figures are
  single-host, software-layer measurements against `MockLedger`, with no
  consensus, endorsement or network cost. The cited systems ran real
  Fabric/PoA/fog networks. A Pareto claim on latency requires deploying
  `Phase2_Blockchain_Logging/network/` on a Fabric-capable host.
- **Calibration has no published comparator.** This project reports
  isotonic-calibrated confidence with measured ECE 8.14e-05. None of the cited
  works reports a calibration error, so the anchoring-gate argument cannot be
  compared against prior work at all.
- **Blockchain platform and topology.** MBID uses a custom 3-shard fog
  architecture; SmartSecChain-SDN and the Informatica framework use small
  (1-2 peer) Fabric/Ganache networks; the two Fabric-only benchmarks use
  4-8 peer research testbeds. Transaction/commit latency depends heavily
  on topology, consensus configuration, and hardware — see each row's
  source citation for the exact configuration before treating any two
  latency figures as comparable.
- **What "this framework" measures.** This project's own row combines
  Phase 1's reported test-fold metrics (LightGBM multiclass on
  NF-CSE-CIC-IDS2018-v2, 3,778,631 held-out flows — see
  `Phase_1/outputs/07_metrics/metrics_table.csv` and
  `Phase_1/outputs/09_model/model_card.json`)
  with Phase 2's measured software-layer commit latency against a mock
  ledger (`Phase2_Blockchain_Logging/outputs/phase2_results.json`), **not**
  a deployed Fabric network. It is the most protocol-transparent row in
  the table for exactly that reason: every number it reports traces to a
  script in this repository that can be re-run.

## Sources

See `perf/comparative_benchmark.py:SOURCES` for the full citation list with
URLs; `docs/../outputs/phase3_results.md`'s comparative table cites each
row inline. The six cited works, by category:

**Standalone ML intrusion detection (no blockchain):**
- Neto et al., "CICIoT2023: A Real-Time Dataset and Benchmark for
  Large-Scale Attacks in IoT Environment", *Sensors* 23(13):5941, 2023.
  [https://www.mdpi.com/1424-8220/23/13/5941](https://www.mdpi.com/1424-8220/23/13/5941)

**Blockchain-only logging (no detection):**
- "Performance Modeling and Evaluation of Hyperledger Fabric", arXiv:2502.08755, 2025.
  [https://arxiv.org/html/2502.08755v1](https://arxiv.org/html/2502.08755v1)
- "An In-Depth Investigation of Performance Characteristics of Hyperledger Fabric", arXiv:2102.07731, 2021.
  [https://arxiv.org/pdf/2102.07731v1](https://arxiv.org/pdf/2102.07731v1)

**Published hybrid ML + blockchain frameworks:**
- "SmartSecChain-SDN: A Blockchain-Integrated Intelligent Framework for
  Real-Time Intrusion Detection and Prevention in SDN", arXiv:2511.05156, 2025.
  [https://arxiv.org/pdf/2511.05156](https://arxiv.org/pdf/2511.05156)
- "MBID: A Scalable Multi-Tier Blockchain Architecture with
  Physics-Informed Neural Networks for Intrusion Detection", *Computer
  Modeling in Engineering & Sciences* 144(2), 2025.
  [https://www.techscience.com/CMES/v144n2/63732/html](https://www.techscience.com/CMES/v144n2/63732/html)
- "A Machine Learning and Blockchain-Based Framework for..." (tamper-proof
  log integrity), *Informatica*, 2025.
  [https://www.informatica.si/index.php/informatica/article/view/9421/5823](https://www.informatica.si/index.php/informatica/article/view/9421/5823)

## Reading the table

`perf/comparative_benchmark.py:format_table()` renders "not reported" for
any field the source publication did not report — never a computed
placeholder — so a blank cell in the paper's table is traceable to "the
paper doesn't say" rather than to a measurement this project failed to
take.

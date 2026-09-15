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

## Protocol differences that must be stated explicitly

None of the systems compared below were evaluated under an identical
protocol to this project's Phase 1/2 pipeline. In particular:

- **Dataset.** This project's delivered Phase 1 model is trained/tested on
  CICIoT2023; the cited hybrid frameworks use InSDN (SmartSecChain-SDN),
  BoT-IoT + CICIoT2023 (MBID), or CSE-CIC-IDS2018 (the Informatica
  framework). Detection accuracy figures across different datasets are
  **not** a controlled comparison of model quality — they are reported
  side by side because Objective 3 explicitly calls for this comparison,
  with this caveat stated up front rather than implied.
- **Blockchain platform and topology.** MBID uses a custom 3-shard fog
  architecture; SmartSecChain-SDN and the Informatica framework use small
  (1-2 peer) Fabric/Ganache networks; the two Fabric-only benchmarks use
  4-8 peer research testbeds. Transaction/commit latency depends heavily
  on topology, consensus configuration, and hardware — see each row's
  source citation for the exact configuration before treating any two
  latency figures as comparable.
- **What "this framework" measures.** This project's own row combines
  Phase 1's reported test-fold accuracy (STAHN, CICIoT2023, 100,001
  held-out packets — see `Phase1_Submission/blockchain_handoff_document.md`)
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

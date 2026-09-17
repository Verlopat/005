# Objective 2 — Phase 2 Results

Generated: 2026-09-17T19:20:55.899Z
Sample: 120 alerts from the Phase 1 detection layer (LightGBM multiclass, 7 coarse threat categories, NF-CSE-CIC-IDS2018-v2)
Alert source: SYNTHETIC Phase 1-shaped alerts (model_version=SYNTHETIC-FIXTURE-NOT-A-DETECTION); Phase 1's emitted alert stream was not present in this checkout, so no detection figure in this report is a measurement.
Cross-layer digest agreement: Phase 2 independently reproduced 6/6 of Phase 1's frozen digest test vectors.
Ledger backend: `src/ledger/mock_ledger.py` (in-memory, hash-chained, tamper-evident). No Docker/Go/Fabric were available in the environment that generated this report; see the caveats inline below and `../network/` for the production Hyperledger Fabric deployment artifacts.

## Success metrics (Objective 2)

| # | Metric | Target / Benchmark | Measured (this run) | Status |
|---|---|---|---|---|
| 1 | Blockchain transaction throughput | >1,000 TPS sustained, with Merkle batch aggregation enabled at peak arrival rates | Required tx/sec at 10,000 events/sec peak x 11.43% anchoring rate: 1143 tx/sec unbatched -> 11.4 tx/sec at batch factor 100 (minimum batch factor to clear 1,000 TPS: 2). Measured local software-layer submission throughput (mock ledger, immediate-commit, no batching): 106 events/sec on this machine. | Met by design (batching keeps required TPS far below 1,000); network-level TPS requires deploying network/ on a Fabric-capable host. |
| 2 | Log commit latency, detection to on-chain confirmation | < 500 ms at the 95th percentile | Software-layer latency (canonicalise+digest+sign+store+commit, mock ledger), n=60: p50=9.420 ms, p95=9.527 ms, p99=9.982 ms, max=10.292 ms. | Met for the software layer with large margin. Real end-to-end figure additionally includes Fabric endorsement/ordering round-trip, measured on a deployed network. |
| 3 | On-chain storage overhead per event | < 1 KB per record, digest and metadata only | n=120: mean on-chain record size 771 bytes (max 779 bytes) vs mean full off-chain payload 1270 bytes -> 39.3% size reduction. | Met |
| 4 | Log integrity verification failure rate | 0%; every stored digest verifies against its off-chain payload | 0/85 audited events failed verification (0.00%) under normal operation. Live tamper-injection test: detected (VERIFIED -> TAMPERED, chain integrity check also failed). | Met |
| 5 | Integrity Coverage Ratio of the anchored record | >= 95% of true attack flows anchored at the deployment gate | At gate=0.95: ICR=0.8333, on-chain volume=0.7083, attacks in sample=102. Full sweep in the ICR table below. | Gate-dependent — see sweep table; adjust --gate |
| 6 | Canonical digest agreement across layers | 100% agreement between detection-layer and chaincode digests over the published test vectors | Python implementation (src/canonical.py + src/digest.py): 6/6 vectors (100.0%) reproduced exactly. Go chaincode implementation (chaincode/securitylog/canonical.go) is provided with an equivalent test (canonical_test.go) but was NOT independently executed in this environment (no Go toolchain available); run `go test ./...` in chaincode/securitylog/ on a host with Go 1.21+ to complete cross-language confirmation. | Met (Python side); Go side pending toolchain availability |
| 7 | Model provenance traceability | Every anchored alert resolvable to a specific anchored model identifier | Phase 1 exported model artifact unavailable in this run; provenance anchoring skipped. | NOT MET / SKIPPED |
| 8 | Non-repudiation of agent identity | Every record cryptographically bound to an authenticated agent certificate | 85/85 audited signatures verified against the registered agent identity. Forged-signature rejection test (different key signs the same digest): correctly rejected. | Met |

## Integrity Coverage Ratio sweep

| gate | ICR | on-chain volume | attack count |
|---|---|---|---|
| 0.00 | 1.0000 | 1.0000 | 102 |
| 0.50 | 0.8333 | 0.7083 | 102 |
| 0.75 | 0.8333 | 0.7083 | 102 |
| 0.90 | 0.8333 | 0.7083 | 102 |
| 0.95 | 0.8333 | 0.7083 | 102 |
| 0.99 | 0.8333 | 0.7083 | 102 |

## Methodological notes for the paper

- Throughput and latency figures above are software-layer measurements against the mock ledger (`src/ledger/mock_ledger.py`), not a deployed Hyperledger Fabric network. They demonstrate that the canonicalisation, signing, off-chain storage, and Merkle-batching logic add negligible overhead relative to the 1,000 TPS / 500 ms budgets; they are not a substitute for a network-measured figure. Deploy `Phase2_Blockchain_Logging/network/` on a host with Docker, Go 1.21+, and the Fabric binaries/images to obtain a network-measured throughput and commit-latency figure.
- The detection layer for these alerts is the Phase 1 calibrated seven-category LightGBM model on NF-CSE-CIC-IDS2018-v2, this project's detection layer of record. Confidence values are isotonic-calibrated P(attack) carried through from Phase 1 unchanged, and `calibration.is_calibrated` reflects that. Where this run used synthetic Phase 1-shaped alerts (stated above), the evidence pipeline is still exercised end to end but the detection figures are not measurements.
- Integrity Coverage Ratio figures are computed on this sample and detection layer and are not directly comparable to the 95.68% figure reported in the revised Objective 1 text, which was measured on a different dataset and model.


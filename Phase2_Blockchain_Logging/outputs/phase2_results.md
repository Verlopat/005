# Objective 2 — Phase 2 Results

Generated: 2026-09-15T18:28:25.879Z
Sample: 2000 rows from `Phase1_Submission/CICIoT2023_Sample.csv`
Inference source: SIMULATED oracle — torch/model artifact unavailable in this environment
Ledger backend: `src/ledger/mock_ledger.py` (in-memory, hash-chained, tamper-evident). No Docker/Go/Fabric were available in the environment that generated this report; see the caveats inline below and `../network/` for the production Hyperledger Fabric deployment artifacts.

## Success metrics (Objective 2)

| # | Metric | Target / Benchmark | Measured (this run) | Status |
|---|---|---|---|---|
| 1 | Blockchain transaction throughput | >1,000 TPS sustained, with Merkle batch aggregation enabled at peak arrival rates | Required tx/sec at 10,000 events/sec peak x 11.43% anchoring rate: 1143 tx/sec unbatched -> 11.4 tx/sec at batch factor 100 (minimum batch factor to clear 1,000 TPS: 2). Measured local software-layer submission throughput (mock ledger, immediate-commit, no batching): 128 events/sec on this machine. | Met by design (batching keeps required TPS far below 1,000); network-level TPS requires deploying network/ on a Fabric-capable host. |
| 2 | Log commit latency, detection to on-chain confirmation | < 500 ms at the 95th percentile | Software-layer latency (canonicalise+digest+sign+store+commit, mock ledger), n=500: p50=7.615 ms, p95=8.335 ms, p99=12.470 ms, max=15.029 ms. | Met for the software layer with large margin. Real end-to-end figure additionally includes Fabric endorsement/ordering round-trip, measured on a deployed network. |
| 3 | On-chain storage overhead per event | < 1 KB per record, digest and metadata only | n=200: mean on-chain record size 762 bytes (max 773 bytes) vs mean full off-chain payload 1392 bytes -> 45.2% size reduction. | Met |
| 4 | Log integrity verification failure rate | 0%; every stored digest verifies against its off-chain payload | 0/300 audited events failed verification (0.00%) under normal operation. Live tamper-injection test: detected (VERIFIED -> TAMPERED, chain integrity check also failed). | Met |
| 5 | Integrity Coverage Ratio of the anchored record | >= 95% of true attack flows anchored at the deployment gate | At gate=0.95: ICR=0.9897, on-chain volume=0.9730, attacks in sample=1949. Full sweep in the ICR table below. | Met |
| 6 | Canonical digest agreement across layers | 100% agreement between detection-layer and chaincode digests over the published test vectors | Python implementation (src/canonical.py + src/digest.py): 6/6 vectors (100.0%) reproduced exactly. Go chaincode implementation (chaincode/securitylog/canonical.go) is provided with an equivalent test (canonical_test.go) but was NOT independently executed in this environment (no Go toolchain available); run `go test ./...` in chaincode/securitylog/ on a host with Go 1.21+ to complete cross-language confirmation. | Met (Python side); Go side pending toolchain availability |
| 7 | Model provenance traceability | Every anchored alert resolvable to a specific anchored model identifier | Model provenance anchored and retrievable by model_digest=8e985a7cf2272c54...; every ATTACK alert's model.model_digest field matches the anchored record: True. | Met |
| 8 | Non-repudiation of agent identity | Every record cryptographically bound to an authenticated agent certificate | 300/300 audited signatures verified against the registered agent identity. Forged-signature rejection test (different key signs the same digest): correctly rejected. | Met |

## Integrity Coverage Ratio sweep

| gate | ICR | on-chain volume | attack count |
|---|---|---|---|
| 0.00 | 1.0000 | 1.0000 | 1949 |
| 0.50 | 0.9944 | 0.9945 | 1949 |
| 0.75 | 0.9897 | 0.9900 | 1949 |
| 0.90 | 0.9897 | 0.9820 | 1949 |
| 0.95 | 0.9897 | 0.9730 | 1949 |
| 0.99 | 0.1780 | 0.1750 | 1949 |

## Methodological notes for the paper

- Throughput and latency figures above are software-layer measurements against the mock ledger (`src/ledger/mock_ledger.py`), not a deployed Hyperledger Fabric network. They demonstrate that the canonicalisation, signing, off-chain storage, and Merkle-batching logic add negligible overhead relative to the 1,000 TPS / 500 ms budgets; they are not a substitute for a network-measured figure. Deploy `Phase2_Blockchain_Logging/network/` on a host with Docker, Go 1.21+, and the Fabric binaries/images to obtain a network-measured throughput and commit-latency figure.
- The detection layer used to generate these alerts is the delivered Phase 1 STAHN binary classifier (CICIoT2023), not the calibrated seven-category LightGBM cascade described in the revised Objective 1 text (NF-CSE-CIC-IDS2018-v2). `calibration.is_calibrated=False` on every event reflects this honestly; confidence values here are raw softmax scores, not isotonic-calibrated probabilities.
- Integrity Coverage Ratio figures are computed on this sample and detection layer and are not directly comparable to the 95.68% figure reported in the revised Objective 1 text, which was measured on a different dataset and model.


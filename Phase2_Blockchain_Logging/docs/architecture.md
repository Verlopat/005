# Architecture: Platform Selection and Hybrid Storage

## Hyperledger Fabric vs. private Ethereum

Objective 2 calls for "a comparative evaluation of Hyperledger Fabric
against private Ethereum networks ... across transaction throughput, block
confirmation latency, smart contract expressiveness, permissioning
granularity and storage efficiency," with Fabric hypothesised to be
superior. This table records that comparison and the decision it supports.

| Dimension | Hyperledger Fabric (permissioned) | Private Ethereum (PoA, e.g. Geth/Clique or Besu) | Relevance to this system |
|---|---|---|---|
| Consensus finality | Deterministic, immediate on endorsement + ordering (e.g. Raft) | Probabilistic under PoW-derived clients; near-deterministic under PoA but still block-interval bound | A security log needs a definite "committed" answer per event/batch, not a probability that grows over confirmations |
| Permissioning granularity | Channel-level data isolation; MSP-based identity per organisation; fine-grained chaincode endorsement policies | Account-level only; smart-contract-enforced roles, no native network-level data partition | Multi-tenant cloud deployments need tenant-level or org-level isolation of *who can read which channel*, not just who can call a function |
| Smart contract expressiveness | Chaincode in Go/Java/JavaScript; full general-purpose language, direct state DB access (LevelDB/CouchDB) | Solidity/Vyper on EVM; gas-metered, deliberately restricted execution model | LogSecurityEvent/VerifyEvent/QueryEventHistory need straightforward key-value and range queries, not gas-optimised bytecode |
| Transaction cost model | No native token; cost is compute/storage on operator infrastructure | Gas fees per transaction/byte, even on a private PoA network operators typically still meter gas | A >1,000 TPS anchoring workload must not be throttled by a fee market designed for public contention |
| Institutional governance | Consortium/channel policy changes require explicit organisational agreement (matches enterprise cloud security governance) | Governance is whatever the deployer's admin keys allow; no native multi-org consortium primitive | The multi-tenant, regulated (GDPR/ISO 27001/SOC 2) deployment target matches Fabric's consortium model directly |
| Storage efficiency | Block + world-state DB per peer; peers can be pruned/archived independently per org | Full historical state typically replicated identically across all nodes | Off-chain-heavy hybrid storage (this document, next section) benefits more from Fabric's per-org storage independence |

**Decision: Hyperledger Fabric**, per the hypothesis in the registered
Objective 2 text, on the basis of the permissioned architecture, pluggable
consensus (Raft ordering, configured in `network/configtx.yaml`), and
institutional governance model rows above, all of which map directly onto
a multi-tenant cloud security logging deployment with named participating
organisations and no requirement for public, permissionless participation.

## Hybrid on-chain / off-chain storage

Two independent cost pressures make full on-chain storage of alert
payloads infeasible at the measured operating point:

1. **Per-event size.** A complete alert including `triggering_features`
   and `feature_attributions` is on the order of 1–5 KB; at the measured
   11.43% anchoring rate and a 10,000 events/sec peak arrival rate (the
   same figures behind the Merkle-batching amendment; see
   `src/merkle.py:required_batch_factor_for_target_tps`), on-chain state
   would grow by tens of megabytes per second at peak if committed in
   full.
2. **Model artifact size.** `stahn_model.pth` is 10.9 MB — three to four
   orders of magnitude larger than a single alert, and explicitly flagged
   by the Phase 1 handoff document as too expensive to store on-chain.

The resolution (`src/evidence_store.py`, `src/model_provenance.py`) is
uniform across both cases: the full object is placed in content-addressed
storage (local filesystem by default; IPFS for a distributed deployment,
per the handoff document's explicit direction for the model artifact), and
only a SHA-256 digest plus a small, fixed set of essential metadata fields
is committed on-chain. Verifiability is not weakened by this split: the
content address *is* a commitment to the exact bytes (changing one byte of
the payload changes its address), so tamper evidence is inherited by the
off-chain object rather than requiring a second, separate integrity
mechanism.

## Where Objective 3 picks up

This document stops at the boundary Objective 2 owns: platform choice and
the storage split. Merkle batching's *arithmetic dependency* is recorded
here and in `src/merkle.py` because Phase I measurement showed it is
required at peak load for Objective 2's own 1,000 TPS target, but the
*asynchronous pipeline*, *load testing across 100–10,000 simulated
instances*, and *comparative benchmarking against prior systems* are
Objective 3's scope and are deliberately not built in this phase.

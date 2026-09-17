"""Phase 2 — Blockchain-Based Tamper-Proof Security Event Logging.

Implements Research Objective 2 for the Phase 1 intrusion-detection layer (a
calibrated seven-category LightGBM detector over NetFlow features, trained on
NF-CSE-CIC-IDS2018-v2):
canonical serialisation, cryptographic signing, content-addressed off-chain
storage, calibrated anchoring policy, Merkle batching, and a pluggable
ledger client (mock in-memory backend for local development and testing;
Hyperledger Fabric Gateway backend for production).
"""

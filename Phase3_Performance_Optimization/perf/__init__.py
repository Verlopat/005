"""Phase 3 — Performance Optimisation, Scalability Validation, and
Comparative Benchmarking of the Integrated Framework.

Implements Research Objective 3: an asynchronous logging pipeline with
local caching, scalability/load testing across simulated instance counts,
processor-overhead profiling of the integrated framework against a
detection-only baseline, a sustained-load stability harness, and
comparative benchmarking against published prior systems.

Named `perf` (not `src`) specifically so it can be imported side-by-side
with `Phase2_Blockchain_Logging.src` without a module-name collision on
sys.path; see any module here for the two-root sys.path pattern used to
reach Phase 2's canonicalisation/signing/storage/ledger/pipeline code.
"""

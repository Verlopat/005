# Canonical Serialisation and Digest Specification (v1.0.0)

## Why this document exists

Objective 2 requires that "the detection layer and the verification contract
must independently compute identical digests for the same event." The
detection layer is Python; the verification chaincode is Go. Two different
JSON encoders in two different languages do not agree on key ordering,
float formatting, or whitespace unless one canonical form is specified in
advance and treated as a shared artifact rather than as prose. This document
is that artifact. `src/canonical.py` is its Python implementation;
`chaincode/securitylog/canonical.go` is its Go implementation. Both MUST be
validated against `contracts/test_vectors/canonical_digest_vectors.json`
before either is trusted, and CI regenerates and re-checks those vectors as
the compatibility gate between the two layers.

## Rules

1. **Input.** The canonical form is computed over the alert event object as
   defined by `contracts/alert_event.schema.json`, **excluding** the
   `payload_digest` field itself (the digest cannot include itself).

2. **Key ordering.** Object keys are sorted lexicographically by their raw
   UTF-8 byte sequence (ordinal / byte-wise ordering, not locale-aware
   collation). This applies recursively to every nested object, including
   `model`, `calibration`, `triggering_features`, and every element of
   `feature_attributions`.

3. **Whitespace.** No insignificant whitespace. No space after `:` or `,`.
   The canonical form is a single line.

4. **String encoding.** UTF-8. No escaping of non-ASCII characters (i.e. do
   not use `\uXXXX` escapes for characters that have a direct UTF-8
   representation). The solidus `/` is not escaped. Control characters
   below U+0020 are escaped using the shortest standard JSON escape
   (`\n`, `\t`, `\r`, `\b`, `\f`, or `\u00XX` for the remainder).

5. **Number formatting.**
   - Integers are rendered with no decimal point and no leading zeros
     (other than the single digit `0`), e.g. `0`, `42`, `-7`.
   - Non-integer floating point numbers are rendered using the shortest
     decimal representation that round-trips to the same IEEE-754 binary64
     value (Python's `repr(float)` / `float.__repr__` semantics, which is
     what `json.dumps` already uses and what Go's `strconv.FormatFloat(f,
     'g', -1, 64)` reproduces). No trailing zeros beyond what round-tripping
     requires. No `+` sign on the exponent is required; `e` is lowercase
     when scientific notation is used, matching Go's `%g` and Python's
     `repr` for the relevant magnitude ranges. Values exercising this rule
     are covered explicitly in the test vectors.
   - `NaN` and `Infinity` are **forbidden** in any field of a canonicalised
     event. Objective 1's data-integrity remediation exists precisely to
     ensure these never reach the alert boundary; a canonicaliser that
     receives one MUST raise rather than silently coerce it, because a
     silent coercion (e.g. to `0` or `null`) is indistinguishable from a
     legitimate reading and would corrupt the evidentiary record.

6. **Null handling.** `null` is a legal value only where the schema
   declares the field nullable (`source_address`, `destination_address`).
   `null` is rendered as the literal `null`, not omitted.

7. **Array ordering.** Arrays preserve the order presented by the producer.
   `feature_attributions` is defined by the schema as rank-ordered
   (most influential first); canonicalisation does not re-sort it, since
   rank order carries meaning that a canonical-form re-sort would destroy.

8. **Digest.** `payload_digest = lower_hex(SHA-256(canonical_bytes))`, where
   `canonical_bytes` is the UTF-8 encoding of the canonical string produced
   by rules 1–7. The digest is always emitted as 64 lowercase hexadecimal
   characters, matching the `^[0-9a-f]{64}$` pattern in the schema.

## Worked example

Given the minimal object (after excluding `payload_digest` per rule 1):

```json
{"b": 2, "a": 1}
```

the canonical form is:

```
{"a":1,"b":2}
```

and its SHA-256 digest is
`43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777`
(64 lowercase hex characters). This and five further, contract-shaped
vectors are published in `contracts/test_vectors/canonical_digest_vectors.json`
and MUST be reproduced exactly by both implementations.

## Cross-language conformance procedure

1. Run `python3 Phase2_Blockchain_Logging/scripts/validate_commit1.py`.
   It recomputes the digest of every vector using `src/canonical.py` and
   `src/digest.py` and fails loudly on any mismatch.
2. Once `chaincode/securitylog/canonical.go` exists (Commit 4), the Go unit
   test `chaincode/securitylog/canonical_test.go` performs the identical
   check against the same vector file. A vector file that only one side
   passes indicates a specification bug or an implementation bug — it must
   never be "fixed" by patching only one side's expected output.

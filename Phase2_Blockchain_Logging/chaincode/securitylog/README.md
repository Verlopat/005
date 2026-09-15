# `securitylog` Chaincode

Implements the three functions Objective 2 specifies plus model-provenance
anchoring:

| Function | Purpose | Access |
|---|---|---|
| `LogSecurityEvent(eventJSON)` | Commit digest + essential metadata for one event or one Merkle batch root | detection agents only (`phase2.detectionAgent=true` CA attribute) |
| `VerifyEvent(eventID, payloadDigest)` | Confirm a stored digest matches an independently supplied one | auditors or agents |
| `QueryEventHistory(resourceID, startTime, endTime)` | Ordered, filterable audit trail | auditors or agents |
| `AnchorModelProvenance(provenanceJSON)` | Anchor a model_provenance.schema.json record once per retraining cycle | detection agents only |
| `GetModelProvenance(modelDigest)` | Look up a model's anchored provenance by digest | auditors or agents |
| `RecomputeDigest(eventJSONWithoutDigest)` | Read-only conformance check against `canonical.go` | auditors or agents |

## Building

Requires Go 1.21+ (not installed in the sandbox this repository was
scaffolded in):

```bash
cd Phase2_Blockchain_Logging/chaincode/securitylog
go mod tidy
go build ./...
go test ./...       # runs canonical_test.go against the shared vector file
```

`go test` is the authoritative cross-language check: it must pass with the
exact same vectors `scripts/validate_commit1.py` validates on the Python
side (`../../contracts/test_vectors/canonical_digest_vectors.json`). A
vector that only one language reproduces means the specification or one
implementation has a bug — see `../../docs/canonicalisation_spec.md`.

## Deploying

See `../network/scripts/network-up.sh` and `deploy-chaincode.sh`. Requires
Docker, the Fabric peer/orderer/ca images, and the `cryptogen`/
`configtxgen`/`peer` binaries on a host machine — none of which are
available inside this sandbox, so this chaincode is built and tested for
correctness here (once Go is available) but deployed on a separate host.

## Access control model

`requireDetectionAgent` and `requireAuditorOrAgent` read Fabric CA
identity attributes via `github.com/hyperledger/fabric-chaincode-go/pkg/cid`.
An identity without the `phase2.detectionAgent=true` attribute cannot call
`LogSecurityEvent` or `AnchorModelProvenance`, even if it can otherwise
authenticate to the network — this is the concrete implementation of
Objective 2's "only authenticated detection agents may write, while any
authorised auditor may read." `network/scripts/enroll-identities.sh`
provisions these attributes at enrollment time via the Fabric CA.

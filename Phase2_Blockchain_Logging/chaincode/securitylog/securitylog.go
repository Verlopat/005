// Package main implements the securitylog chaincode specified by
// Objective 2: "Go-based chaincode will implement three core functions.
// LogSecurityEvent commits the cryptographic digest of an event payload
// together with its on-chain metadata. VerifyEvent queries the ledger to
// confirm the integrity of a specified record against its stored digest.
// QueryEventHistory retrieves the complete ordered audit trail for a
// specified asset or time window. Access control is enforced within the
// contracts so that only authenticated detection agents may write, while
// any authorised auditor may read."
//
// AnchorModelProvenance / GetModelProvenance implement the model
// provenance anchoring Objective 2 also specifies, matching
// contracts/model_provenance.schema.json.
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// SecurityLogContract implements the chaincode contract.
type SecurityLogContract struct {
	contractapi.Contract
}

// EventRecord mirrors src/ledger/base.py:EventRecord. Field names use
// lowerCamelCase JSON tags matching what the on-chain state actually
// stores; Python-side field names are snake_case (language convention on
// each side), and src/ledger/fabric_gateway.py performs the translation at
// the gateway boundary rather than either language pretending to share a
// field-naming convention with the other.
type EventRecord struct {
	EventID              string   `json:"event_id"`
	PayloadDigest         string   `json:"payload_digest"`
	ContentAddress        string   `json:"content_address"`
	ResourceID             string   `json:"resource_id"`
	ThreatCategory        string   `json:"threat_category"`
	Severity               string   `json:"severity"`
	CalibratedConfidence  float64  `json:"calibrated_confidence"`
	ModelDigest            string   `json:"model_digest"`
	AgentID                string   `json:"agent_id"`
	Signature              string   `json:"signature"`
	Timestamp              string   `json:"timestamp"`
	TransactionID          string   `json:"transaction_id"`
	MerkleRoot             *string  `json:"merkle_root,omitempty"`
}

const (
	eventKeyPrefix      = "EVENT~"
	provenanceKeyPrefix = "PROVENANCE~"
	// writerRoleAttribute is the Fabric CA identity attribute a detection
	// agent's certificate must carry with value "true" and ecert:true for
	// LogSecurityEvent / AnchorModelProvenance to succeed. Configuring the
	// CA to issue this attribute is part of network/scripts/network-up.sh.
	writerRoleAttribute = "phase2.detectionAgent"
	auditorRoleAttribute = "phase2.auditor"
)

// requireDetectionAgent enforces "only authenticated detection agents may
// write." A caller whose certificate lacks the writer attribute is
// rejected before any state mutation, not merely logged as suspicious.
func requireDetectionAgent(ctx contractapi.TransactionContextInterface) error {
	ok, found, err := cid.GetAttributeValue(ctx.GetStub(), writerRoleAttribute)
	if err != nil {
		return fmt.Errorf("failed to read client identity attribute: %w", err)
	}
	if !found || ok != "true" {
		return fmt.Errorf("submitting identity is not an authorised detection agent (missing %s=true attribute)", writerRoleAttribute)
	}
	return nil
}

// requireAuditorOrAgent enforces "any authorised auditor may read" while
// also allowing detection agents to read back their own writes.
func requireAuditorOrAgent(ctx contractapi.TransactionContextInterface) error {
	if auditorOK, found, _ := cid.GetAttributeValue(ctx.GetStub(), auditorRoleAttribute); found && auditorOK == "true" {
		return nil
	}
	if agentOK, found, _ := cid.GetAttributeValue(ctx.GetStub(), writerRoleAttribute); found && agentOK == "true" {
		return nil
	}
	return fmt.Errorf("submitting identity is neither an authorised auditor nor a detection agent")
}

// LogSecurityEvent commits one event's digest + essential metadata.
// eventJSON is the JSON-encoded EventRecord (without transaction_id, which
// this function fills in from the transaction's own ID for a canonical,
// tamper-evident linkage between the record and its commit).
func (c *SecurityLogContract) LogSecurityEvent(ctx contractapi.TransactionContextInterface, eventJSON string) (string, error) {
	if err := requireDetectionAgent(ctx); err != nil {
		return "", err
	}

	var record EventRecord
	if err := json.Unmarshal([]byte(eventJSON), &record); err != nil {
		return "", fmt.Errorf("invalid event record JSON: %w", err)
	}
	if record.EventID == "" || record.PayloadDigest == "" {
		return "", fmt.Errorf("event_id and payload_digest are required")
	}

	key, err := ctx.GetStub().CreateCompositeKey(eventKeyPrefix, []string{record.EventID})
	if err != nil {
		return "", err
	}
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", err
	}
	if existing != nil {
		return "", fmt.Errorf("event_id %s is already committed; ledger records are append-only and cannot be overwritten", record.EventID)
	}

	txID := ctx.GetStub().GetTxID()
	record.TransactionID = txID

	stored, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	if err := ctx.GetStub().PutState(key, stored); err != nil {
		return "", err
	}

	response := map[string]interface{}{
		"transaction_id": txID,
		"committed":      true,
		"block_number":   nil, // resolved by the caller from the commit event, not visible to chaincode itself
		"timestamp":      record.Timestamp,
	}
	out, _ := json.Marshal(response)
	return string(out), nil
}

// VerifyEvent confirms the ledger's stored digest for eventID equals
// payloadDigest exactly.
func (c *SecurityLogContract) VerifyEvent(ctx contractapi.TransactionContextInterface, eventID string, payloadDigest string) (string, error) {
	if err := requireAuditorOrAgent(ctx); err != nil {
		return "", err
	}
	record, err := c.getEvent(ctx, eventID)
	if err != nil {
		out, _ := json.Marshal(map[string]interface{}{"verified": false, "reason": err.Error()})
		return string(out), nil
	}
	verified := record.PayloadDigest == payloadDigest
	out, _ := json.Marshal(map[string]interface{}{"verified": verified})
	return string(out), nil
}

// QueryEventHistory retrieves the ordered audit trail, optionally filtered
// by resourceID and/or a [startTime, endTime] RFC3339 window. Empty string
// arguments mean "no filter on this dimension."
func (c *SecurityLogContract) QueryEventHistory(ctx contractapi.TransactionContextInterface, resourceID string, startTime string, endTime string) (string, error) {
	if err := requireAuditorOrAgent(ctx); err != nil {
		return "", err
	}

	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey(eventKeyPrefix, []string{})
	if err != nil {
		return "", err
	}
	defer iterator.Close()

	var records []EventRecord
	for iterator.HasNext() {
		kv, err := iterator.Next()
		if err != nil {
			return "", err
		}
		var record EventRecord
		if err := json.Unmarshal(kv.Value, &record); err != nil {
			continue
		}
		if resourceID != "" && record.ResourceID != resourceID {
			continue
		}
		if startTime != "" && record.Timestamp < startTime {
			continue
		}
		if endTime != "" && record.Timestamp > endTime {
			continue
		}
		records = append(records, record)
	}

	sort.Slice(records, func(i, j int) bool { return records[i].Timestamp < records[j].Timestamp })

	out, err := json.Marshal(records)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func (c *SecurityLogContract) getEvent(ctx contractapi.TransactionContextInterface, eventID string) (*EventRecord, error) {
	key, err := ctx.GetStub().CreateCompositeKey(eventKeyPrefix, []string{eventID})
	if err != nil {
		return nil, err
	}
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("no event found for event_id %s", eventID)
	}
	var record EventRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, err
	}
	return &record, nil
}

// AnchorModelProvenance commits a model_provenance.schema.json record,
// keyed by model_digest, once per retraining cycle.
func (c *SecurityLogContract) AnchorModelProvenance(ctx contractapi.TransactionContextInterface, provenanceJSON string) (string, error) {
	if err := requireDetectionAgent(ctx); err != nil {
		return "", err
	}
	var provenance map[string]interface{}
	if err := json.Unmarshal([]byte(provenanceJSON), &provenance); err != nil {
		return "", fmt.Errorf("invalid provenance record JSON: %w", err)
	}
	modelDigest, ok := provenance["model_digest"].(string)
	if !ok || modelDigest == "" {
		return "", fmt.Errorf("model_digest is required")
	}
	key, err := ctx.GetStub().CreateCompositeKey(provenanceKeyPrefix, []string{modelDigest})
	if err != nil {
		return "", err
	}
	if err := ctx.GetStub().PutState(key, []byte(provenanceJSON)); err != nil {
		return "", err
	}
	txID := ctx.GetStub().GetTxID()
	response := map[string]interface{}{
		"transaction_id": txID,
		"committed":      true,
		"block_number":   nil,
		"timestamp":      provenance["anchored_at"],
	}
	out, _ := json.Marshal(response)
	return string(out), nil
}

// GetModelProvenance looks up a previously anchored provenance record.
// Returns an empty JSON object ("{}") if none exists — never an error —
// so that "not yet anchored" is trivially distinguishable by callers from
// a genuine chaincode failure.
func (c *SecurityLogContract) GetModelProvenance(ctx contractapi.TransactionContextInterface, modelDigest string) (string, error) {
	if err := requireAuditorOrAgent(ctx); err != nil {
		return "", err
	}
	key, err := ctx.GetStub().CreateCompositeKey(provenanceKeyPrefix, []string{modelDigest})
	if err != nil {
		return "", err
	}
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return "", err
	}
	if data == nil {
		return "{}", nil
	}
	return string(data), nil
}

// RecomputeDigest is exposed as a convenience read-only transaction so an
// operator can sanity-check canonicalisation/digest agreement directly
// against the deployed chaincode using the published test vectors, without
// needing a full end-to-end LogSecurityEvent/VerifyEvent round trip.
func (c *SecurityLogContract) RecomputeDigest(ctx contractapi.TransactionContextInterface, eventJSONWithoutDigest string) (string, error) {
	var event map[string]interface{}
	decoder := json.NewDecoder(strings.NewReader(eventJSONWithoutDigest))
	decoder.UseNumber()
	if err := decoder.Decode(&event); err != nil {
		return "", fmt.Errorf("invalid event JSON: %w", err)
	}
	return DigestEvent(event)
}

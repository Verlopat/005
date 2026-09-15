package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vectorFile mirrors the structure written by
// Phase2_Blockchain_Logging/contracts/test_vectors/canonical_digest_vectors.json
// and read by scripts/validate_commit1.py on the Python side. This test is
// the Go half of the cross-language conformance procedure described in
// docs/canonicalisation_spec.md — it MUST reproduce every vector's
// expected_canonical string and expected_sha256 digest exactly.
type vectorFile struct {
	SpecVersion string   `json:"spec_version"`
	Vectors     []vector `json:"vectors"`
}

type vector struct {
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	Input              json.RawMessage `json:"input"`
	ExpectedCanonical  string          `json:"expected_canonical"`
	ExpectedSHA256     string          `json:"expected_sha256"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	// chaincode/securitylog/ -> Phase2_Blockchain_Logging/contracts/test_vectors/...
	path := filepath.Join("..", "..", "contracts", "test_vectors", "canonical_digest_vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read shared test vector file at %s: %v", path, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("could not parse vector file: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatalf("vector file contained no vectors")
	}
	return vf
}

func TestCanonicalDigestVectorsAgreeWithPython(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader(v.Input))
			decoder.UseNumber()
			var input map[string]interface{}
			if err := decoder.Decode(&input); err != nil {
				t.Fatalf("could not decode input for vector %q: %v", v.Name, err)
			}

			canonical, err := CanonicalString(input)
			if err != nil {
				t.Fatalf("vector %q: CanonicalString error: %v", v.Name, err)
			}
			if canonical != v.ExpectedCanonical {
				t.Fatalf("vector %q: canonical mismatch\n  expected: %s\n  got:      %s", v.Name, v.ExpectedCanonical, canonical)
			}

			digest := DigestHex([]byte(canonical))
			if digest != v.ExpectedSHA256 {
				t.Fatalf("vector %q: digest mismatch\n  expected: %s\n  got:      %s", v.Name, v.ExpectedSHA256, digest)
			}
		})
	}
}

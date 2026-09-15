package main

import (
	"crypto/sha256"
	"encoding/hex"
)

// DigestHex mirrors src/digest.py:digest_bytes — lowercase hex SHA-256.
func DigestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// DigestEvent mirrors src/digest.py:digest_event: strips payload_digest if
// present, canonicalises, and hashes.
func DigestEvent(event map[string]interface{}) (string, error) {
	stripped := make(map[string]interface{}, len(event))
	for k, v := range event {
		if k == "payload_digest" {
			continue
		}
		stripped[k] = v
	}
	canonical, err := CanonicalString(stripped)
	if err != nil {
		return "", err
	}
	return DigestHex([]byte(canonical)), nil
}

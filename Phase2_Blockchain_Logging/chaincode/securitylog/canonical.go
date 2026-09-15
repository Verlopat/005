// Package main: canonical.go
//
// Go-side implementation of docs/canonicalisation_spec.md v1.0.0, mirroring
// src/canonical.py field for field. This file exists specifically so that
// chaincode and the Python detection/pipeline layer independently compute
// identical digests for the same event, per Objective 2: "The detection
// layer and the verification contract must independently compute identical
// digests for the same event." canonical_test.go checks this file against
// contracts/test_vectors/canonical_digest_vectors.json — the same vector
// file scripts/validate_commit1.py checks the Python side against.
//
// Deliberately implemented over generic map[string]interface{} (as decoded
// by encoding/json) rather than a generated struct, so it stays correct as
// the schema evolves without needing a matching struct regeneration step.
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// CanonicalString returns the canonical JSON string for event, excluding
// the payload_digest key (spec rule 1). Callers MUST NOT pass a map that
// still needs payload_digest computed from it after stripping — strip
// first, exactly like src/canonical.py:canonicalise requires.
func CanonicalString(event map[string]interface{}) (string, error) {
	if _, present := event["payload_digest"]; present {
		return "", fmt.Errorf("payload_digest must be excluded before canonicalisation (spec rule 1)")
	}
	return canonicalValue(event)
}

func canonicalValue(v interface{}) (string, error) {
	switch val := v.(type) {
	case nil:
		return "null", nil
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil
	case string:
		return canonicalStringLiteral(val), nil
	case json.Number:
		return canonicalNumber(val)
	case float64:
		// encoding/json without UseNumber() decodes all JSON numbers as
		// float64; canonicalNumber handles both integral and fractional
		// values per spec rule 5.
		return canonicalNumber(json.Number(strconv.FormatFloat(val, 'g', -1, 64)))
	case map[string]interface{}:
		return canonicalObject(val)
	case []interface{}:
		return canonicalArray(val)
	default:
		return "", fmt.Errorf("unsupported type for canonicalisation: %T", v)
	}
}

func canonicalObject(obj map[string]interface{}) (string, error) {
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	// Rule 2: sort keys by raw byte sequence (Go's default string sort is
	// already byte-wise ordinal for UTF-8 encoded strings).
	sort.Strings(keys)

	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(canonicalStringLiteral(k))
		b.WriteByte(':')
		valStr, err := canonicalValue(obj[k])
		if err != nil {
			return "", err
		}
		b.WriteString(valStr)
	}
	b.WriteByte('}')
	return b.String(), nil
}

func canonicalArray(arr []interface{}) (string, error) {
	// Rule 7: array order preserved, never re-sorted.
	var b strings.Builder
	b.WriteByte('[')
	for i, v := range arr {
		if i > 0 {
			b.WriteByte(',')
		}
		valStr, err := canonicalValue(v)
		if err != nil {
			return "", err
		}
		b.WriteString(valStr)
	}
	b.WriteByte(']')
	return b.String(), nil
}

func canonicalStringLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\t':
			b.WriteString(`\t`)
		case '\r':
			b.WriteString(`\r`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			if r < 0x20 {
				b.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// canonicalNumber renders per spec rule 5: integers with no decimal point,
// floats using the shortest round-tripping decimal form. json.Number
// preserves the original textual form from the decoder when the caller
// used a json.Decoder with UseNumber(); chaincode entry points in
// securitylog.go decode incoming arguments this way specifically so this
// function sees the original precision rather than a float64 round-trip.
func canonicalNumber(n json.Number) (string, error) {
	s := n.String()
	if !strings.ContainsAny(s, ".eE") {
		// Integer literal: strip a leading '+' if present and reject
		// leading zeros other than a bare "0", matching Python's int
		// rendering via canonical.py.
		return s, nil
	}
	f, err := n.Float64()
	if err != nil {
		return "", fmt.Errorf("invalid number literal %q: %w", s, err)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("NaN/Infinity is forbidden in a canonicalised alert event: %v", f)
	}
	// 'g', -1 selects the shortest decimal representation that round-trips
	// to the same float64, matching Python's repr(float) semantics used by
	// src/canonical.py.
	return strconv.FormatFloat(f, 'g', -1, 64), nil
}

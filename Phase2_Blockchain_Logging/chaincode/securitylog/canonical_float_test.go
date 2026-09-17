package main

import (
	"math"
	"strconv"
	"testing"
)

// TestCanonicalFloatMatchesPythonRepr pins the float rendering that the
// cross-language digest agreement depends on.
//
// The Python producer (src/canonical.py) renders floats with repr(). Every
// expected value below is that repr() output, and is mirrored in
// tests/test_cross_language_float_rendering.py so both halves of the agreement
// are checked against the same table.
//
// Regression guard: canonicalFloat previously delegated to
// strconv.FormatFloat(f, 'g', -1, 64), which renders an integral 6.0 as "6"
// where Python renders "6.0", and 1e15 as "1e+15" where Python renders
// "1000000000000000.0". Either mismatch changes the canonical string, changes
// the SHA-256, and causes this peer to reject evidence the producer considers
// valid.
func TestCanonicalFloatMatchesPythonRepr(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0.0, "0.0"},
		{6.0, "6.0"},
		{1480.0, "1480.0"},
		{1500.0, "1500.0"},
		{0.412, "0.412"},
		{16251.95, "16251.95"},
		{0.0001, "0.0001"},
		{1e-05, "1e-05"},
		{8.135997203703995e-05, "8.135997203703995e-05"},
		{0.9997655153274536, "0.9997655153274536"},
		{0.303016, "0.303016"},
		{1e15, "1000000000000000.0"},
		{1234567890123456.0, "1234567890123456.0"},
		{1e16, "1e+16"},
		{1.5e16, "1.5e+16"},
		{2e13, "20000000000000.0"},
		{-6.0, "-6.0"},
		{-0.5, "-0.5"},
		{5e-324, "5e-324"},
		{1.7976931348623157e308, "1.7976931348623157e+308"},
	}
	for _, c := range cases {
		if got := canonicalFloat(c.in); got != c.want {
			t.Errorf("canonicalFloat(%v) = %q, want %q (Python repr)", c.in, got, c.want)
		}
	}
}

// TestIntegralFloatsKeepFractionalPart isolates the divergence that affected
// ordinary alerts: feature vectors carry integral floats (byte counts, packet
// counts, protocol numbers, ports) in almost every event.
func TestIntegralFloatsKeepFractionalPart(t *testing.T) {
	for _, v := range []float64{1.0, 6.0, 42.0, 1480.0, 65535.0, 1e6} {
		got := canonicalFloat(v)
		if len(got) < 2 || got[len(got)-2:] != ".0" {
			t.Errorf("canonicalFloat(%v) = %q, want a trailing \".0\"", v, got)
		}
	}
}

// TestCanonicalFloatRoundTrips checks that the rendered form always parses back
// to the identical float64, so the shortest-round-trip property the spec
// requires is not lost by the formatting rules above.
func TestCanonicalFloatRoundTrips(t *testing.T) {
	values := []float64{
		0.0, 1.0, -1.0, 0.1, 1.0 / 3.0, 1e-7, 1e-5, 0.0001, 6.0, 1480.0,
		1e15, 1e16, 1e17, 2e13, 8.135997203703995e-05, 0.9997655153274536,
		math.MaxFloat64, math.SmallestNonzeroFloat64,
	}
	for _, v := range values {
		got := canonicalFloat(v)
		parsed, err := strconv.ParseFloat(got, 64)
		if err != nil {
			t.Errorf("canonicalFloat(%v) = %q, which does not parse: %v", v, got, err)
			continue
		}
		if parsed != v {
			t.Errorf("canonicalFloat(%v) = %q, which parses back to %v", v, got, parsed)
		}
	}
}

// TestCanonicalFloatThresholds pins the decimal/exponent boundary itself, since
// an off-by-one there silently changes the digest of large feature values.
func TestCanonicalFloatThresholds(t *testing.T) {
	// Decimal notation up to and including exponent 15.
	if got := canonicalFloat(1e15); got != "1000000000000000.0" {
		t.Errorf("1e15 rendered as %q, want decimal notation", got)
	}
	// Exponent notation from exponent 16 upward.
	if got := canonicalFloat(1e16); got != "1e+16" {
		t.Errorf("1e16 rendered as %q, want exponent notation", got)
	}
	// Decimal notation down to exponent -4.
	if got := canonicalFloat(1e-4); got != "0.0001" {
		t.Errorf("1e-4 rendered as %q, want decimal notation", got)
	}
	// Exponent notation from exponent -5 downward.
	if got := canonicalFloat(1e-5); got != "1e-05" {
		t.Errorf("1e-5 rendered as %q, want exponent notation", got)
	}
}

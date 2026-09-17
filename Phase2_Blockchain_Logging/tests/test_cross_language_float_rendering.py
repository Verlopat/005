"""Cross-language float rendering agreement between canonical.py and canonical.go.

Objective 2 depends on Python and Go producing *byte-identical* canonical
strings: the Python detection-side producer computes a digest, and the Go
chaincode recomputes it on the peer. If the two disagree on how a single float
renders, the peer rejects evidence the producer considers valid.

Float rendering is the fragile part of that agreement. These tests pin the rule
and verify the Go implementation's algorithm against Python's actual output.

Why the Go algorithm is re-implemented here
-------------------------------------------
Go is not installed in every environment this suite runs in, so
``go test ./chaincode/securitylog`` cannot be relied on as the only check.
``go_canonical_float`` below is a line-for-line transcription of
``canonicalFloat`` in ``chaincode/securitylog/canonical.go``. Testing it against
Python's ``repr`` catches a divergence in the Go *algorithm* here, in CI, without
a Go toolchain. It does not replace running the Go tests - a transcription can
drift from the original - so ``go test`` remains required on a host with Go, and
``test_transcription_matches_go_source`` guards the transcription against the
most likely drift.

Background: the Go implementation previously used
``strconv.FormatFloat(f, 'g', -1, 64)``, which renders an integral float ``6.0``
as ``"6"`` where Python renders ``"6.0"``. Feature vectors are full of integral
floats, so that divergence affected ordinary alerts, not edge cases.
"""
from pathlib import Path

import pytest

from src.canonical import canonicalise

PHASE2_ROOT = Path(__file__).resolve().parent.parent
CANONICAL_GO = PHASE2_ROOT / "chaincode" / "securitylog" / "canonical.go"

# Python's repr uses decimal notation for decimal exponents in this range.
DECIMAL_EXPONENT_MIN = -4
DECIMAL_EXPONENT_MAX = 15


def go_canonical_float(f: float) -> str:
    """Transcription of canonicalFloat() from canonical.go."""
    if f == 0:
        # math.Signbit(f)
        import math as _math

        return "-0.0" if _math.copysign(1.0, f) < 0 else "0.0"

    # strconv.FormatFloat(f, 'e', -1, 64) -> shortest round-trip, scientific.
    sci = _go_format_e(f)
    epos = sci.index("e")
    exp = int(sci[epos + 1:])

    if DECIMAL_EXPONENT_MIN <= exp <= DECIMAL_EXPONENT_MAX:
        # strconv.FormatFloat(f, 'f', -1, 64)
        s = _go_format_f(f)
        if "." not in s:
            s += ".0"
        return s

    mantissa = sci[:epos]
    sign = "+"
    if exp < 0:
        sign = "-"
        exp = -exp
    return f"{mantissa}e{sign}{exp:02d}"


def _go_format_e(f: float) -> str:
    """Equivalent of Go strconv.FormatFloat(f, 'e', -1, 64)."""
    # Python's repr gives shortest round-trip digits; reformat into Go's 'e'
    # shape: d[.ddd]e±dd with no trailing zeros in the mantissa.
    mantissa, _, exponent = f"{f:.17e}".partition("e")
    # Find the shortest mantissa that still round-trips.
    for precision in range(0, 18):
        candidate = f"{f:.{precision}e}"
        if float(candidate) == f:
            mantissa, _, exponent = candidate.partition("e")
            break
    mantissa = mantissa.rstrip("0").rstrip(".") if "." in mantissa else mantissa
    exp_value = int(exponent)
    sign = "+" if exp_value >= 0 else "-"
    return f"{mantissa}e{sign}{abs(exp_value):02d}"


def _go_format_f(f: float) -> str:
    """Equivalent of Go strconv.FormatFloat(f, 'f', -1, 64)."""
    for precision in range(0, 18):
        candidate = f"{f:.{precision}f}"
        if float(candidate) == f:
            return candidate.rstrip("0").rstrip(".") if "." in candidate else candidate
    return repr(f)


# Values chosen to cover every branch and both threshold boundaries.
CASES = [
    (0.0, "0.0"),
    (6.0, "6.0"),
    (1480.0, "1480.0"),
    (1500.0, "1500.0"),
    (0.412, "0.412"),
    (16251.95, "16251.95"),
    (0.0001, "0.0001"),
    (1e-05, "1e-05"),
    (8.135997203703995e-05, "8.135997203703995e-05"),
    (0.9997655153274536, "0.9997655153274536"),
    (0.303016, "0.303016"),
    (1e15, "1000000000000000.0"),
    (1234567890123456.0, "1234567890123456.0"),
    (1e16, "1e+16"),
    (1.5e16, "1.5e+16"),
    (2e13, "20000000000000.0"),
    (-6.0, "-6.0"),
    (-0.5, "-0.5"),
    (5e-324, "5e-324"),
    (1.7976931348623157e308, "1.7976931348623157e+308"),
]


@pytest.mark.parametrize("value,expected", CASES)
def test_python_canonicalisation_matches_expected_rendering(value, expected):
    """canonical.py must render exactly these strings."""
    assert canonicalise({"v": value}) == '{"v":%s}' % expected


@pytest.mark.parametrize("value,expected", CASES)
def test_go_algorithm_matches_expected_rendering(value, expected):
    assert go_canonical_float(value) == expected


@pytest.mark.parametrize("value,_expected", CASES)
def test_go_algorithm_agrees_with_python(value, _expected):
    assert go_canonical_float(value) == repr(value)


def test_integral_floats_keep_their_fractional_part():
    """The specific divergence that made Go reject valid Python digests."""
    for value in (1.0, 6.0, 42.0, 1480.0, 65535.0, 1e6):
        rendered = go_canonical_float(value)
        assert rendered.endswith(".0"), rendered
        assert rendered == repr(value)


def test_agreement_over_many_values():
    """Randomised agreement check across a wide magnitude range."""
    import random

    rng = random.Random(20260917)
    for _ in range(4000):
        exponent = rng.randint(-320, 300)
        mantissa = rng.uniform(-10.0, 10.0)
        value = mantissa * (10.0 ** exponent)
        if value in (float("inf"), float("-inf")) or value != value:
            continue
        assert go_canonical_float(value) == repr(value), value

    for _ in range(2000):
        value = float(rng.randint(-10**9, 10**9))
        assert go_canonical_float(value) == repr(value), value


def test_transcription_matches_go_source():
    """Guard the transcription against the most likely kinds of drift.

    If canonical.go stops implementing the rule this file transcribes, this test
    fails and points at the mismatch, instead of the suite silently validating a
    stale copy of the algorithm.
    """
    source = CANONICAL_GO.read_text(encoding="utf-8")
    assert "func canonicalFloat(" in source, "canonicalFloat was renamed or removed"
    assert f"exp >= {DECIMAL_EXPONENT_MIN} && exp <= {DECIMAL_EXPONENT_MAX}" in source, (
        "the decimal/exponent threshold in canonical.go no longer matches this test"
    )
    assert 's += ".0"' in source, "canonical.go no longer forces a fractional part"
    assert "'e', -1, 64" in source, "canonical.go no longer reads the exponent exactly"
    assert "'f', -1, 64" in source, "canonical.go no longer uses decimal formatting"
    # The formatter that caused the original divergence must not be reintroduced
    # as the final rendering step.
    assert "return strconv.FormatFloat(f, 'g', -1, 64), nil" not in source, (
        "canonical.go reverted to 'g' formatting, which disagrees with Python "
        "on integral floats"
    )

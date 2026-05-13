"""
test_suite.py  —  Day 6: Automated Test Suite
Run:  python test_suite.py
Covers: parser, SPF logic, DKIM detection, DMARC alignment, scorer, edge cases.
"""
import sys
import os
import traceback
from dataclasses import dataclass
from typing import Callable

# ── tiny test framework so we need zero external deps ─────────────────────────
@dataclass
class TestResult:
    name:    str
    passed:  bool
    message: str = ""

_results: list[TestResult] = []

def test(name: str):
    """Decorator that registers a test function."""
    def decorator(fn: Callable):
        try:
            fn()
            _results.append(TestResult(name, True))
        except AssertionError as e:
            _results.append(TestResult(name, False, str(e)))
        except Exception as e:
            _results.append(TestResult(name, False, f"{type(e).__name__}: {e}"))
        return fn
    return decorator

def assert_eq(actual, expected, msg=""):
    if actual != expected:
        raise AssertionError(
            f"{msg}\n    Expected: {expected!r}\n    Got:      {actual!r}")

def assert_in(item, container, msg=""):
    if item not in container:
        raise AssertionError(f"{msg}\n    {item!r} not in {container!r}")

def assert_true(val, msg=""):
    if not val:
        raise AssertionError(msg or f"Expected truthy, got {val!r}")

def assert_ge(a, b, msg=""):
    if a < b:
        raise AssertionError(msg or f"{a} < {b}")

def assert_le(a, b, msg=""):
    if a > b:
        raise AssertionError(msg or f"{a} > {b}")


# ── imports ───────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))
from parser  import parse_email, _extract_domain
from checker import check_spf, check_dkim, SPFResult, DKIMResult
from dmarc   import check_dmarc, DMARCResult, DMARCPolicy, _domains_aligned
from scorer  import compute_score

# re-import internal helpers
from parser  import _extract_domain
from checker import _ip_in_cidr, _resolve_to_ips
from dmarc   import _domains_aligned


# ══════════════════════════════════════════════════════════════════════════════
# PARSER TESTS
# ══════════════════════════════════════════════════════════════════════════════

@test("Parser: extract_domain from plain address")
def _():
    assert_eq(_extract_domain("user@example.com"), "example.com")

@test("Parser: extract_domain from display name address")
def _():
    assert_eq(_extract_domain("John Doe <john@mail.google.com>"), "mail.google.com")

@test("Parser: extract_domain returns None for empty string")
def _():
    assert_eq(_extract_domain(""), None)

@test("Parser: extract_domain lowercases result")
def _():
    assert_eq(_extract_domain("USER@EXAMPLE.COM"), "example.com")

@test("Parser: legitimate.eml - from_domain is google.com")
def _():
    h = parse_email("samples/legitimate.eml")
    assert_eq(h.from_domain, "google.com")

@test("Parser: legitimate.eml - has DKIM signature header")
def _():
    h = parse_email("samples/legitimate.eml")
    assert_true(h.dkim_signature, "DKIM-Signature should be present")

@test("Parser: legitimate.eml - no suspicious flags")
def _():
    h = parse_email("samples/legitimate.eml")
    bad = [f for f in h.flags if f not in ("NO_DKIM_SIGNATURE","NO_SPF_RESULT_HEADER")]
    assert_eq(bad, [], "Should have no domain mismatch flags")

@test("Parser: spoofed.eml - REPLY_TO_DOMAIN_MISMATCH flag raised")
def _():
    h = parse_email("samples/spoofed.eml")
    assert_in("REPLY_TO_DOMAIN_MISMATCH", h.flags)

@test("Parser: spoofed.eml - RETURN_PATH_DOMAIN_MISMATCH flag raised")
def _():
    h = parse_email("samples/spoofed.eml")
    assert_in("RETURN_PATH_DOMAIN_MISMATCH", h.flags)

@test("Parser: spoofed.eml - SENDER_FROM_MISMATCH flag raised")
def _():
    h = parse_email("samples/spoofed.eml")
    assert_in("SENDER_FROM_MISMATCH", h.flags)

@test("Parser: spoofed.eml - originating IP extracted")
def _():
    h = parse_email("samples/spoofed.eml")
    assert_eq(h.originating_ip, "185.220.101.45")

@test("Parser: internal_spoof.eml - reply_to domain differs from from_domain")
def _():
    h = parse_email("samples/internal_spoof.eml")
    assert_in("REPLY_TO_DOMAIN_MISMATCH", h.flags)

@test("Parser: received chain is a list")
def _():
    h = parse_email("samples/spoofed.eml")
    assert_true(isinstance(h.received_chain, list))
    assert_ge(len(h.received_chain), 1)


# ══════════════════════════════════════════════════════════════════════════════
# SPF TESTS
# ══════════════════════════════════════════════════════════════════════════════

@test("SPF: ip_in_cidr - IP inside range")
def _():
    assert_true(_ip_in_cidr("209.85.220.41", "209.85.128.0/17"))

@test("SPF: ip_in_cidr - IP outside range")
def _():
    assert_true(not _ip_in_cidr("1.2.3.4", "209.85.128.0/17"))

@test("SPF: ip_in_cidr - exact /32 match")
def _():
    assert_true(_ip_in_cidr("8.8.8.8", "8.8.8.8/32"))

@test("SPF: ip_in_cidr - bad CIDR returns False gracefully")
def _():
    assert_true(not _ip_in_cidr("1.2.3.4", "notacidr"))

@test("SPF: no sender domain → NONE result")
def _():
    r = check_spf("", "1.2.3.4")
    assert_eq(r.result, SPFResult.NONE)

@test("SPF: no sender IP → NONE result")
def _():
    r = check_spf("gmail.com", "")
    assert_eq(r.result, SPFResult.NONE)

@test("SPF: gmail.com + authorised Google IP → PASS")
def _():
    r = check_spf("gmail.com", "209.85.220.41")
    assert_eq(r.result, SPFResult.PASS, "Google IP should pass Gmail SPF")

@test("SPF: gmail.com + random IP → not PASS")
def _():
    r = check_spf("gmail.com", "1.2.3.4")
    assert_true(r.result != SPFResult.PASS, "Random IP should not pass Gmail SPF")

@test("SPF: nonexistent domain → NONE")
def _():
    r = check_spf("this-domain-definitely-does-not-exist-xyz123.com", "1.2.3.4")
    assert_eq(r.result, SPFResult.NONE)


# ══════════════════════════════════════════════════════════════════════════════
# DKIM TESTS
# ══════════════════════════════════════════════════════════════════════════════

@test("DKIM: spoofed.eml → NONE (no signature header)")
def _():
    with open("samples/spoofed.eml", "rb") as f:
        r = check_dkim(f.read())
    assert_eq(r.result, DKIMResult.NONE)

@test("DKIM: legitimate.eml → FAIL or PERMERROR (fake sig, real check)")
def _():
    # Our sample .eml has a fake DKIM sig so it won't verify against real DNS
    # But it MUST NOT return NONE — the header is present
    with open("samples/legitimate.eml", "rb") as f:
        r = check_dkim(f.read())
    assert_true(r.result != DKIMResult.NONE,
        "Legitimate sample has DKIM header — should not return NONE")

@test("DKIM: legitimate.eml - selector extracted correctly")
def _():
    with open("samples/legitimate.eml", "rb") as f:
        r = check_dkim(f.read())
    assert_true(r.selector is not None, "Selector should be extracted from header")

@test("DKIM: raw bytes with no headers → NONE")
def _():
    r = check_dkim(b"From: test@example.com\n\nHello world")
    assert_eq(r.result, DKIMResult.NONE)


# ══════════════════════════════════════════════════════════════════════════════
# DMARC TESTS
# ══════════════════════════════════════════════════════════════════════════════

@test("DMARC: domain alignment - relaxed, subdomain ok")
def _():
    assert_true(_domains_aligned("google.com", "mail.google.com", relaxed=True))

@test("DMARC: domain alignment - strict, subdomain not ok")
def _():
    assert_true(not _domains_aligned("google.com", "mail.google.com", relaxed=False))

@test("DMARC: domain alignment - exact match always ok")
def _():
    assert_true(_domains_aligned("google.com", "google.com", relaxed=False))

@test("DMARC: domain alignment - different org domains → False")
def _():
    assert_true(not _domains_aligned("google.com", "attacker.com", relaxed=True))

@test("DMARC: no from_domain → NONE result")
def _():
    r = check_dmarc("", None, False, None, False)
    assert_eq(r.result, DMARCResult.NONE)

@test("DMARC: gmail.com has a real DMARC record")
def _():
    r = check_dmarc("gmail.com", "gmail.com", True, "gmail.com", True)
    assert_true(r.result != DMARCResult.NONE,
        "gmail.com should have a DMARC record")

@test("DMARC: spoofed domain (suspicious-mailer.xyz) → FAIL or NONE")
def _():
    r = check_dmarc("sbi.co.in", "suspicious-mailer.xyz", False, None, False)
    assert_true(r.result in (DMARCResult.FAIL, DMARCResult.NONE))

@test("DMARC: aligned SPF → PASS")
def _():
    r = check_dmarc("gmail.com", "gmail.com", True, None, False)
    assert_eq(r.result, DMARCResult.PASS,
        "SPF passing with aligned domain should give DMARC PASS")


# ══════════════════════════════════════════════════════════════════════════════
# SCORER TESTS
# ══════════════════════════════════════════════════════════════════════════════

from checker import SPFCheckResult, DKIMCheckResult
from dmarc   import DMARCCheckResult

def _make_spf(result):
    return SPFCheckResult(result, "test")

def _make_dkim(result):
    return DKIMCheckResult(result, "test")

def _make_dmarc(result, policy=DMARCPolicy.NONE):
    return DMARCCheckResult(result, policy, "test")

@test("Scorer: all pass → score >= 80")
def _():
    h = parse_email("samples/legitimate.eml")
    h.flags = []
    s = compute_score(h, _make_spf(SPFResult.PASS),
                         _make_dkim(DKIMResult.PASS),
                         _make_dmarc(DMARCResult.PASS, DMARCPolicy.REJECT))
    assert_ge(s.score, 80, f"All-pass score should be ≥80, got {s.score}")

@test("Scorer: all fail → score <= 20")
def _():
    h = parse_email("samples/spoofed.eml")
    s = compute_score(h, _make_spf(SPFResult.FAIL),
                         _make_dkim(DKIMResult.FAIL),
                         _make_dmarc(DMARCResult.FAIL, DMARCPolicy.REJECT))
    assert_le(s.score, 20, f"All-fail score should be ≤20, got {s.score}")

@test("Scorer: score is always 0–100")
def _():
    h = parse_email("samples/spoofed.eml")
    s = compute_score(h, _make_spf(SPFResult.FAIL),
                         _make_dkim(DKIMResult.FAIL),
                         _make_dmarc(DMARCResult.FAIL))
    assert_ge(s.score, 0)
    assert_le(s.score, 100)

@test("Scorer: SPF softfail deducts less than hard fail")
def _():
    h = parse_email("samples/legitimate.eml")
    h.flags = []
    s_hard = compute_score(h, _make_spf(SPFResult.FAIL),
                               _make_dkim(DKIMResult.PASS),
                               _make_dmarc(DMARCResult.PASS, DMARCPolicy.REJECT))
    s_soft = compute_score(h, _make_spf(SPFResult.SOFTFAIL),
                               _make_dkim(DKIMResult.PASS),
                               _make_dmarc(DMARCResult.PASS, DMARCPolicy.REJECT))
    assert_true(s_soft.score > s_hard.score,
        f"Softfail ({s_soft.score}) should score higher than hard fail ({s_hard.score})")

@test("Scorer: verdict is one of 3 known strings")
def _():
    h = parse_email("samples/legitimate.eml")
    s = compute_score(h, _make_spf(SPFResult.PASS),
                         _make_dkim(DKIMResult.PASS),
                         _make_dmarc(DMARCResult.PASS, DMARCPolicy.REJECT))
    assert_in(s.verdict, ["Likely Legitimate", "Suspicious", "Likely Spoofed / Phishing"])

@test("Scorer: spoofed.eml full pipeline → Likely Spoofed")
def _():
    h = parse_email("samples/spoofed.eml")
    with open("samples/spoofed.eml", "rb") as f:
        spf  = check_spf(h.return_path_domain or "", h.originating_ip or "")
        dkim = check_dkim(f.read())
    dmarc = check_dmarc(h.from_domain, h.return_path_domain,
                        spf.result == SPFResult.PASS,
                        dkim.signing_domain,
                        dkim.result == DKIMResult.PASS)
    s = compute_score(h, spf, dkim, dmarc)
    assert_eq(s.verdict, "Likely Spoofed / Phishing",
        f"Spoofed email verdict should be 'Likely Spoofed / Phishing', got '{s.verdict}'")


# ══════════════════════════════════════════════════════════════════════════════
# EDGE CASE TESTS
# ══════════════════════════════════════════════════════════════════════════════

@test("Edge: homograph domain (paypa1.com) parsed correctly")
def _():
    h = parse_email("samples/homograph.eml")
    assert_eq(h.from_domain, "paypa1.com", "Lookalike domain should parse as-is")

@test("Edge: partial_auth.eml parses without crash")
def _():
    h = parse_email("samples/partial_auth.eml")
    assert_true(h.from_domain is not None)

@test("Edge: empty email string doesn't crash parser")
def _():
    h = parse_email("From: a@b.com\n\nHello")
    assert_eq(h.from_domain, "b.com")

@test("Edge: email with no From header still parses")
def _():
    h = parse_email("Subject: Test\n\nNo from header")
    assert_eq(h.from_address, "")

@test("Edge: SPF with IPv6 address format doesn't crash")
def _():
    r = check_spf("gmail.com", "2607:f8b0:4023:c0b::1a")
    assert_true(r.result in list(SPFResult))   # any valid result, no exception


# ══════════════════════════════════════════════════════════════════════════════
# PRINT RESULTS
# ══════════════════════════════════════════════════════════════════════════════

def print_results():
    passed = sum(1 for r in _results if r.passed)
    failed = len(_results) - passed

    print()
    print("=" * 64)
    print(f"  TEST RESULTS  —  {passed} passed / {failed} failed / {len(_results)} total")
    print("=" * 64)

    categories = {}
    for r in _results:
        cat = r.name.split(":")[0].strip()
        categories.setdefault(cat, []).append(r)

    for cat, tests in categories.items():
        cat_pass = sum(1 for t in tests if t.passed)
        print(f"\n  [{cat}]  {cat_pass}/{len(tests)}")
        for t in tests:
            icon = "✓" if t.passed else "✗"
            name = t.name.split(":", 1)[1].strip() if ":" in t.name else t.name
            print(f"    {icon}  {name}")
            if not t.passed and t.message:
                for line in t.message.strip().splitlines():
                    print(f"         {line}")

    print()
    print("=" * 64)
    if failed == 0:
        print("  ✓  ALL TESTS PASSED — project is solid!")
    else:
        print(f"  ✗  {failed} test(s) failed — review above")
    print("=" * 64)
    print()
    return failed


if __name__ == "__main__":
    failed = print_results()
    sys.exit(0 if failed == 0 else 1)
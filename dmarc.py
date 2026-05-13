import dns.resolver
import re
from dataclasses import dataclass
from typing import Optional
from enum import Enum


class DMARCPolicy(Enum):
    NONE       = "none"        
    QUARANTINE = "quarantine"  
    REJECT     = "reject"      
    MISSING    = "missing"     # No DMARC record found


class DMARCResult(Enum):
    PASS    = "pass"    
    FAIL    = "fail"    
    NONE    = "none"    # No DMARC record
    ERROR   = "error"   # DNS error


@dataclass
class DMARCCheckResult:
    result:         DMARCResult
    policy:         DMARCPolicy
    reason:         str
    raw_record:     Optional[str] = None
    spf_aligned:    Optional[bool] = None  
    dkim_aligned:   Optional[bool] = None   
    pct:            int = 100               # % of mail policy applies to
    rua:            Optional[str] = None    # Aggregate report address


def _get_dmarc_record(domain: str) -> Optional[str]:
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=5)
        for rdata in answers:
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=DMARC1"):
                return txt
    except Exception:
        pass
    return None


def _parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    return tags


def _domains_aligned(from_domain: str, auth_domain: str, relaxed: bool = True) -> bool:
    if not from_domain or not auth_domain:
        return False
    from_domain  = from_domain.lower().strip(".")
    auth_domain  = auth_domain.lower().strip(".")
    if relaxed:
        # Extract org domain: last two labels  
        def org(d):
            parts = d.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else d
        return org(from_domain) == org(auth_domain)
    return from_domain == auth_domain

# SPF DOMAIN REPRESENTS return-Path domain (used in SPF)# d= tag from DKIM-Signature

def check_dmarc(from_domain,spf_domain:Optional[str],spf_passed,dkim_domain:Optional[str],dkim_passed):
    # DMARC passes if at least one of these is true:
      # - SPF passed AND SPF domain aligns with From domain
      # - DKIM passed AND DKIM domain aligns with From domain
    
    if not from_domain:
        return DMARCCheckResult(DMARCResult.NONE, DMARCPolicy.MISSING,
                                "No From domain to check DMARC for")

    record = _get_dmarc_record(from_domain)
    if not record:
        return DMARCCheckResult(DMARCResult.NONE, DMARCPolicy.MISSING,
                                f"No DMARC record at _dmarc.{from_domain}")

    tags   = _parse_dmarc(record)
    policy = DMARCPolicy(tags.get("p", "none"))
    pct    = int(tags.get("pct", "100"))
    rua    = tags.get("rua")

    aspf_relaxed  = tags.get("aspf", "r") == "r"
    adkim_relaxed = tags.get("adkim", "r") == "r"

    spf_aligned  = spf_passed  and _domains_aligned(from_domain, spf_domain,  aspf_relaxed)
    dkim_aligned = dkim_passed and _domains_aligned(from_domain, dkim_domain, adkim_relaxed)

    if spf_aligned or dkim_aligned:
        reasons = []
        if spf_aligned:  reasons.append("SPF aligned")
        if dkim_aligned: reasons.append("DKIM aligned")
        return DMARCCheckResult(
            DMARCResult.PASS, policy,
            f"DMARC passed ({', '.join(reasons)}); policy={policy.value}",
            record, spf_aligned, dkim_aligned, pct, rua
        )
    else:
        return DMARCCheckResult(
            DMARCResult.FAIL, policy,
            f"DMARC FAILED — neither SPF nor DKIM aligned with From domain; policy={policy.value}",
            record, spf_aligned, dkim_aligned, pct, rua
        )
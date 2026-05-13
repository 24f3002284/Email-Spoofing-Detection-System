from dataclasses import dataclass, field
from typing import Optional
from checker   import SPFResult, DKIMResult, SPFCheckResult, DKIMCheckResult
from dmarc     import DMARCResult, DMARCPolicy, DMARCCheckResult
from parser    import EmailHeaders
from lookalike import check_lookalike

SPF_PENALTIES = {
    SPFResult.FAIL:      (35, "SPF hard fail",    "Sending IP explicitly rejected by domain"),
    SPFResult.SOFTFAIL:  (20, "SPF softfail",     "Sending IP probably not authorised (~all)"),
    SPFResult.NEUTRAL:   (10, "SPF neutral",      "Domain makes no claim about this IP"),
    SPFResult.NONE:      (15, "No SPF record",    "Domain has no SPF policy published"),
    SPFResult.PERMERROR: (10, "SPF error",        "Malformed SPF record"),
    SPFResult.TEMPERROR: (5,  "SPF temp error",   "DNS timeout during SPF lookup"),
    SPFResult.PASS:      (0,  "SPF pass",         "Sender IP is authorised"),
}

DKIM_PENALTIES = {
    DKIMResult.FAIL:     (30, "DKIM fail",        "Signature present but cryptographically invalid"),
    DKIMResult.NONE:     (20, "No DKIM signature","Email was not signed — cannot verify integrity"),
    DKIMResult.PERMERROR:(15, "DKIM error",       "Signature malformed or public key missing"),
    DKIMResult.TEMPERROR:(5,  "DKIM temp error",  "DNS timeout fetching DKIM public key"),
    DKIMResult.PASS:     (0,  "DKIM pass",        "Signature verified"),
}

DMARC_PENALTIES = {
    DMARCResult.FAIL:    (25, "DMARC fail",       "From domain not aligned with SPF or DKIM"),
    DMARCResult.NONE:    (10, "No DMARC record",  "Domain publishes no DMARC policy"),
    DMARCResult.ERROR:   (5,  "DMARC error",      "DNS error during DMARC lookup"),
    DMARCResult.PASS:    (0,  "DMARC pass",       "From domain properly aligned"),
}

HEADER_FLAG_PENALTIES = {
    "REPLY_TO_DOMAIN_MISMATCH":    (15, "Reply-To domain mismatch","Replies go to a different domain than From"),
    "RETURN_PATH_DOMAIN_MISMATCH": (10, "Return-Path domain mismatch","Bounce address belongs to a different domain than From"),
    "SENDER_FROM_MISMATCH":        (10, "Sender header mismatch","Sender: header disagrees with From: header"),
    "NO_DKIM_SIGNATURE":           (0,  "No DKIM header","Already penalised under DKIM checks"),   # avoid double-count
    "NO_SPF_RESULT_HEADER":        (0,  "No SPF result header","Already penalised under SPF checks"),
}

@dataclass
class ScoreDetail:
    category:    str          # SPF / DKIM / DMARC / Header
    label:       str          # Short name
    deduction:   int         
    explanation: str          

@dataclass
class RiskScore:
    score:       int                          
    verdict:     str                          
    color:       str                          
    details:     list = field(default_factory=list)   # List[ScoreDetail]
    total_deducted: int = 0

def _verdict(score):
    if score >= 80:
        return "Likely Legitimate", "green"
    elif score >= 50:
        return "Suspicious", "yellow"
    else:
        return "Likely Spoofed / Phishing", "red"

def compute_score(headers,spf_result,dkim_result,dmarc_result):
    details = []
    total_deducted = 0

    deduction, label, explanation = SPF_PENALTIES.get(spf_result.result, (10, "SPF unknown", "Unrecognised SPF result"))
    details.append(ScoreDetail("SPF", label, deduction, explanation))
    total_deducted += deduction

    deduction, label, explanation = DKIM_PENALTIES.get(dkim_result.result, (10, "DKIM unknown", "Unrecognised DKIM result"))
    details.append(ScoreDetail("DKIM", label, deduction, explanation))
    total_deducted += deduction

    deduction, label, explanation = DMARC_PENALTIES.get(dmarc_result.result, (10, "DMARC unknown", "Unrecognised DMARC result"))
    details.append(ScoreDetail("DMARC", label, deduction, explanation))
    total_deducted += deduction

    for flag in headers.flags:
        if flag in HEADER_FLAG_PENALTIES:
            deduction, label, explanation = HEADER_FLAG_PENALTIES[flag]
            if deduction > 0:
                details.append(ScoreDetail("Header", label, deduction, explanation))
                total_deducted += deduction

    # If DMARC is missing and SPF/DKIM also failed, add extra penalty
    if (dmarc_result.result == DMARCResult.NONE and spf_result.result in (SPFResult.FAIL, SPFResult.SOFTFAIL, SPFResult.NONE) and
            dkim_result.result in (DKIMResult.FAIL, DKIMResult.NONE)):
        extra = 10
        details.append(ScoreDetail("Combined", "No authentication at all",
                                   extra, "SPF, DKIM, and DMARC all failed/missing"))
        total_deducted += extra

    score = max(0, 100 - total_deducted)
    verdict, color = _verdict(score)

    return RiskScore(score=score, verdict=verdict, color=color, details=details, total_deducted=total_deducted)

def compute_score_with_lookalike(headers, spf_result, dkim_result, dmarc_result):
    score_obj = compute_score(headers, spf_result, dkim_result, dmarc_result)

    lookalike_deduction = 0
    if headers.from_domain:
        result = check_lookalike(headers.from_domain)
        if result["is_lookalike"] and result["best_match"]:
            sim = result["best_score"]
            # if similarity is 80% ,points to be deducted is -10, 90% = -20, 95%+ = -25
            if sim >= 95:
                lookalike_deduction = 25
            elif sim >= 90:
                lookalike_deduction = 20
            else:
                lookalike_deduction = 10

            score_obj.details.append(ScoreDetail("Lookalike",f"Domain resembles {result['best_match']}",lookalike_deduction,f"'{headers.from_domain}' is {sim}% similar to trusted domain '{result['best_match']}' — possible homograph attack"))
            score_obj.total_deducted += lookalike_deduction
            score_obj.score = max(0, score_obj.score - lookalike_deduction)
            score_obj.verdict, score_obj.color = _verdict(score_obj.score)

    return score_obj
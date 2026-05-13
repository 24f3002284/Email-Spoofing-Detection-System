import dns.resolver, dns.exception, re, ipaddress
from dataclasses import dataclass
from typing import Optional
from enum import Enum

class SPFResult(Enum): # created, not as variables, but as properties of the class, bcz we can export this class and use the prop. in other files.
    PASS="pass"; FAIL="fail"; SOFTFAIL="softfail"
    NEUTRAL="neutral"; NONE="none"; PERMERROR="permerror"; TEMPERROR="temperror"

class DKIMResult(Enum):
    PASS="pass"; FAIL="fail"; NONE="none"; PERMERROR="permerror"; TEMPERROR="temperror"

@dataclass
class SPFCheckResult:
    result: SPFResult
    reason: str
    spf_record: Optional[str] = None
    sender_ip: Optional[str] = None

@dataclass
class DKIMCheckResult:
    result: DKIMResult
    reason: str
    selector: Optional[str] = None
    signing_domain: Optional[str] = None

def _get_spf_record(domain): # returns the spf record of the domain
    try:
        for rdata in dns.resolver.resolve(domain, "TXT", lifetime=5): # checks for "TXT" records in DNS. lifetime=5 means to give up after 5 sec
            txt = b"".join(rdata.strings).decode("utf-8", errors="replace") # error=replce is to replace a character which doesn't fit the utf-8 rulebook with a '?', doen't crash.
            if txt.startswith("v=spf1"):
                return txt
    except Exception:
        pass # if domain has not been found, ignore. wouldnot throw dns timeout exception
    return None

def _ip_in_cidr(ip_str, cidr_str):
    try:
        actual_ip_address=ipaddress.ip_address(ip_str) # converting string ip address
        if actual_ip_address in ipaddress.ip_network(cidr_str,strict=False): # strict=False => host part of the ip addrs may or maynot be 0
            return True
        else:
            return False
    except ValueError:
        return False

def _resolve_to_ips(hostname): # converts hostname to ip addresses
    ips = []
    for qtype in ("A", "AAAA"): # "A" record contains IPv4 records and "AAAA" contains IPv6 records in the spf records of the dns of hostname
        try:
            for r in dns.resolver.resolve(hostname,qtype,lifetime=5): # qtype can be "A" or "AAAA"
                ips.append(str(r))
        except Exception:
            pass
    return ips

def _qualifier_result(qualifier, record, ip, reason):
    mapping = {"+": SPFResult.PASS, "-": SPFResult.FAIL, "~": SPFResult.SOFTFAIL, "?": SPFResult.NEUTRAL}
    return SPFCheckResult(mapping.get(qualifier, SPFResult.NEUTRAL), reason, record, ip) # if qualifier is not present use SPFResult.NEUTRAL as result

def check_spf(sender_domain, sender_ip):
    if not sender_domain:
        return SPFCheckResult(SPFResult.NONE, "No sender domain provided")
    if not sender_ip:
        return SPFCheckResult(SPFResult.NONE, "No sender IP available") # SPFResult is None means that SPF check couldn't run=> nothing to check
    record = _get_spf_record(sender_domain)
    if not record:
        return SPFCheckResult(SPFResult.NONE, f"No SPF record for {sender_domain}")
    for mech in record.split()[1:]: # v=spf1 is the version tag and it is not a mechanism. so skip it.
        q = "+" # by default assuming that qualifier is +all
        if mech[0] in "+-~?": # if it is a qualifier. ie., +,-,? or ~
            q, mech = mech[0], mech[1:]
        ml = mech.lower()
        if ml.startswith("ip4:") or ml.startswith("ip6:"):
            if _ip_in_cidr(sender_ip, mech.split(":",1)[1]): # mech.split(":",1)[1] removes the ipv4 or ipv6 part(captures only the ip address, not the tag)
                return _qualifier_result(q, record, sender_ip, f"IP matches {mech}")
        elif ml=="a" or ml.startswith("a:"): # captures v=spf1 a -all and v=spf1 a:mail.startup.com -all 

        # v=spf1 a -all => trust ip addresses that this domain itself resolves to 
        # v=spf1 a:abc@xyz.com -all => trust ip addresses that abc@xyz.com resolves to 

            if ":" in mech:
                d=sender_domain
            else:
                d=mech.split(":",1)[1] # ",1" splits mech only at the 1st ":", restof the mech remains intact 

            if sender_ip in _resolve_to_ips(d):
                return _qualifier_result(q, record, sender_ip, f"IP matches A record of {d}")
        elif ml == "mx" or ml.startswith("mx:"):
            d = mech.split(":",1)[1] if ":" in mech else sender_domain # if no domain is specified (no ":" after mx), use the sender_domain itself; else use the domain specified after ":"
            try:
                for mx in dns.resolver.resolve(d, "MX", lifetime=5):
                    if sender_ip in _resolve_to_ips(str(mx.exchange).rstrip(".")):
                        return _qualifier_result(q, record, sender_ip, f"IP matches MX of {d}")
            except Exception:
                pass
        elif ml.startswith("include:"): # we will have to check this domain's spf also
            sub = check_spf(mech.split(":",1)[1], sender_ip)
            if sub.result == SPFResult.PASS:
                return SPFCheckResult(SPFResult.PASS, f"Authorised via include:{mech.split(':',1)[1]}", record, sender_ip)
        elif ml.startswith("redirect="): # ignore the current record and use this domain's spf instead
            return check_spf(mech.split("=",1)[1], sender_ip)
        elif ml == "all":
            return _qualifier_result(q, record, sender_ip, f"Matched 'all' fallback (qualifier='{q}')")
    return SPFCheckResult(SPFResult.NEUTRAL, "No mechanism matched", record, sender_ip)

def check_dkim(raw_email_bytes): # takes the entire file as bytes bcz dkim.verify() requires bytes
    header_str = raw_email_bytes.decode("utf-8", errors="replace") # convert bytes to readable string, to search for "dkim-signature:"
    if "dkim-signature:" not in header_str.lower():
        return DKIMCheckResult(DKIMResult.NONE, "No DKIM-Signature header found")
    selector, domain = None, None
    m = re.search(r'DKIM-Signature:.*?s=([\w]+).*?d=([\w.\-]+)', header_str, re.IGNORECASE|re.DOTALL) #finding the selector and domain inside DKIM-Signature
    # dot all => headers can span multiple lines

    if m:
        selector, domain = m.group(1), m.group(2)
    try:
        import dkim # imported here bcz if it is missing, only DKIM fails rest of the prgm stillwill work
        valid = dkim.verify(raw_email_bytes)
        if valid:
            return DKIMCheckResult(DKIMResult.PASS, f"Signature verified via {selector}._domainkey.{domain}", selector, domain)
        else:
            return DKIMCheckResult(DKIMResult.FAIL, "Signature present but verification FAILED — email may be tampered", selector, domain)
    except Exception as e:
        return DKIMCheckResult(DKIMResult.PERMERROR, f"Could not verify: {e}", selector, domain) # something went wrong during verification eg.public key missing from dns


# d represents domain ie., who signed(created) the dkim signature. s represents selector. both r reqd to find public key from DNS.


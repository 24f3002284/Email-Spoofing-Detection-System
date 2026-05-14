import email
import email.policy
from email.header import decode_header
from dataclasses import dataclass, field
from typing import Optional
import re

@dataclass
class EmailHeaders:
    # sender fields
    from_address: Optional[str]= None          
    reply_to: Optional[str]= None              
    return_path: Optional[str]= None           
    sender: Optional[str]= None               

    received_chain: list= field(default_factory=list) #we have to use default_factory(list) in order to create a new list during the creation of each object of the class
    originating_ip: Optional[str]= None        

    authentication_results: Optional[str]= None
    dkim_signature: Optional[str]= None
    received_spf: Optional[str]= None

    subject: Optional[str]= None
    date: Optional[str]= None
    message_id: Optional[str]= None
    to: Optional[str]= None

    from_domain: Optional[str]= None
    return_path_domain: Optional[str]= None
    reply_to_domain: Optional[str]= None

    flags: list= field(default_factory=list)

def _decode_header_value(value): 
    if not value:
        return ""
    parts = decode_header(value)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(charset or "utf-8", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded).strip()


def _extract_domain(address):
    if not address:
        return None
    match = re.search(r'@([\w.\-]+)', address)
    return match.group(1).lower() if match else None

def _extract_ip_from_received(received):
    match = re.search(r'\[(\d{1,3}(\.\d{1,3}){3})\]', received)
    return match.group(1) if match else None


def parse_email(source):
    # Load the message
    if source.endswith(".eml") or "\n" not in source[:50]:
        try:
            with open(source, "rb") as f:
                msg = email.message_from_binary_file(f, policy=email.policy.default)
        except (FileNotFoundError, IsADirectoryError):
            # Treat as raw string if file not found
            msg = email.message_from_string(source, policy=email.policy.default)
    else:
        msg = email.message_from_string(source, policy=email.policy.default)

    h = EmailHeaders()

    h.from_address   = _decode_header_value(msg.get("From", ""))
    h.reply_to       = _decode_header_value(msg.get("Reply-To", ""))
    h.return_path    = _decode_header_value(msg.get("Return-Path", ""))
    h.sender         = _decode_header_value(msg.get("Sender", ""))

    h.subject        = _decode_header_value(msg.get("Subject", ""))
    h.date           = msg.get("Date", "")
    h.message_id     = msg.get("Message-ID", "")
    h.to             = _decode_header_value(msg.get("To", ""))

    h.authentication_results = msg.get("Authentication-Results", "")
    h.dkim_signature         = msg.get("DKIM-Signature", "")
    h.received_spf           = msg.get("Received-SPF", "")

    h.received_chain = msg.get_all("Received") or []

    h.originating_ip = msg.get("X-Originating-IP", "")
    if not h.originating_ip and h.received_chain:
        h.originating_ip = _extract_ip_from_received(h.received_chain[-1]) or ""

    h.from_domain         = _extract_domain(h.from_address)
    h.return_path_domain  = _extract_domain(h.return_path)
    h.reply_to_domain     = _extract_domain(h.reply_to)

    if h.reply_to and h.from_address and h.reply_to_domain != h.from_domain:
        h.flags.append("REPLY_TO_DOMAIN_MISMATCH")

    if h.return_path_domain and h.from_domain and h.return_path_domain != h.from_domain:
        h.flags.append("RETURN_PATH_DOMAIN_MISMATCH")

    if h.sender and h.from_address and h.sender != h.from_address:
        h.flags.append("SENDER_FROM_MISMATCH")

    if not h.dkim_signature:
        h.flags.append("NO_DKIM_SIGNATURE")

    if not h.received_spf:
        h.flags.append("NO_SPF_RESULT_HEADER")

    return h
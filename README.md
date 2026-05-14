A Python tool that analyses email headers to detect spoofed and phishing emails using real DNS-based verification of SPF, DKIM, and DMARC records. Scores every email on a 0–100 trust scale and presents results via a CLI tool or a Flask web interface.

Features:
    1) SPF Verification — DNS TXT lookup to check if the sending IP is authorised by the domain. Handles ip4, ip6, a, mx, include (recursive),and redirect mechanisms.
    2) DKIM Verification — Cryptographic signature check using the public key fetched from DNS at <selector>._domainkey.<domain>
    DMARC Policy Check — Fetches _dmarc.<domain> and verifies alignment between the From: domain and authenticated domains (relaxed and strict modes).
    3) Header Flag Detection — Detects suspicious patterns like Reply-To mismatches, Return-Path mismatches, and Sender/From conflicts.
    4) Trust Scoring — Combines all checks into a 0–100 score with a clear verdict: Likely Legitimate, Suspicious, or Likely Spoofed / Phishing.
    5)CLI Tool — Run from terminal with rich colour-coded output and optional HTML report export.
    6) Web Interface — Flask app with drag-and-drop .eml upload and a live dashboard report.

How It Works:
.eml file / raw headers -> parser.py (Extract From, Reply-To, Return-Path, Received chain, IPs) -> checker.py (SPF DNS lookup + DKIM cryptographic verification -> dmarc.py (DMARC policy fetch + domain alignment check) -> scorer.py (Combine results into 0–100 trust score) -> display.py (Rich terminal output or Flask web dashboard)

Command to be run in terminal to install DEPENDENCIES: pip install dnspython dkimpy rich flask
 
How to get a real .eml file:
If email client Gmail, open email, open menu. Click download message.

Tech Stack used:
dnspython      : DNS TXT record lookups for SPF and DMARC
dkim           : pyDKIM cryptographic signature verification
rich           : Colour-coded terminal output
flask          : Web interface
email (stdlib) : Email parsing and header extraction
ipaddress (stdlib) :  CIDR range matching for SPF ip4/ip6
re (stdlib)    : Regex for header field extraction

Instructions to run this project:
    Option 1: Type 'python app.py' in terminal,press enter.  and upload .eml files.
    Option 2: Type 'puthon display.py <file_name.eml>' in terminal and press enter. 
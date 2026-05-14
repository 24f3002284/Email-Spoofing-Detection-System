CONFUSABLES = {
    'a': ['а', 'ä', 'á', 'à', 'â', 'ã', '@'],   # Cyrillic 'а' looks like 'a'
    'e': ['е', 'ë', 'é', 'è', 'ê'],              # Cyrillic 'е' looks like 'e'
    'o': ['о', 'ö', 'ó', 'ò', 'ô', '0'],         # Cyrillic 'о' looks like 'o'
    'i': ['і', 'ï', 'í', 'ì', 'î', '1', 'l'],   # '1' and 'l' look like 'i'
    'l': ['1', 'i', 'І'],
    'p': ['р'],                                    # Cyrillic 'р' looks like 'p'
    'c': ['с'],                                    # Cyrillic 'с' looks like 'c'
    'x': ['х'],                                    # Cyrillic 'х' looks like 'x'
    'n': ['п'],                                    # Cyrillic 'п' looks like 'n'
    'rn': ['m'],                                   # 'rn' together looks like 'm'
    'm': ['rn'],
}

# trusted domains to compare against
TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "yahoo.com", "outlook.com", "microsoft.com",
    "apple.com", "amazon.com", "paypal.com", "facebook.com", "instagram.com",
    "twitter.com", "linkedin.com", "netflix.com", "sbi.co.in", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "bankofamerica.com", "chase.com",
    "wellsfargo.com", "citibank.com", "irctc.co.in", "incometax.gov.in",
]

def levenshtein(s1,s2): 
    # minimum number of insertions, deletions, substitutions to turn s1 into s2.
    m, n = len(s1), len(s2)

    dp = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1): dp[i][0] = i
    for j in range(n + 1): dp[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if s1[i-1] == s2[j-1]:
                dp[i][j] = dp[i-1][j-1]          # characters match, no cost
            else:
                dp[i][j] = 1 + min(
                    dp[i-1][j],    # deletion
                    dp[i][j-1],    # insertion
                    dp[i-1][j-1]  # substitution(replacing)
                )
    return dp[m][n]

def similarity_percent(s1,s2):
    # converting the edit distance to a 0-100 similarity percentage
    max_len = max(len(s1), len(s2))
    if max_len == 0:
        return 100.0
    distance = levenshtein(s1, s2)
    return round((1 - distance / max_len) * 100, 1)

def _normalize(domain):
    domain = domain.lower().strip()
    if domain.startswith("www."):
        domain = domain[4:] # removing www. 
    return domain

def _has_confusable_chars(domain):
    # checking if domain contains Unicode characters
    found = []
    for char in domain:
        if ord(char) > 127:   # non-ASCII character
            found.append(char)
    return found

def check_lookalike(domain, threshold= 80):
    # checking if a domain looks suspiciously similar to any known trusted domain.
    if not domain:
        return {"is_lookalike": False, "matches": [], "confusables": [],
                "best_match": None, "best_score": 0}

    domain_norm = _normalize(domain) # removing www. if present
    matches = []

    for trusted in TRUSTED_DOMAINS:
        trusted_norm = normalize(trusted)

        # exact match => trusted domain
        if domain_norm == trusted_norm:
            continue

        similarity = similarity_percent(domain_norm, trusted_norm)
        distance   = levenshtein(domain_norm, trusted_norm)

        if similarity >= threshold:
            matches.append({
                "trusted_domain": trusted,
                "similarity":     similarity,
                "distance":       distance,
            })

    # sorting by similarity 
    matches.sort(key=lambda x: x["similarity"], reverse=True)

    confusables = _has_confusable_chars(domain_norm)

    best_match  = matches[0]["trusted_domain"] if matches else None
    best_score  = matches[0]["similarity"]     if matches else 0.0

    return {
        "is_lookalike": len(matches) > 0 or len(confusables) > 0,
        "matches":      matches,
        "confusables":  confusables,
        "best_match":   best_match,
        "best_score":   best_score,
    }
import re
from urllib.parse import urlparse

RISKY_WORDS = [
    "urgent", "verify", "password", "click here", "update account",
    "reset", "invoice", "credential", "login", "payment", "suspend",
    "deactivation", "confirm", "2fa", "multi-factor", "unlock"
]
URL_REGEX = re.compile(r"https?://\S+", re.IGNORECASE)


TRUSTED_DOMAINS = {
    # add your real clinic/corp domains here
    "clinic.com",
    "tailoredlearning.local"
}

def parse_email(payload: dict) -> dict:
    """Return analysis signals used by routes.py.
       Expected payload keys: sender, subject, body
       Returns: { urls, flagged_keywords, risk_score, verdict }
    """
    sender = (payload.get("sender") or "").strip()
    subject = (payload.get("subject") or "").strip()
    body = payload.get("body") or ""

    text = f"{subject} {body}".lower()

    # extract URLs
    urls = URL_REGEX.findall(body) or []

    # find risky keywords (unique, keep stable order)
    flagged = [w for w in RISKY_WORDS if w in text]

    # sender/URL domain checks
    sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
    url_domains = {urlparse(u).netloc.lower() for u in urls}

      # suspicious if any URL domain isn't in company-trusted set
    external_domain_present = any(
        (d.split(":")[0] not in TRUSTED_DOMAINS) for d in url_domains
    )

      # flag brand-mismatch patterns (very naive example: look for hyphenated lookalikes)
    lookalike = any("-" in d or d.endswith(".co") for d in url_domains)

    # naive scoring
    risk_score = min(100, len(flagged) * 20 + len(urls) * 10)


   # 4) scoring (tune as you like)
    score = 0
    score += 20 * len(flagged)          # keywords
    score += 10 * len(urls)             # URLs present
    if external_domain_present: score += 25
    if lookalike: score += 25
    if sender_domain and external_domain_present and sender_domain not in TRUSTED_DOMAINS:
        score += 10                     # sender not trusted + external links

    score = min(100, score)


    # verdict
    if risk_score >= 60:
        verdict = "Phishing"
    elif risk_score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Legitimate"

    return {
        "urls": urls,
        "flagged_keywords": flagged,
        "risk_score": risk_score,
        "verdict": verdict,
    }

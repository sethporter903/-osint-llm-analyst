"""
hibp_lookup.py
--------------
Queries the HaveIBeenPwned (HIBP) API v3 for a given email address
and returns structured breach and paste data relevant to
threat intelligence analysis.

Requires a HIBP API key. Free keys are available at:
https://haveibeenpwned.com/API/Key

Rate limit: 1 request per 1500ms (enforced by the API).
We handle this with a small sleep between calls.
"""

import requests
import time


# HIBP API base URL (v3)
HIBP_API = "https://haveibeenpwned.com/api/v3"


def get_hibp_data(email: str, api_key: str) -> dict:
    """
    Accepts an email address and HIBP API key.
    Returns a structured dict containing:
      - breach summary (how many, which services, what data types)
      - paste exposure (whether the email appeared in paste sites)
      - a list of high-severity breaches flagged for analyst review
    """

    headers = {
        "hibp-api-key": api_key,
        # HIBP requires a user-agent identifying your application
        "user-agent":   "OSINT-TI-Tool/1.0",
        "Accept":       "application/json",
    }

    # ── Step 1: Query breach data for the email ───────────────────────
    breach_url = f"{HIBP_API}/breachedaccount/{email}"
    params = {
        "truncateResponse": "false"   # get full breach details, not just names
    }

    try:
        breach_resp = requests.get(
            breach_url,
            headers=headers,
            params=params,
            timeout=10
        )
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}", "email": email}

    # 404 from HIBP means no breaches found — this is a good outcome,
    # not an error. We handle it explicitly rather than treating it as failure.
    if breach_resp.status_code == 404:
        breaches = []
    elif breach_resp.status_code == 401:
        return {"error": "Invalid or missing HIBP API key.", "email": email}
    elif breach_resp.status_code == 429:
        return {"error": "Rate limited by HIBP. Wait 1.5 seconds between requests.", "email": email}
    elif breach_resp.status_code != 200:
        return {"error": f"Breach API returned {breach_resp.status_code}", "email": email}
    else:
        breaches = breach_resp.json()

    # ── Step 2: Respect the HIBP rate limit before second call ────────
    # HIBP enforces 1 request per 1500ms. Sleeping here prevents a 429
    # on the paste query that follows immediately after.
    time.sleep(1.6)

    # ── Step 3: Query paste data for the email ────────────────────────
    # Pastes are appearances on sites like Pastebin, GitHub Gist, etc.
    # These often indicate credential dumps or doxxing exposure.
    paste_url = f"{HIBP_API}/pasteaccount/{email}"

    try:
        paste_resp = requests.get(paste_url, headers=headers, timeout=10)
    except requests.exceptions.RequestException:
        paste_resp = None

    if paste_resp is None or paste_resp.status_code == 404:
        pastes = []
    elif paste_resp.status_code == 200:
        pastes = paste_resp.json()
    else:
        pastes = []   # non-critical; continue with empty list

    # ── Step 4: Extract TI-relevant breach fields ─────────────────────
    # HIBP returns ~15 fields per breach. We extract what matters for TI:
    # name, date, affected data types, size, and whether it was verified.
    breach_summaries = []
    for breach in breaches:
        breach_summaries.append({
            "name":           breach.get("Name", ""),
            "domain":         breach.get("Domain", ""),
            "breach_date":    breach.get("BreachDate", ""),
            "added_date":     breach.get("AddedDate", "")[:10],
            "pwn_count":      breach.get("PwnCount", 0),       # number of accounts affected
            "data_classes":   breach.get("DataClasses", []),   # what types of data were exposed
            "is_verified":    breach.get("IsVerified", False), # has HIBP confirmed the breach?
            "is_sensitive":   breach.get("IsSensitive", False),# marked sensitive by HIBP
            "is_spam_list":   breach.get("IsSpamList", False), # spam list vs. actual breach
        })

    # ── Step 5: Flag high-severity breaches ───────────────────────────
    # We define high-severity as breaches that exposed credential-level
    # data — passwords, tokens, or financial information.
    # This list mirrors the data classes HIBP uses in its taxonomy.
    high_severity_classes = {
        "Passwords", "Password hints", "Auth tokens",
        "Credit cards", "Bank account numbers",
        "Social security numbers", "Private messages",
        "Government issued IDs"
    }

    high_severity_breaches = [
        b["name"] for b in breach_summaries
        if any(dc in high_severity_classes for dc in b["data_classes"])
        and b["is_verified"]   # only flag verified breaches to reduce noise
    ]

    # ── Step 6: Summarize paste exposure ─────────────────────────────
    paste_summaries = []
    for paste in pastes:
        paste_summaries.append({
            "source":    paste.get("Source", "Unknown"),   # e.g. Pastebin, GitHub
            "title":     paste.get("Title", "Untitled") or "Untitled",
            "date":      paste.get("Date", "Unknown"),
            "email_count": paste.get("EmailCount", 0),    # how many emails in the paste
        })

    # ── Step 7: Assemble final result dict ────────────────────────────
    result = {
        "email":                    email,
        "total_breaches":           len(breach_summaries),
        "total_pastes":             len(paste_summaries),
        "high_severity_breaches":   high_severity_breaches,
        "total_high_severity":      len(high_severity_breaches),
        "breaches":                 breach_summaries,
        "pastes":                   paste_summaries,
        # Convenience flag for the LLM prompt —
        # True if there's anything worth flagging to an analyst
        "has_significant_exposure": (
            len(high_severity_breaches) > 0 or len(paste_summaries) > 0
        ),
    }

    return result

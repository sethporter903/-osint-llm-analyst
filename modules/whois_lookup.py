"""
whois_lookup.py
---------------
Queries WHOIS registration data for a given domain and returns
a structured dictionary for downstream LLM analysis.
"""

import whois                  # python-whois library
from datetime import datetime


def get_whois(domain: str) -> dict:
    """
    Accepts a domain string (e.g. 'example.com') and returns
    a cleaned dictionary of WHOIS fields relevant to threat intel.
    """

    try:
        w = whois.whois(domain)   # makes the WHOIS query
    except Exception as e:
        # If the query fails (domain not found, timeout, etc.)
        # we return an error dict rather than crashing the notebook
        return {"error": str(e), "domain": domain}

    # whois returns some fields as lists when there are multiple values
    # (e.g. multiple name servers). This helper flattens them to a string
    # so the LLM prompt stays clean.
    def flatten(val):
        if isinstance(val, list):
            return ", ".join(str(v) for v in val if v)
        if isinstance(val, datetime):
            return val.strftime("%Y-%m-%d")
        return str(val) if val else "Not available"

    # We only extract fields that are meaningful for TI purposes.
    # Raw WHOIS responses contain a lot of noise we don't need.
    result = {
        "domain":           domain,
        "registrar":        flatten(w.registrar),
        "creation_date":    flatten(w.creation_date),
        "expiration_date":  flatten(w.expiration_date),
        "updated_date":     flatten(w.updated_date),
        "name_servers":     flatten(w.name_servers),
        "registrant_name":  flatten(w.name),
        "registrant_org":   flatten(w.org),
        "registrant_email": flatten(w.emails),
        "registrant_country": flatten(w.country),
        "status":           flatten(w.status),
    }

    return result

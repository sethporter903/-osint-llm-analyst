"""
github_recon.py
---------------
Queries the GitHub REST API for a given username and returns
a structured dictionary of profile and repository data
relevant to threat intelligence analysis.

No authentication required for public data, but an optional
GitHub token is accepted to raise the rate limit from
60 requests/hour (unauthenticated) to 5,000 requests/hour.
"""

import requests               # standard HTTP library
from datetime import datetime


# GitHub's public REST API base URL
GITHUB_API = "https://api.github.com"


def get_github_profile(username: str, token: str = None) -> dict:
    """
    Accepts a GitHub username and returns a structured dict
    containing profile metadata and a summary of public repositories.

    token: optional GitHub personal access token (PAT).
            If not provided, unauthenticated rate limits apply.
    """

    # Build request headers. The Accept header tells GitHub
    # we want the stable v3 JSON format.
    headers = {"Accept": "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"token {token}"

    # ── Step 1: Fetch the user profile ──────────────────────────────
    profile_url = f"{GITHUB_API}/users/{username}"

    try:
        profile_resp = requests.get(profile_url, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        return {"error": f"Network error: {str(e)}", "username": username}

    # 404 means the user doesn't exist
    if profile_resp.status_code == 404:
        return {"error": "User not found", "username": username}

    # 403 usually means rate limited
    if profile_resp.status_code == 403:
        return {"error": "Rate limited by GitHub API. Provide a token to increase limits.", "username": username}

    # Any other non-200 is unexpected
    if profile_resp.status_code != 200:
        return {"error": f"API returned {profile_resp.status_code}", "username": username}

    profile = profile_resp.json()   # parse JSON response into a dict

    # ── Step 2: Fetch the user's public repositories ─────────────────
    # We request up to 100 repos sorted by most recently updated.
    # This gives us the most relevant signal without pulling everything.
    repos_url = f"{GITHUB_API}/users/{username}/repos"
    params = {
        "per_page": 100,
        "sort": "updated",
        "direction": "desc"
    }

    try:
        repos_resp = requests.get(repos_url, headers=headers, params=params, timeout=10)
        repos = repos_resp.json() if repos_resp.status_code == 200 else []
    except requests.exceptions.RequestException:
        repos = []   # if repos call fails, continue with empty list

    # ── Step 3: Extract TI-relevant repo fields ───────────────────────
    # We don't need every field GitHub returns (there are ~80).
    # We extract what matters: names, topics, language, activity dates,
    # and whether the repo has been forked (social graph signal).
    repo_summaries = []
    for repo in repos:
        repo_summaries.append({
            "name":         repo.get("name", ""),
            "description":  repo.get("description", "") or "No description",
            "language":     repo.get("language", "") or "Not specified",
            "topics":       repo.get("topics", []),          # GitHub topic tags
            "stars":        repo.get("stargazers_count", 0),
            "forks":        repo.get("forks_count", 0),
            "is_fork":      repo.get("fork", False),         # did they fork this from someone?
            "created_at":   repo.get("created_at", "")[:10], # trim to YYYY-MM-DD
            "updated_at":   repo.get("updated_at", "")[:10],
            "url":          repo.get("html_url", ""),
        })

    # ── Step 4: Flag any potentially sensitive repository names ───────
    # Simple keyword scan — not a substitute for manual review,
    # but surfaces repos worth a closer look in the LLM prompt.
    sensitive_keywords = [
        "exploit", "payload", "malware", "rat", "keylogger",
        "botnet", "exfil", "c2", "rootkit", "ransomware",
        "bypass", "inject", "phish", "spoof", "credential"
    ]

    flagged_repos = [
        r["name"] for r in repo_summaries
        if any(kw in r["name"].lower() or kw in r["description"].lower()
               for kw in sensitive_keywords)
    ]

    # ── Step 5: Assemble final result dict ────────────────────────────
    result = {
        "username":         username,
        "display_name":     profile.get("name", "Not provided"),
        "bio":              profile.get("bio", "Not provided") or "Not provided",
        "company":          profile.get("company", "Not provided") or "Not provided",
        "location":         profile.get("location", "Not provided") or "Not provided",
        "email":            profile.get("email", "Not provided") or "Not provided",
        "created_at":       profile.get("created_at", "")[:10],
        "public_repos":     profile.get("public_repos", 0),
        "followers":        profile.get("followers", 0),
        "following":        profile.get("following", 0),
        "profile_url":      profile.get("html_url", ""),
        "repositories":     repo_summaries,
        "flagged_repos":    flagged_repos,   # repos matching sensitive keywords
        "total_flagged":    len(flagged_repos),
    }

    return result

# OSINT Threat Intelligence Tool
### LLM-Assisted Infrastructure and Identity Analysis

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![Anthropic](https://img.shields.io/badge/LLM-Anthropic%20Claude-orange)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

A Jupyter-based OSINT tool that queries three public data sources — WHOIS, GitHub, and HaveIBeenPwned — and passes the structured results to an Anthropic Claude model to generate a formatted threat intelligence report.

Built as a portfolio project to demonstrate:
- LLM-assisted OSINT collection and report generation
- **Indirect prompt injection risk** in AI-powered intelligence pipelines
- Practical mitigations for LLM input trust boundary violations
- Applied threat intelligence tradecraft in an AI engineering context

This tool is a companion to the research paper:
> *Vulnerability Landscape of Large Language Models: Attack Vectors, Exploitation Techniques, and Defensive Controls* (2026)

The injection demonstration in Cell 6 of the notebook operationalizes the vulnerability class documented in Section 3 and Section 15 of that paper.

---

## Architecture

```
osint_tool/
├── osint_report.ipynb      # Main notebook — run this
├── llm_analyst.py          # Anthropic API integration and prompt construction
├── modules/
│   ├── whois_lookup.py     # WHOIS registration data
│   ├── github_recon.py     # GitHub profile and repository recon
│   └── hibp_lookup.py      # HaveIBeenPwned breach and paste data
├── requirements.txt
├── .gitignore
└── README.md
```

**Data flow:**

```
TARGET DOMAIN / USERNAME / EMAIL
        │
        ├─► WHOIS query ──────────────────┐
        ├─► GitHub API query ─────────────┤──► LLM Prompt (delimited) ──► TI Report
        └─► HaveIBeenPwned API query ─────┘
```

---

## Prompt Injection Risk — By Design

This tool intentionally exposes and demonstrates the **indirect prompt injection** vulnerability that affects all LLM-assisted OSINT pipelines.

All three data sources return unverified public content that flows directly into the LLM prompt. An adversary who anticipates being queried by an LLM-assisted tool can embed instruction payloads in:

- WHOIS registrant name or organization fields
- GitHub bio, repository names, or descriptions
- HaveIBeenPwned breach metadata (less likely but structurally possible)

**Cell 6 of the notebook demonstrates this attack live** using a locally constructed poisoned WHOIS record. No external systems are queried in that cell.

### Mitigations Implemented

| Mitigation | Implementation | Limitation |
|---|---|---|
| Delimiter tags | All external data wrapped in `<external_data>` tags | Sophisticated payloads can escape delimiter context |
| System/user separation | Role and trust instructions in system prompt, data in user message | Does not prevent all context blending |
| Model self-reporting | LLM instructed to flag detected injection attempts | Soft control — model can be deceived |
| Analyst warning banner | Injection flag surfaced visually in notebook output | Depends on analyst reading the warning |

**No mitigation substitutes for human analyst review before acting on output.**

---

## Setup

### Requirements

- Python 3.11+
- Anthropic API key ([console.anthropic.com](https://console.anthropic.com))
- HaveIBeenPwned API key ([haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key)) — ~$4/year personal tier
- GitHub personal access token (optional — raises rate limit from 60 to 5,000 req/hr)

### Install

```bash
git clone https://github.com/YOUR_USERNAME/osint-ti-tool.git
cd osint-ti-tool
pip install -r requirements.txt
```

### Configure API Keys

Never hardcode keys. Set them as environment variables:

```bash
export ANTHROPIC_API_KEY='your-anthropic-key'
export HIBP_API_KEY='your-hibp-key'
export GITHUB_TOKEN='your-github-token'   # optional
```

### Run

```bash
jupyter notebook osint_report.ipynb
```

Set your target in Cell 2, then run all cells.

---

## Output

The tool produces two exports per run (Cell 8):

**`report_<domain>_<timestamp>.md`** — structured intelligence report with sections:
- Subject Summary
- Infrastructure Indicators
- Technical Profile
- Credential and Breach Exposure
- Analyst Assessment (with confidence level)
- Recommended Follow-On Collection
- Data Quality Notes
- Injection Attempt Detected (if applicable)

**`data_<domain>_<timestamp>.json`** — raw data sidecar including all API responses and LLM metadata (model, token counts, injection warning flag).

Both files are excluded from git by `.gitignore` — they may contain PII.

---

## Before Committing

Clear notebook cell outputs before every commit to prevent accidental exposure of query results:

```bash
jupyter nbconvert --clear-output --inplace osint_report.ipynb
git add .
git commit -m "your message"
```

---

## Authorization Notice

Query only domains, accounts, and email addresses you are authorized to research. Public availability of data does not imply authorization to collect or analyze it. This tool is intended for authorized threat intelligence research, security assessments, and educational demonstration only.

---

## Roadmap

- [ ] Shodan integration for port/service enumeration
- [ ] VirusTotal domain reputation lookup
- [ ] URLScan.io screenshot and DOM analysis
- [ ] Structured JSON report schema (STIX 2.1 alignment)
- [ ] Batch target processing
- [ ] Injection detection accuracy evaluation against known payloads

---

## Related Work

- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [MITRE ATLAS — Adversarial Threat Landscape for AI Systems](https://atlas.mitre.org)
- Greshake et al. (2023) — *Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection*
- Anthropic Prompt Engineering Guide — Input Validation and Injection Defense

---

## License

MIT License — see LICENSE file for details.

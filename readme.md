<div align="center">

```
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██████╔╝███████║██║███████╗███████║    █████╗  ██║   ██║██████╔╝██║  ███╗█████╗
██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
██║     ██║  ██║██║███████║██║  ██║    ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝    ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```

### Phishing Email Triage Analyzer

**parse · authenticate · extract · enrich · verdict**

by **Asad (Cyb3r Asad)** — CS Student · Aspiring SOC Analyst · Blue Team

![version](https://img.shields.io/badge/version-1.5-blueviolet)
![language](https://img.shields.io/badge/language-bash-4EAA25?logo=gnubash&logoColor=white)
![language](https://img.shields.io/badge/language-python-3776AB?logo=python&logoColor=white)
![platform](https://img.shields.io/badge/platform-linux-557C94?logo=linux&logoColor=white)
![intel](https://img.shields.io/badge/intel-VirusTotal-394EFF?logo=virustotal&logoColor=white)

<br>

![Phish Forge terminal output](docs/screenshot.png)

</div>

---

## Overview

Phishing remains one of the most common initial access vectors for attackers. For SOC Level 1 analysts, manually working through a reported `.eml` file means opening headers, checking SPF/DKIM/DMARC, digging out hidden URLs, and hashing attachments. That can take 10 to 15 minutes per email, which feeds alert fatigue and slows incident response.

Phish Forge takes a raw `.eml` file and produces a standardized threat report in seconds, so analysts can spend their time on investigation, containment, and response instead of repetitive data gathering.

Reputation lookups alone have a blind spot. VirusTotal often shows zero detections for domains registered only hours ago, and attackers use these Newly Registered Domains (NRDs) specifically to evade reputation-based tools. Phish Forge closes that gap with a domain age heuristic that penalizes freshly registered domains in the risk score.

## Key Capabilities

| Capability | What it does |
|---|---|
| Header spoofing detection | Compares `From`, `Reply-To`, and `Return-Path` domains to catch impersonation and lookalike domains |
| Email authentication | Parses `Authentication-Results` and flags SPF, DKIM, and DMARC failures |
| NRD heuristic | Calculates domain age using the WhoisFreaks API with a free RDAP fallback. Domains registered in the last 30 days receive a heavy penalty in the risk score |
| Payload extraction | Decodes MIME structures to extract obfuscated URLs and generates SHA256 hashes for attachments |
| Threat intel enrichment | Queries the VirusTotal API for the reputation of extracted domains |
| Scoring engine | Aggregates findings into a verdict: `MALICIOUS`, `SUSPICIOUS`, or `LIKELY CLEAN` |

## Example Run

Analysis of a simulated Microsoft 365 credential phish (`samples/phish-test.eml`):

| Check | Result |
|---|---|
| From domain | `micros0ft.com` (lookalike using a zero) |
| Reply-To domain | `evil-c2.tld` (mismatch) |
| Return-Path domain | `evil-c2.tld` (mismatch) |
| SPF | Fail |
| DKIM | None |
| DMARC | Fail |
| URLs extracted | 2 |
| VirusTotal | `micros0ft.com` flagged by 13 engines |
| Verdict | **MALICIOUS** (score 14) |

Every run saves its artifacts to a timestamped folder under `./reports/`.

> The sample email is synthetic. `evil-c2.tld` shows as clean on VirusTotal because it is a made-up domain.

## How the Verdict Works

Each finding adds to a cumulative score, and the total maps to a verdict.

| Signal | Examples |
|---|---|
| Header mismatch | From vs Reply-To, From vs Return-Path |
| Authentication failure | SPF fail, DKIM fail or none, DMARC fail |
| Newly registered domain | Domain registered within the last 30 days (heavy penalty) |
| Threat intel hit | Domain flagged by VirusTotal engines |

The final score maps to `LIKELY CLEAN`, `SUSPICIOUS`, or `MALICIOUS`.

## Tech Stack

| Component | Role |
|---|---|
| Bash | Orchestration, argument parsing, interactive terminal UI |
| Python (`email` module) | Robust MIME parsing and decoding |
| curl and jq | VirusTotal and WhoisFreaks API requests and safe JSON handling |
| WhoisFreaks API / RDAP | Domain registration data for the NRD age check, with RDAP as a free fallback |

## Installation

```bash
git clone https://github.com/cyb3erasad/phish-forge.git
cd phish-forge
chmod +x phish-forge.sh
```

**Requirements:** Bash 4+, Python 3, `curl`, `jq`, and a VirusTotal API key (a free key works, subject to rate limits).

API keys are read from environment variables and are never stored in the script:

```bash
export VT_API_KEY="your_virustotal_key_here"
export WHOISFREAKS_API_KEY="your_whoisfreaks_key_here"   # optional
```

The WhoisFreaks key is optional. Without it, domain age is looked up through RDAP, which needs no key.

## Usage

```bash
./phish-forge.sh samples/phish-test.eml
```

Output is written to `./reports/phish-forge-<timestamp>/`.

## Project Structure

```
phish-forge/
├── phish-forge.sh
├── samples/
├── reports/
├── docs/
│   └── screenshot.png
└── README.md
```

## Roadmap

- [ ] Attachment hash lookups against VirusTotal
- [ ] URL unshortening and redirect chain analysis
- [ ] JSON and HTML report export
- [ ] Batch mode for multiple `.eml` files

## Disclaimer

This tool is intended for defensive security work and education. Only analyze emails you are authorized to inspect.

---

<div align="center">

**Asad (Cyb3r Asad)** · [GitHub](https://github.com/cyb3erasad)

</div>
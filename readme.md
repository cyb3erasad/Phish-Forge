# Phish Forge

**Automated phishing email triage for SOC analysts.**

![Version](https://img.shields.io/badge/version-1.4-blueviolet?style=for-the-badge)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![VirusTotal](https://img.shields.io/badge/VirusTotal-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)
![Kali Linux](https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)
![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)

![Phish Forge terminal output](docs/screenshot.png)

## Overview

Phishing remains one of the most common initial access vectors for attackers. For SOC Level 1 analysts, manually working through a reported `.eml` file means opening headers, checking SPF/DKIM/DMARC, digging out hidden URLs, and hashing attachments. That can take 10 to 15 minutes per email, which feeds alert fatigue and slows incident response.

Phish Forge takes a raw `.eml` file and produces a standardized threat report in seconds, so analysts can spend their time on investigation, containment, and response instead of repetitive data gathering.

## Key Capabilities

**Header spoofing detection**
Compares the `From`, `Reply-To`, and `Return-Path` domains to catch impersonation and lookalike domains.

**Email authentication checks**
Parses the `Authentication-Results` header and flags SPF, DKIM, and DMARC failures.

**Payload extraction**
Decodes the MIME structure to extract obfuscated URLs and generates SHA256 hashes for every attachment.

**Threat intelligence enrichment**
Queries the VirusTotal API for the reputation of each extracted domain.

**Scoring engine**
Aggregates all findings into a single verdict: `MALICIOUS`, `SUSPICIOUS`, or `LIKELY CLEAN`.

## Example Output

The screenshot above shows Phish Forge analyzing a simulated Microsoft 365 credential phish:

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

All artifacts for each run are saved to a timestamped folder under `./reports/`.

## Tech Stack

| Component | Role |
|---|---|
| Bash | Orchestration, argument parsing, interactive terminal UI |
| Python (`email` module) | Robust MIME parsing and decoding |
| curl and jq | VirusTotal API requests and safe JSON handling |

## Installation

```bash
git clone https://github.com/cyb3erasad/phish-forge.git
cd phish-forge
chmod +x phish-forge.sh
```

**Requirements**

- Bash 4+
- Python 3
- `curl`
- `jq`
- A VirusTotal API key (a free key works, subject to rate limits)

Set your API key as an environment variable:

```bash
export VT_API_KEY="your_api_key_here"
```

## Usage

```bash
./phish-forge.sh samples/phish-test.eml
```

Reports are written to:

```
./reports/phish-forge-<timestamp>/
```

## How the Verdict Works

Each finding adds to a cumulative score, and the total maps to a verdict.

| Finding | Examples |
|---|---|
| Header mismatch | From vs Reply-To, From vs Return-Path |
| Authentication failure | SPF fail, DKIM fail or none, DMARC fail |
| Threat intel hit | Domain flagged by VirusTotal engines |

Final score ranges map to `LIKELY CLEAN`, `SUSPICIOUS`, or `MALICIOUS`.

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

- Attachment hash lookups against VirusTotal
- URL unshortening and redirect chain analysis
- JSON and HTML report export
- Batch mode for multiple `.eml` files

## What I Learned

Building this project deepened my understanding of email security fundamentals, MIME parsing, and how to build tooling that addresses real SOC pain points.

## Disclaimer

This tool is intended for defensive security work and education. Only analyze emails you are authorized to inspect. The sample emails in this repository are simulated.

## Author

**Asad (Cyb3r Asad)**
GitHub: [@cyb3erasad](https://github.com/cyb3erasad)
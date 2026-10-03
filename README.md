# PRISM

> **One indicator. Multiple perspectives.**

PRISM is an extensible **IOC intelligence and threat investigation platform** for security analysts. It supports both a **command-line interface (CLI)** and a **desktop application**, allowing analysts to investigate indicators from whichever workflow suits them.

Give PRISM an **IP address, domain, URL, MD5, SHA1, or SHA256 hash**, and it queries multiple threat-intelligence providers in parallel, normalizes the results, and presents the most relevant information in a single analyst-friendly interface.

## Features

* 🔎 **IOC Detection** — Automatically identifies IP addresses, domains, URLs, and file hashes.
* ⚡ **Parallel Lookups** — Queries multiple threat-intelligence providers simultaneously.
* 🧩 **Multi-Provider Intelligence** — Combines intelligence from multiple sources into one investigation.
* 📊 **Result Normalization** — Converts provider-specific responses into a consistent format.
* 👨‍💻 **Analyst-Focused Details** — Presents relevant investigation data without overwhelming analysts with raw API responses.
* 🗂️ **Overview & Analyst Details** — Quickly view key findings or investigate additional context.
* 📈 **Live Progress** — Shows provider progress and results as they become available.
* 🛑 **Stop Investigation** — Stop an active investigation while preserving completed results.
* 🖥️ **Desktop Application** — Interactive graphical interface for IOC investigations.
* 💻 **CLI** — Command-line workflow for quick lookups and automation.
* 📦 **JSON Output** — Export normalized results for automation and further processing.
* 🔌 **Extensible Architecture** — Add new threat-intelligence providers without modifying the core engine.

## Current Providers

PRISM currently integrates:

* **VirusTotal**
* **urlscan.io**
* **URLQuery**
* **AbuseIPDB**

The provider architecture is designed so additional threat-intelligence sources can be added independently.

## Supported Indicators

PRISM can investigate:

* IPv4 addresses
* IPv6 addresses
* Domains
* URLs
* MD5 hashes
* SHA1 hashes
* SHA256 hashes

Provider capabilities may vary depending on the IOC type and the provider's API.

## Investigation Views

### Overview

The **Overview** tab provides a concise SOC-friendly view containing the most important information for an initial investigation.

Depending on the IOC and provider, this can include:

* Reputation / verdict
* Detection results
* Confidence or abuse score
* IP and domain information
* ASN / network information
* Geographic information
* URL information
* Key findings
* Provider status

### Analyst Details

The **Analyst Details** tab provides additional investigation context in a structured and readable format.

Instead of displaying raw API responses, PRISM organizes relevant information into sections such as:

* Detection & Reputation
* Network Identity
* Infrastructure
* Web Identity
* TLS / Certificate Information
* Scan Activity
* Findings / Alerts
* Timeline
* File / Object Information

Duplicate and low-value API metadata is intentionally excluded to keep the information focused on what is useful during an investigation.

## Desktop Application

PRISM includes a desktop application designed for interactive IOC investigations.

The desktop application provides:

* IOC search
* Provider selection/status
* Parallel provider execution
* Live investigation progress
* Results displayed as providers complete
* Investigation stop control
* Overview results
* Analyst Details
* Scrollable investigation information
* Clean analyst-focused UI
* Windows desktop support

The application is designed so analysts can start with the **Overview** for a quick assessment and move to **Analyst Details** when deeper investigation is required.

## CLI Usage

Lookup an IP address:

```bash
prism lookup 8.8.8.8
```

Lookup a domain:

```bash
prism lookup example.com
```

Lookup a URL:

```bash
prism lookup https://example.com
```

Lookup a file hash:

```bash
prism lookup 44d88612fea8a8f36de82e1278abb02f
```

Short form:

```bash
prism 8.8.8.8
```

### JSON Output

```bash
prism lookup 8.8.8.8 --json
```

JSON output can be used for automation, scripting, or integration with other security tools.

### Verbose Output

```bash
prism lookup 8.8.8.8 --verbose
```

Verbose mode displays provider errors and additional diagnostic information.

## Architecture

```text
                           PRISM
                             |
                    +--------v--------+
                    |   IOC Detector  |
                    +--------+--------+
                             |
                    +--------v--------+
                    |    IOC Engine   |
                    +--------+--------+
                             |
          +------------------+------------------+
          |          |             |            |
          v          v             v            v
    VirusTotal   urlscan.io    URLQuery    AbuseIPDB
          |          |             |            |
          +----------+-------------+------------+
                             |
                    +--------v--------+
                    |    Normalizer   |
                    +--------+--------+
                             |
                    +--------v--------+
                    | Investigation  |
                    |     Engine      |
                    +--------+--------+
                             |
                    +--------+--------+
                    |                 |
              +-----v-----+    +-----v------+
              |    CLI    |    |  Desktop   |
              |           |    |    App     |
              +-----------+    +------------+
```

Each provider operates independently. Results are collected and normalized before being presented to the user.

A slow or unavailable provider does not prevent completed results from other providers from being displayed.

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/prism.git
cd prism
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it:

### Linux / macOS

```bash
source .venv/bin/activate
```

### Windows

```powershell
.venv\Scripts\activate
```

Install PRISM:

```bash
pip install -e .
```

## Configure API Keys

Create the environment file:

```bash
cp .env.example .env
```

On Windows:

```powershell
copy .env.example .env
```

Configure the provider API keys:

```env
VIRUSTOTAL_API_KEY=your_key
URLSCAN_API_KEY=your_key
URLQUERY_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
```

**Never commit `.env` or expose your API keys publicly.**

## Provider Capabilities

| Provider   |  IP | Domain | URL | Hash |
| ---------- | :-: | :----: | :-: | :--: |
| VirusTotal |  ✓  |    ✓   |  ✓  |   ✓  |
| urlscan.io |  ✓  |    ✓   |  ✓  |   —  |
| URLQuery   |  ✓  |    ✓   |  ✓  |   —  |
| AbuseIPDB  |  ✓  |    —   |  —  |   —  |

Provider capabilities and available information depend on the provider's API and the type of indicator being investigated.

## Project Structure

```text
prism/
├── prism/
│   ├── cli.py
│   ├── models.py
│   ├── engine/
│   ├── providers/
│   │   ├── base.py
│   │   ├── virustotal.py
│   │   ├── urlscan.py
│   │   ├── urlquery.py
│   │   ├── abuseipdb.py
│   │   └── registry.py
│   └── ...
├── .env.example
├── pyproject.toml
└── README.md
```

The exact desktop application files may vary depending on the release structure.

## Adding a Provider

Create a provider implementing the `ThreatProvider` interface in:

```text
prism/providers/
```

Then register it in:

```text
prism/providers/registry.py
```

The core engine should not need to understand provider-specific API response formats.

Each provider is responsible for retrieving its own intelligence, while the normalization layer converts the results into a common structure for PRISM.

## Privacy & Security

PRISM sends queried indicators to the configured third-party threat-intelligence providers.

**Do not use PRISM with sensitive, confidential, private, or PII-containing indicators unless you have confirmed that doing so is appropriate for the provider and your organization's policies.**

VirusTotal's API documentation states that indicators queried or submitted through its API may be added to its dataset and warns against using the API with sensitive or confidential information.

Other providers may have their own visibility, retention, and submission policies.

Review each provider's terms and API documentation before using PRISM with sensitive indicators or in production environments.

## Current Scope

PRISM currently focuses on **IOC lookup and enrichment**.

It retrieves existing intelligence and scan information from supported providers.

PRISM does not automatically submit URLs to external scanning services unless explicitly implemented by the relevant provider.

## Roadmap

Potential future improvements include:

* IOC relationship / pivot graph
* Cross-provider risk scoring
* MITRE ATT&CK mapping
* IOC investigation history
* Analyst notes
* PDF / HTML investigation reports
* IOC comparison
* Passive DNS enrichment
* WHOIS enrichment
* Certificate and infrastructure pivoting
* Additional threat-intelligence providers

## Official API Documentation

* [VirusTotal API v3](https://docs.virustotal.com/reference/overview)
* [VirusTotal Search API](https://docs.virustotal.com/reference/api-search)
* [urlscan.io API](https://docs.urlscan.io/pages/api-intro)
* [urlscan.io Search API](https://docs.urlscan.io/apis/urlscan-openapi/search)
* [AbuseIPDB API](https://docs.abuseipdb.com/)

## License

MIT

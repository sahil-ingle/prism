# PRISM

> **One indicator. Multiple perspectives.**

PRISM is an extensible command-line IOC intelligence aggregator.

Give PRISM an IP address, domain, URL, MD5, SHA1, or SHA256 hash and it queries supported threat-intelligence providers, then presents the useful results in one normalized report.

## Current providers

- VirusTotal
- urlscan.io

More providers can be added without changing the core engine.

## Current scope

PRISM v0.1 performs **lookups/enrichment**. It does not automatically submit URLs to urlscan.io for scanning.

VirusTotal API v3 supports reports for file hashes, URLs, domains and IP addresses. urlscan.io provides a Search API for historical scans. See the official documentation linked below.

## Install

```bash
git clone https://github.com/YOUR_USERNAME/prism.git
cd prism

python -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows

pip install -e .
```

## Configure API keys

```bash
cp .env.example .env
```

Then edit `.env`:

```env
VIRUSTOTAL_API_KEY=your_key
URLSCAN_API_KEY=your_key
```

Do not commit `.env`.

## Usage

```bash
prism lookup 8.8.8.8
prism lookup example.com
prism lookup https://example.com
prism lookup 44d88612fea8a8f36de82e1278abb02f
```

You can also use the short form:

```bash
prism 8.8.8.8
```

JSON output:

```bash
prism lookup 8.8.8.8 --json
```

Show provider errors instead of hiding them in the normal summary:

```bash
prism lookup 8.8.8.8 --verbose
```

## Architecture

```text
                         PRISM
                           |
                    +------v------+
                    | IOC Detector|
                    +------+------+
                           |
                    +------v------+
                    | IOC Engine  |
                    +------+------+
                           |
              +------------+------------+
              |                         |
       +------v------+           +------v------+
       | VirusTotal |           |  urlscan.io |
       +-------------+           +-------------+
              |                         |
              +------------+------------+
                           |
                    +------v------+
                    |  Normalizer |
                    +------+------+
                           |
                    +------v------+
                    | CLI / JSON  |
                    +-------------+
```

The provider interface is intentionally separate from the engine so future providers can be added independently.

## Adding a provider

Create a provider implementing the `ThreatProvider` protocol in:

```text
prism/providers/
```

Then register it in:

```text
prism/providers/registry.py
```

The core engine should not need to know provider-specific API response formats.

## Important privacy note

VirusTotal's API documentation states that IoCs submitted or queried through its API are added to its dataset and warns against using the API with sensitive, confidential, or PII-containing indicators. Do not use PRISM with such indicators.

urlscan has visibility and submission considerations as well; this version only searches existing scans.

## Official API documentation

- VirusTotal API v3: https://docs.virustotal.com/reference/overview
- VirusTotal search: https://docs.virustotal.com/reference/api-search
- urlscan API: https://docs.urlscan.io/pages/api-intro
- urlscan Search API: https://docs.urlscan.io/apis/urlscan-openapi/search

## License

MIT

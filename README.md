# ShodanX v1.0.0

> **Enterprise Red Team Intelligence Suite**

ShodanX is an enterprise-grade attack surface reconnaissance tool that chains multiple OSINT sources together — Shodan, crt.sh, HackerTarget, DNS resolution, InternetDB, and favicon fingerprinting — into a single automated pipeline. It takes an organization name as input and produces a verified, false-positive-free asset inventory with CVE analysis, technology fingerprinting, and a professional HTML report.

---

## What Makes It Different

Most Shodan tools run one or two queries and dump raw results. ShodanX runs up to 141 algorithmically generated queries ranked by confidence, filters out ISP noise and CDN edge nodes through strict relevance matching, enriches every IP with free InternetDB data, and delivers a clean report you can drop directly into a client deliverable.

---

## Features

- **QueryIntelligence Engine** — Analyzes the org name, detects abbreviations, infers industry, generates probable domains, and produces a ranked probability table of 100+ Shodan queries. User picks a confidence threshold before a single credit is spent.
- **Multi-Source Chaining** — crt.sh certificate transparency → HackerTarget passive DNS → mass DNS resolution → Shodan API → InternetDB enrichment → favicon hashing. Each phase feeds the next.
- **False Positive Removal** — Strict RelevanceFilter cross-checks every result against SSL cert CNs, hostnames, org fields, and SAN extensions. ISP infrastructure and CDN edge nodes are excluded.
- **Favicon Fingerprinting** — MurmurHash3 favicon hashing identifies products from HTTP responses. Detects Cobalt Strike C2, Metasploit, Grafana, Jenkins, VMware, Oracle WebLogic, SAP, and 15+ more.
- **CVE Analysis** — Severity breakdown into Critical / High / Medium / Low. Cross-referenced against a curated list of 21 known-critical CVEs including Log4Shell, ProxyShell, Citrix Bleed, SAP RECON, and more. InternetDB CVEs merged automatically.
- **Facet Queries (Free)** — Statistical port, product, country, and CVE distribution pulled via Shodan facets before any paid queries run.
- **Risk Grading** — A–F letter grade with 0–100 composite score per asset based on port criticality, CVE severity, WAF absence, and service type.
- **Enterprise HTML Report** — Dark-themed, fixed sidebar navigation, 4 charts, sortable asset table with 3-filter search, favicon hit table, DNS resolution table, geographic and ISP breakdown, technology stack, and export to CSV.
- **JSON Output** — Full machine-readable report for pipeline integration.

---

## Installation

```bash
git clone https://github.com/ShubhamGupta-VULNDETOX/ShodanX.git
cd ShodanX
pip install shodan requests
pip install mmh3   # optional — enables favicon hashing
```

Requires Python 3.8+. A Shodan API key is required — get one at [shodan.io](https://account.shodan.io).

---

## Usage

```bash
python shodanx.py
```

The tool is fully interactive:

```
[?] Shodan API Key: ••••••••••••••••
[?] Target organization name: Acme Corporation
[?] Primary domain (optional, e.g. example.com): acme.com
[?] Mode [1/2/3] (default 2): 2
```

### Scan Modes

| Mode | Description | Time |
|---|---|---|
| **Quick** | Facets + high-confidence queries + 1-page Shodan | ~1 min |
| **Balanced** | All passive recon + 2-page Shodan + all modules | ~3 min |
| **Deep** | Full chain + 5-page Shodan + all 141 queries | ~10 min |

### Output Files

```
shodanx_acme_corporation_20241201_143022.html   ← open in browser
shodanx_acme_corporation_20241201_143022.json   ← machine-readable
```

---

## Files

| File | Purpose |
|---|---|
| `shodanx.py` | Core engine — orchestration, scanning, enrichment, reporting |
| `query_intelligence.py` | Smart query generator — org analysis, probability scoring, planner UI |
| `shodanx_html_template.py` | HTML report template — dark UI, charts, tables, export |

---

## How QueryIntelligence Works

QueryIntelligence is pure algorithmic logic — no AI, no external calls during generation.

1. **Parse** the org name into significant words, detect industry, find known abbreviations
2. **Generate** base name variants (`acmecorp`, `acme-corp`, `acme`) and probable domains
3. **Score** every query type (org field, hostname, SSL cert CN, SSL cert org, HTTP title, product hunt, favicon hash) with a confidence percentage
4. **Display** a ranked table grouped by confidence band
5. **User selects** a threshold — only queries above it run

```
org:"Acme Corporation"                  95%  🏢
ssl.cert.subject.cn:"*.acme.com"        92%  🔒
hostname:acmecorp                        88%  🌐
org:"Acme Corporation" http.status:200  88%  🏢
ssl.cert.subject.o:"Acme Corporation"   82%  🔒
org:"Acme" product:"Microsoft Exchange" 82%  ⚙
...
```

---

## Recon Pipeline

```
Phase 1  →  crt.sh certificate transparency + HackerTarget passive DNS
Phase 2  →  Parallel DNS resolution (30 workers)
Phase 3  →  Shodan facets (free) + paid queries ranked by confidence
Phase 4  →  InternetDB enrichment for all discovered IPs
Phase 5  →  Favicon hashing for all HTTP/HTTPS services
Output   →  HTML report + JSON
```

---

## Risk Scoring

Each asset receives a 0–100 composite risk score:

| Factor | Points |
|---|---|
| Critical port (RDP, VNC, Redis, MongoDB, Docker...) | +40 |
| Sensitive port (SSH, SMTP, LDAP, SNMP...) | +20 |
| Per CVE matched (capped at 60) | +5–30 |
| Known critical CVE (Log4Shell, ProxyShell...) | +30 |
| VPN gateway exposed | +15 |
| No WAF detected | +5 |

**Grade scale:** A (clean) · B (minor issues) · C (moderate risk) · D (high risk) · F (3+ critical assets)

---

## Supported Shodan Filters

ShodanX uses the following Shodan filters across its query types:

`org:` `hostname:` `ssl.cert.subject.cn:` `ssl.cert.subject.o:` `ssl.cert.issuer.cn:` `ssl.cert.expired:` `ssl:` `http.title:` `http.status:` `http.html:` `http.favicon.hash:` `product:` `port:` `vuln:` + Shodan Facets API

---

## Detected Products via Favicon Hash

| Hash | Product |
|---|---|
| `-335242539` | Cobalt Strike C2 |
| `116323821` | Grafana |
| `-1028703694` | Fortinet / FortiGate |
| `81586312` | Jenkins |
| `1621371862` | VMware vSphere |
| `-1286589462` | Oracle WebLogic |
| `-338745917` | SAP Web GUI |
| `-1659512841` | Kibana |
| `1722105798` | phpMyAdmin |
| `541088007` | Jupyter Notebook |
| `442749392` | Outlook Web App |
| `1278323681` | GitLab |
| `893284639` | Havoc C2 |
| `-127886975` | Metasploit |
| `-471426521` | Webmin |

---

## Legal & Ethics

ShodanX queries publicly available data indexed by Shodan — the same information accessible to anyone with a port scanner. Shodan dorking is legal.

**Accessing or exploiting systems you do not own or have explicit written permission to test is illegal.** Use this tool only for:
- Your own infrastructure
- Authorized red team engagements
- Bug bounty programs within defined scope
- Defensive monitoring of your own IP ranges

---

## Requirements

```
Python      3.8+
shodan      pip install shodan
requests    pip install requests
mmh3        pip install mmh3     (optional, for favicon hashing)
```

---

## License

MIT License — see `LICENSE` for details.

---

*Built for security professionals. Use responsibly.*

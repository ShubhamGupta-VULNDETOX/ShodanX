#!/usr/bin/env python3
"""
QueryIntelligence — Smart Shodan Query Generator
No AI. Pure logic: string analysis, naming conventions, pattern matching.

How it works:
  1. Parse org name → extract tokens, abbreviations, domain guesses
  2. Score each query variant by confidence (0-100)
  3. Show user a ranked probability table
  4. User selects which to run (or run all above threshold)
"""

import re
import itertools
from dataclasses import dataclass, field
from typing import List, Tuple, Optional
from collections import OrderedDict


# ═══════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════

STOPWORDS = {
    "of", "the", "and", "for", "in", "on", "at", "to", "a", "an",
    "by", "from", "with", "into", "through", "during", "before",
    "after", "above", "below", "between",
}

# Legal suffixes — usually stripped for domain/hostname guessing
LEGAL_SUFFIXES = {
    "ltd", "limited", "inc", "corp", "corporation", "pvt", "private",
    "llc", "llp", "plc", "gmbh", "ag", "sa", "nv", "bv", "co",
    "company", "group", "holdings", "international", "global",
    "technologies", "technology", "tech", "solutions", "services",
    "systems", "consulting", "enterprises", "ventures",
}

# Industry-specific suffixes that hint at domain patterns
INDUSTRY_HINTS = {
    "bank":      [".com", ".in", ".co.in", ".bank", ".bank.in", ".net"],
    "insurance": [".com", ".in", ".co.in", ".org"],
    "hospital":  [".com", ".in", ".org", ".co.in"],
    "university":[".edu", ".ac.in", ".edu.in", ".org"],
    "college":   [".edu", ".ac.in", ".edu.in"],
    "school":    [".edu", ".ac.in", ".org"],
    "government":[".gov", ".gov.in", ".nic.in", ".org"],
    "ministry":  [".gov.in", ".nic.in", ".gov"],
    "defence":   [".mil", ".gov", ".gov.in", ".nic.in"],
    "railways":  [".gov.in", ".nic.in", ".com", ".co.in"],
    "telecom":   [".com", ".in", ".co.in", ".net"],
    "airline":   [".com", ".in", ".co.in", ".aero"],
    "airport":   [".com", ".in", ".aero"],
    "petroleum": [".com", ".in", ".co.in"],
    "power":     [".com", ".in", ".co.in", ".gov.in"],
}

# Common TLDs to try in priority order
DEFAULT_TLDS = [".com", ".in", ".co.in", ".org", ".net", ".io", ".co"]

# Known abbreviation patterns
COMMON_ABBREVS = {
    "state bank of india": "sbi",
    "bank of baroda": "bob",
    "bank of india": "boi",
    "punjab national bank": "pnb",
    "hdfc bank": "hdfc",
    "icici bank": "icici",
    "axis bank": "axis",
    "tata consultancy services": "tcs",
    "oil and natural gas corporation": "ongc",
    "national thermal power corporation": "ntpc",
    "bharat petroleum corporation": "bpcl",
    "bharat heavy electricals": "bhel",
    "steel authority of india": "sail",
    "life insurance corporation": "lic",
    "air india": "ai",
    "indian railways": "ir",
    "infosys limited": "infy",
    "wipro limited": "wipro",
    "reliance industries": "ril",
    "mahindra and mahindra": "m&m",
    "larsen and toubro": "l&t",
}

# Query type metadata
QUERY_META = {
    "org":       {"label": "Org Name",        "icon": "🏢", "credit_cost": 1},
    "hostname":  {"label": "Hostname",        "icon": "🌐", "credit_cost": 1},
    "ssl_cn":    {"label": "SSL Cert CN",     "icon": "🔒", "credit_cost": 1},
    "ssl_o":     {"label": "SSL Cert Org",    "icon": "🔒", "credit_cost": 1},
    "ssl_kw":    {"label": "SSL Keyword",     "icon": "🔑", "credit_cost": 1},
    "http_title":{"label": "HTTP Title",      "icon": "📄", "credit_cost": 1},
    "net":       {"label": "CIDR Range",      "icon": "🗺", "credit_cost": 1},
    "asn":       {"label": "ASN",             "icon": "📡", "credit_cost": 1},
    "product":   {"label": "Product/Version", "icon": "⚙",  "credit_cost": 1},
    "favicon":   {"label": "Favicon Hash",    "icon": "🖼",  "credit_cost": 1},
    "http_html": {"label": "HTTP Body",       "icon": "🔍", "credit_cost": 1},
    "facet":     {"label": "Facet (Free)",    "icon": "📊", "credit_cost": 0},
}


# ═══════════════════════════════════════════════════════════════════════
# QUERY OBJECT
# ═══════════════════════════════════════════════════════════════════════

@dataclass
class ShodanQuery:
    query:       str
    qtype:       str
    confidence:  int          # 0-100
    reasoning:   str          # why this confidence
    label:       str          # human-readable label
    is_facet:    bool = False
    facets:      List[str] = field(default_factory=list)
    enabled:     bool = True  # user can toggle

    @property
    def credit_cost(self):
        return 0 if self.is_facet else QUERY_META.get(self.qtype, {}).get("credit_cost", 1)

    @property
    def icon(self):
        return QUERY_META.get(self.qtype, {}).get("icon", "•")

    @property
    def type_label(self):
        return QUERY_META.get(self.qtype, {}).get("label", self.qtype)

    def confidence_bar(self, width=20):
        filled = int(width * self.confidence / 100)
        return "█" * filled + "░" * (width - filled)

    def confidence_color(self):
        from shodanx import C
        if self.confidence >= 80: return C.G
        if self.confidence >= 60: return C.Y
        return C.R


# ═══════════════════════════════════════════════════════════════════════
# ORG NAME PARSER — extracts all structural info from an org name
# ═══════════════════════════════════════════════════════════════════════

class OrgNameParser:
    """
    Pure string analysis of an org name.
    No external calls. No AI. Just patterns.
    """

    def __init__(self, org_name: str, domain: Optional[str] = None):
        self.raw         = org_name.strip()
        self.domain      = domain
        self.lower       = self.raw.lower()
        self.words       = self.lower.split()
        self.clean_words = [w for w in self.words if re.sub(r'[^a-z]','',w)]

        # Core analysis
        self.significant = self._significant_words()
        self.abbrev      = self._find_abbreviation()
        self.industry    = self._detect_industry()
        self.tlds        = self._probable_tlds()
        self.base_names  = self._generate_base_names()
        self.domains     = self._generate_domains()
        self.has_numbers = bool(re.search(r'\d', self.raw))
        self.word_count  = len(self.significant)

    def _significant_words(self) -> List[str]:
        """Words that carry meaning — no stopwords, no legal suffixes."""
        words = []
        for w in self.clean_words:
            cleaned = re.sub(r'[^a-z0-9]', '', w)
            if cleaned and cleaned not in STOPWORDS and cleaned not in LEGAL_SUFFIXES:
                words.append(cleaned)
        return words

    def _find_abbreviation(self) -> Optional[str]:
        """Find known abbreviation or derive one algorithmically."""
        # Check known abbreviations table first
        known = COMMON_ABBREVS.get(self.lower.rstrip('.').strip())
        if known:
            return known

        # Derive from significant words
        sig = self.significant
        if not sig:
            return None

        # Classic acronym: first letter of each significant word
        if len(sig) >= 2:
            acronym = "".join(w[0] for w in sig)
            if len(acronym) <= 6:
                return acronym

        # Single significant word → use as-is
        if len(sig) == 1:
            return sig[0]

        return None

    def _detect_industry(self) -> Optional[str]:
        """Detect industry sector from org name."""
        for industry in INDUSTRY_HINTS:
            if industry in self.lower:
                return industry
        return None

    def _probable_tlds(self) -> List[str]:
        """Return TLDs in probability order based on industry."""
        if self.domain:
            # Extract TLD from provided domain, put it first
            parts = self.domain.split(".")
            tld = "." + ".".join(parts[1:]) if len(parts) > 2 else "." + parts[-1]
            tlds = [tld] + [t for t in (INDUSTRY_HINTS.get(self.industry) or DEFAULT_TLDS) if t != tld]
            return tlds[:6]
        if self.industry:
            return INDUSTRY_HINTS.get(self.industry, DEFAULT_TLDS)[:6]
        return DEFAULT_TLDS[:5]

    def _generate_base_names(self) -> List[Tuple[str, int]]:
        """
        Generate hostname base name candidates with confidence.
        Returns: [(name, confidence), ...]
        """
        candidates = []
        sig = self.significant

        if not sig:
            return candidates

        # 1. All significant words joined (most common pattern)
        joined = "".join(sig)
        if len(joined) >= 3:
            candidates.append((joined, 90))

        # 2. Hyphenated
        if len(sig) > 1:
            hyphen = "-".join(sig)
            candidates.append((hyphen, 75))

        # 3. First word only (if meaningful and long enough)
        if sig[0] and len(sig[0]) >= 4:
            candidates.append((sig[0], 65))

        # 4. First word + last word
        if len(sig) >= 3:
            first_last = sig[0] + sig[-1]
            if len(first_last) >= 4:
                candidates.append((first_last, 70))

        # 5. Abbreviation
        if self.abbrev and self.abbrev != joined:
            # confidence depends on whether it's a known abbreviation
            abbrev_conf = 85 if self.abbrev in COMMON_ABBREVS.values() else 55
            candidates.append((self.abbrev, abbrev_conf))

        # 6. First two significant words
        if len(sig) >= 2:
            two = "".join(sig[:2])
            if two != joined and len(two) >= 4:
                candidates.append((two, 60))

        # 7. If domain provided, extract its hostname base
        if self.domain:
            base = self.domain.split(".")[0]
            # Check if it's already in candidates
            existing = {n for n, _ in candidates}
            if base not in existing:
                candidates.append((base, 95))  # highest confidence — user provided it

        # Deduplicate while preserving max confidence
        seen = {}
        for name, conf in candidates:
            if name not in seen or seen[name] < conf:
                seen[name] = conf

        return sorted(seen.items(), key=lambda x: -x[1])

    def _generate_domains(self) -> List[Tuple[str, int]]:
        """Generate probable domain candidates with confidence."""
        domains = []
        tlds = self.tlds

        for base, base_conf in self.base_names[:5]:
            for i, tld in enumerate(tlds):
                # Confidence decreases with TLD priority
                tld_penalty = i * 8
                domain_conf = max(base_conf - tld_penalty, 20)
                full = base + tld
                domains.append((full, domain_conf))

        # If domain was provided, it gets 100%
        if self.domain:
            existing = {d for d, _ in domains}
            if self.domain not in existing:
                domains.insert(0, (self.domain, 100))
            else:
                # Boost the provided domain to 100
                domains = [(d, 100 if d == self.domain else c) for d, c in domains]

        # Deduplicate
        seen = {}
        for d, c in domains:
            if d not in seen or seen[d] < c:
                seen[d] = c

        return sorted(seen.items(), key=lambda x: -x[1])


# ═══════════════════════════════════════════════════════════════════════
# QUERY INTELLIGENCE ENGINE
# ═══════════════════════════════════════════════════════════════════════

class QueryIntelligence:
    """
    Generates ALL probable Shodan queries for an org with confidence scores.
    Pure algorithmic logic — no AI, no external calls during generation.
    """

    def __init__(self, org_name: str, domain: Optional[str] = None):
        self.org    = org_name
        self.domain = domain
        self.parser = OrgNameParser(org_name, domain)
        self._queries: List[ShodanQuery] = []

    def generate(self) -> List[ShodanQuery]:
        """Generate all queries. Returns sorted by confidence desc."""
        self._queries = []

        self._gen_org_queries()
        self._gen_hostname_queries()
        self._gen_ssl_queries()
        self._gen_http_queries()
        self._gen_facet_queries()
        self._gen_product_queries()

        # Sort: facets last (free), then by confidence desc
        self._queries.sort(key=lambda q: (q.is_facet, -q.confidence))
        return self._queries

    # ─── ORG FIELD QUERIES ───────────────────────────────────────────
    def _gen_org_queries(self):
        raw = self.org

        # Exact org name — always highest confidence
        self._add(ShodanQuery(
            query      = f'org:"{raw}"',
            qtype      = "org",
            confidence = 95,
            reasoning  = "Direct org field match — Shodan indexes ASN WHOIS org names",
            label      = f"Org exact: {raw}",
        ))

        # Org name without legal suffixes
        sig_joined = " ".join(self.parser.significant)
        if sig_joined and sig_joined.lower() != raw.lower():
            self._add(ShodanQuery(
                query      = f'org:"{sig_joined}"',
                qtype      = "org",
                confidence = 78,
                reasoning  = "Org name stripped of legal suffixes (Ltd, Corp, etc.) — common in WHOIS",
                label      = f"Org stripped: {sig_joined}",
            ))

        # Common legal suffix variants
        suffixes = ["Ltd", "Limited", "Inc", "Corp", "Pvt Ltd", "Private Limited"]
        for suf in suffixes:
            variant = f"{raw} {suf}"
            if suf.lower() not in raw.lower():
                conf = 55 if "Ltd" in suf or "Inc" in suf else 45
                self._add(ShodanQuery(
                    query      = f'org:"{variant}"',
                    qtype      = "org",
                    confidence = conf,
                    reasoning  = f"Legal suffix variant '{suf}' commonly appended in WHOIS registrations",
                    label      = f"Org variant: {variant}",
                ))

        # Abbreviation in org field
        if self.parser.abbrev:
            abbrev_upper = self.parser.abbrev.upper()
            conf = 72 if self.parser.abbrev in COMMON_ABBREVS.values() else 42
            self._add(ShodanQuery(
                query      = f'org:"{abbrev_upper}"',
                qtype      = "org",
                confidence = conf,
                reasoning  = f"Known abbreviation '{abbrev_upper}' may appear in org field for subsidiaries",
                label      = f"Org abbrev: {abbrev_upper}",
            ))

    # ─── HOSTNAME QUERIES ─────────────────────────────────────────────
    def _gen_hostname_queries(self):
        for base, conf in self.parser.base_names:
            if len(base) < 3:
                continue

            # Direct hostname match
            self._add(ShodanQuery(
                query      = f"hostname:{base}",
                qtype      = "hostname",
                confidence = min(conf, 88),
                reasoning  = f"'{base}' derived from org name — likely subdomain pattern",
                label      = f"Hostname: {base}",
            ))

            # Common subdomain patterns
            prefixes = [
                ("www",      85, "Primary web presence — very common"),
                ("mail",     70, "Mail servers often in Shodan"),
                ("vpn",      75, "VPN gateways — high value target"),
                ("remote",   65, "Remote access portals"),
                ("portal",   65, "Client/employee portals"),
                ("api",      60, "API endpoints"),
                ("dev",      55, "Development environments — often insecure"),
                ("staging",  50, "Staging servers — frequently forgotten"),
                ("admin",    60, "Admin panels"),
                ("owa",      65, "Outlook Web Access — Exchange servers"),
                ("webmail",  60, "Webmail interfaces"),
                ("mx",       55, "Mail exchange servers"),
                ("ns",       45, "Nameservers"),
                ("ftp",      50, "FTP servers"),
                ("sftp",     45, "SFTP endpoints"),
                ("backup",   55, "Backup systems — often exposed"),
                ("monitor",  45, "Monitoring dashboards"),
                ("intranet", 50, "Intranet portals accidentally exposed"),
            ]
            for prefix, pconf, reason in prefixes:
                subdomain = f"{prefix}.{base}"
                if conf >= 70:  # only add subdomain variants for high-confidence bases
                    self._add(ShodanQuery(
                        query      = f"hostname:{subdomain}",
                        qtype      = "hostname",
                        confidence = min(conf - 15, pconf),
                        reasoning  = f"{reason} — derived from base '{base}'",
                        label      = f"Hostname: {subdomain}",
                    ))

    # ─── SSL CERTIFICATE QUERIES ──────────────────────────────────────
    def _gen_ssl_queries(self):
        # SSL cert subject CN — wildcard domains
        for domain, conf in self.parser.domains[:6]:
            self._add(ShodanQuery(
                query      = f'ssl.cert.subject.cn:"*.{domain}"',
                qtype      = "ssl_cn",
                confidence = min(conf, 92),
                reasoning  = f"Wildcard cert for *.{domain} — links all SSL assets under this domain",
                label      = f"SSL CN: *.{domain}",
            ))
            # Exact domain in CN
            self._add(ShodanQuery(
                query      = f'ssl.cert.subject.cn:"{domain}"',
                qtype      = "ssl_cn",
                confidence = min(conf - 5, 85),
                reasoning  = f"Exact CN match for {domain}",
                label      = f"SSL CN exact: {domain}",
            ))

        # SSL cert subject O (organization field in cert)
        self._add(ShodanQuery(
            query      = f'ssl.cert.subject.o:"{self.org}"',
            qtype      = "ssl_o",
            confidence = 82,
            reasoning  = "Organization field in SSL cert — links certs issued directly to the org",
            label      = f"SSL Org: {self.org}",
        ))
        # Stripped version
        sig = " ".join(self.parser.significant).title()
        if sig and sig != self.org:
            self._add(ShodanQuery(
                query      = f'ssl.cert.subject.o:"{sig}"',
                qtype      = "ssl_o",
                confidence = 68,
                reasoning  = "Stripped org name in cert O field — subsidiaries often use shorter names",
                label      = f"SSL Org stripped: {sig}",
            ))

        # SSL keyword searches (searches across all SSL fields)
        for base, conf in self.parser.base_names[:4]:
            if len(base) >= 5:
                self._add(ShodanQuery(
                    query      = f'ssl:"{base}"',
                    qtype      = "ssl_kw",
                    confidence = min(conf - 10, 75),
                    reasoning  = f"'{base}' anywhere in SSL data — finds certs that mention the org",
                    label      = f"SSL keyword: {base}",
                ))

        # Expired certs — hygiene indicator
        self._add(ShodanQuery(
            query      = f'ssl.cert.expired:true org:"{self.org}"',
            qtype      = "ssl_cn",
            confidence = 70,
            reasoning  = "Expired certs = poor maintenance culture — often found on forgotten assets",
            label      = f"SSL expired: {self.org}",
        ))

        # Self-signed certs — internal services exposed
        for base, conf in self.parser.base_names[:2]:
            if conf >= 70:
                self._add(ShodanQuery(
                    query      = f'ssl.cert.issuer.cn:"{base}"',
                    qtype      = "ssl_cn",
                    confidence = 50,
                    reasoning  = "Self-signed certs where org issued their own cert — internal services accidentally exposed",
                    label      = f"SSL self-signed: {base}",
                ))

    # ─── HTTP TITLE / BODY QUERIES ────────────────────────────────────
    def _gen_http_queries(self):
        raw = self.org

        # HTTP title exact
        self._add(ShodanQuery(
            query      = f'http.title:"{raw}"',
            qtype      = "http_title",
            confidence = 72,
            reasoning  = "Org name in page title — login portals, intranet pages, admin panels",
            label      = f"Title: {raw}",
        ))

        # HTTP title with significant words
        sig = " ".join(self.parser.significant[:3]).title()
        if sig and sig != raw:
            self._add(ShodanQuery(
                query      = f'http.title:"{sig}"',
                qtype      = "http_title",
                confidence = 60,
                reasoning  = "Core words from org name in title — catches abbreviated page titles",
                label      = f"Title partial: {sig}",
            ))

        # Common page title patterns for known page types
        for base, conf in self.parser.base_names[:2]:
            if conf >= 70:
                titles = [
                    (f"{base.title()} Portal",   52, "Employee/client portals"),
                    (f"{base.upper()} Login",     50, "Login pages"),
                    (f"{base.title()} Admin",     55, "Admin panels"),
                    (f"{base.title()} VPN",       58, "VPN login pages"),
                ]
                for title, tconf, reason in titles:
                    self._add(ShodanQuery(
                        query      = f'http.title:"{title}"',
                        qtype      = "http_title",
                        confidence = tconf,
                        reasoning  = f"{reason} — common pattern for '{base}'",
                        label      = f"Title: {title}",
                    ))

        # HTTP body keyword searches (searches page content)
        for base, conf in self.parser.base_names[:2]:
            if conf >= 80 and len(base) >= 6:
                self._add(ShodanQuery(
                    query      = f'http.html:"{base}"',
                    qtype      = "http_html",
                    confidence = 52,
                    reasoning  = f"'{base}' in page body — finds pages that mention the org even without it in title",
                    label      = f"HTML body: {base}",
                ))

        # HTTP status 200 — live services only
        self._add(ShodanQuery(
            query      = f'org:"{raw}" http.status:200',
            qtype      = "org",
            confidence = 88,
            reasoning  = "Org filter + HTTP 200 — live web services only, eliminates dead hosts",
            label      = f"Live web: {raw}",
        ))

        # Shadow IT hunting — HTTP on non-standard ports
        self._add(ShodanQuery(
            query      = f'org:"{raw}" http.status:200 -port:80 -port:443 -port:8080 -port:8443',
            qtype      = "org",
            confidence = 70,
            reasoning  = "HTTP services on unusual ports = shadow IT, forgotten dev servers, misconfigured services",
            label      = f"Shadow IT: {raw}",
        ))

    # ─── FACET QUERIES (FREE — no credit cost) ────────────────────────
    def _gen_facet_queries(self):
        raw = self.org

        # Use unique sentinel so dedup doesn't block these
        FACET_PREFIX = "__FACET__"

        # Main facet — statistical overview before burning credits
        self._queries.append(ShodanQuery(
            query      = f'org:"{raw}"',
            qtype      = "facet",
            confidence = 98,
            reasoning  = "FREE: facets give statistical breakdown (ports, products, countries, CVEs) for 0 credits — run this first",
            label      = f"📊 Facet overview: {raw}",
            is_facet   = True,
            facets     = ["port:20", "product:15", "country:10", "vuln:20", "os:10", "isp:10"],
        ))

        # Top CVEs across org (invaluable, free)
        self._queries.append(ShodanQuery(
            query      = f'org:"{raw}"',
            qtype      = "facet",
            confidence = 95,
            reasoning  = "FREE: top CVEs matched across org's entire surface — no per-host credit cost",
            label      = f"📊 Facet CVEs: {raw}",
            is_facet   = True,
            facets     = ["vuln:50"],
        ))

        # Top ports facet
        self._queries.append(ShodanQuery(
            query      = f'org:"{raw}"',
            qtype      = "facet",
            confidence = 92,
            reasoning  = "FREE: port distribution — understand attack surface before deciding what to search",
            label      = f"📊 Facet ports: {raw}",
            is_facet   = True,
            facets     = ["port:30"],
        ))

    # ─── PRODUCT/VERSION QUERIES ──────────────────────────────────────
    def _gen_product_queries(self):
        raw = self.org

        # High-value product targeting — cross-reference with org
        targets = [
            # (product_filter, port, confidence, reasoning)
            ('product:"Microsoft Exchange"',      443,  82, "Exchange OWA — ProxyShell/ProxyLogon hunting"),
            ('product:"Apache httpd"',            None, 70, "Apache versions — CVE version targeting"),
            ('product:"nginx"',                   None, 65, "Nginx — config issues, info disclosure"),
            ('product:"Microsoft IIS"',           80,   72, "IIS — often older, known CVEs"),
            ('product:"OpenSSH"',                 22,   68, "SSH version fingerprinting"),
            ('product:"VMware"',                  443,  78, "VMware vCenter/ESXi — ransomware target"),
            ('product:"Fortinet"',                443,  75, "FortiGate VPN — active CVE exploits"),
            ('product:"Cisco"',                   None, 70, "Cisco devices — version-specific CVEs"),
            ('product:"Palo Alto"',               443,  72, "Palo Alto VPN — CVE-2024-3400"),
            ('http.title:"Outlook Web App"',      443,  80, "Exchange OWA login pages"),
            ('http.title:"Citrix Gateway"',       443,  75, "Citrix Netscaler — Citrix Bleed"),
            ('http.title:"Confluence"',           None, 78, "Confluence — CVE-2022-26134 unauthenticated RCE"),
            ('http.title:"Grafana"',              None, 65, "Grafana — CVE-2021-43798 path traversal"),
            ('http.title:"Jenkins"',              None, 65, "Jenkins — Script Console RCE risk"),
            ('"MongoDB Server Information"',      27017,75, "Open MongoDB — no auth"),
            ('"redis_version"',                   6379, 78, "Open Redis — potential RCE"),
            ('port:3389',                         3389, 80, "RDP exposed — #1 ransomware entry point"),
            ('port:5900 "authentication disabled"', 5900, 82, "VNC with no auth"),
        ]

        for product_filter, port, conf, reason in targets:
            port_part = f" port:{port}" if port else ""
            self._add(ShodanQuery(
                query      = f'org:"{raw}" {product_filter}{port_part}',
                qtype      = "product",
                confidence = conf,
                reasoning  = reason,
                label      = f"Product hunt: {product_filter[:40]}",
            ))

    # ─── HELPER ──────────────────────────────────────────────────────
    def _add(self, q: ShodanQuery):
        # Deduplicate by query string
        existing = {x.query for x in self._queries}
        if q.query not in existing:
            self._queries.append(q)

    def total_credits(self, queries: List[ShodanQuery]) -> int:
        return sum(q.credit_cost for q in queries if q.enabled and not q.is_facet)

    def summary_by_type(self, queries: List[ShodanQuery]) -> dict:
        by_type = {}
        for q in queries:
            t = q.type_label
            if t not in by_type:
                by_type[t] = {"count": 0, "total_conf": 0, "queries": []}
            by_type[t]["count"] += 1
            by_type[t]["total_conf"] += q.confidence
            by_type[t]["queries"].append(q)
        return by_type


# ═══════════════════════════════════════════════════════════════════════
# INTERACTIVE DISPLAY
# ═══════════════════════════════════════════════════════════════════════

class QueryPlanner:
    """
    Shows the probability table, lets user select/deselect queries,
    set a confidence threshold, and confirms before running.
    """

    def __init__(self, org: str, domain: Optional[str] = None):
        self.org     = org
        self.domain  = domain
        self.engine  = QueryIntelligence(org, domain)
        self.queries: List[ShodanQuery] = []

    def run(self) -> Optional[List[ShodanQuery]]:
        """Full interactive planning flow. Returns selected queries or None."""
        try:
            from shodanx import C
        except ImportError:
            class C:
                H='';B='';CY='';G='';Y='';R='';BD='';DM='';RS=''

        print(f"\n  {C.BD}{C.CY}╔══════════════════════════════════════════════════════════╗")
        print(f"  ║         QUERY INTELLIGENCE — Probability Analysis        ║")
        print(f"  ╚══════════════════════════════════════════════════════════╝{C.RS}")
        print(f"\n  Analyzing: {C.BD}{self.org}{C.RS}", end="")
        if self.domain:
            print(f" · {C.CY}{self.domain}{C.RS}", end="")
        print("\n")

        # Generate
        print(f"  {C.DM}Generating query variants...{C.RS}")
        self.queries = self.engine.generate()
        print(f"  {C.G}[+]{C.RS} {len(self.queries)} queries generated\n")

        # Show org analysis
        self._show_org_analysis(C)

        # Show query table
        self._show_query_table(C)

        # Threshold filter
        threshold = self._ask_threshold(C)
        selected  = [q for q in self.queries if q.confidence >= threshold or q.is_facet]

        # Show selection summary
        self._show_selection_summary(selected, C)

        # Confirm
        answer = input(f"\n  {C.CY}[?]{C.RS} Run these {len(selected)} queries? [Y/n/edit]: ").strip().lower()

        if answer == "n":
            return None
        if answer == "edit":
            selected = self._manual_edit(selected, C)

        return selected if selected else None

    def _show_org_analysis(self, C):
        p = self.engine.parser
        print(f"  {C.BD}┌─ Org Name Analysis ──────────────────────────────────────┐{C.RS}")
        print(f"  │  Raw:          {C.BD}{p.raw}{C.RS}")
        print(f"  │  Significant:  {C.G}{' · '.join(p.significant)}{C.RS}")
        if p.abbrev:
            src = "known" if p.abbrev in COMMON_ABBREVS.values() else "derived"
            print(f"  │  Abbreviation: {C.Y}{p.abbrev.upper()}{C.RS}  ({src})")
        if p.industry:
            print(f"  │  Industry:     {C.CY}{p.industry.title()}{C.RS}")
        print(f"  │  Base names:   {', '.join(f'{n}({c}%)' for n,c in p.base_names[:5])}")
        print(f"  │  Probable domains:")
        for domain, conf in p.domains[:5]:
            bar = "█" * int(conf/10) + "░" * (10 - int(conf/10))
            print(f"  │    {bar} {conf:3d}%  {C.CY}{domain}{C.RS}")
        print(f"  {C.BD}└──────────────────────────────────────────────────────────┘{C.RS}\n")

    def _show_query_table(self, C):
        # Group by type
        facets  = [q for q in self.queries if q.is_facet]
        regular = [q for q in self.queries if not q.is_facet]

        # Show facets first (free)
        print(f"  {C.BD}┌─ FREE Queries (Facets — 0 Credits) ─────────────────────┐{C.RS}")
        for q in facets:
            bar = f"{C.G}{q.confidence_bar(15)}{C.RS}"
            print(f"  │  {bar} {q.confidence:3d}%  {C.CY}{q.icon}{C.RS}  {q.label[:55]}")
        print(f"  {C.BD}└──────────────────────────────────────────────────────────┘{C.RS}\n")

        # Regular queries by confidence band
        bands = [
            (80, 100, f"{C.G}HIGH CONFIDENCE (80-100%){C.RS}", C.G),
            (60,  79, f"{C.Y}MEDIUM CONFIDENCE (60-79%){C.RS}", C.Y),
            (40,  59, f"{C.R}LOWER CONFIDENCE (40-59%){C.RS}", C.R),
        ]

        for low, high, title, col in bands:
            band_q = [q for q in regular if low <= q.confidence <= high]
            if not band_q:
                continue
            print(f"  {C.BD}┌─ {title} {'─'*(47-len(title)//2)}┐{C.RS}")
            for q in band_q:
                bar = q.confidence_bar(12)
                print(f"  │  {col}{bar}{C.RS}  {q.confidence:3d}%  {q.icon}  {q.type_label:<16}  {q.query[:50]}")
            print(f"  │  {C.DM}  ({len(band_q)} queries · {sum(q.credit_cost for q in band_q)} credit(s)){C.RS}")
            print(f"  {C.BD}└──────────────────────────────────────────────────────────┘{C.RS}\n")

    def _show_selection_summary(self, selected, C):
        facets  = [q for q in selected if q.is_facet]
        regular = [q for q in selected if not q.is_facet]
        credits = sum(q.credit_cost for q in regular)

        print(f"\n  {C.BD}┌─ Selection Summary ──────────────────────────────────────┐{C.RS}")
        print(f"  │  Total queries:   {len(selected)}")
        print(f"  │  Free (facets):   {C.G}{len(facets)}{C.RS}")
        print(f"  │  Paid queries:    {C.Y}{len(regular)}{C.RS}")
        print(f"  │  Credits needed:  {C.BD}{credits}{C.RS}")
        avg = sum(q.confidence for q in selected) / len(selected) if selected else 0
        print(f"  │  Avg confidence:  {avg:.0f}%")
        print(f"  {C.BD}└──────────────────────────────────────────────────────────┘{C.RS}")

    def _ask_threshold(self, C):
        print(f"\n  {C.BD}Confidence Threshold:{C.RS}")
        print(f"  {C.G}[1]{C.RS} High only    ≥80%  — precision, fewer queries")
        print(f"  {C.Y}[2]{C.RS} Medium+      ≥60%  — balanced (recommended)")
        print(f"  {C.R}[3]{C.RS} All          ≥40%  — maximum coverage")
        print(f"  {C.DM}[4]{C.RS} Custom       enter number")
        choice = input(f"\n  {C.CY}[?]{C.RS} Select threshold [1/2/3/4] (default 2): ").strip()
        mapping = {"1": 80, "2": 60, "3": 40, "": 60}
        if choice in mapping:
            return mapping[choice]
        if choice == "4":
            try:
                val = int(input(f"  {C.CY}[?]{C.RS} Enter threshold (0-100): ").strip())
                return max(0, min(100, val))
            except ValueError:
                return 60
        return 60

    def _manual_edit(self, selected, C):
        print(f"\n  {C.BD}Manual Query Editor{C.RS}")
        print(f"  {C.DM}Enter query numbers to toggle (comma separated), or 'done'{C.RS}\n")
        all_q = self.queries
        for i, q in enumerate(all_q):
            status = f"{C.G}✓{C.RS}" if q in selected else f"{C.R}✗{C.RS}"
            print(f"  [{i+1:3d}] {status}  {q.confidence:3d}%  {q.query[:60]}")
        while True:
            inp = input(f"\n  {C.CY}[?]{C.RS} Toggle queries (e.g. 1,3,5) or 'done': ").strip()
            if inp.lower() == "done":
                break
            try:
                nums = [int(x.strip()) - 1 for x in inp.split(",")]
                for n in nums:
                    if 0 <= n < len(all_q):
                        q = all_q[n]
                        if q in selected:
                            selected.remove(q)
                        else:
                            selected.append(q)
            except ValueError:
                print(f"  {C.R}Invalid input{C.RS}")
        return selected

    def verbose_explain(self, query: ShodanQuery):
        """Print detailed explanation for a single query."""
        try:
            from shodanx import C
        except ImportError:
            class C:
                H='';B='';CY='';G='';Y='';R='';BD='';DM='';RS=''

        print(f"\n  {C.BD}Query:{C.RS}      {C.CY}{query.query}{C.RS}")
        print(f"  {C.BD}Type:{C.RS}       {query.icon} {query.type_label}")
        print(f"  {C.BD}Confidence:{C.RS} {query.confidence}% {query.confidence_bar()}")
        print(f"  {C.BD}Reasoning:{C.RS}  {query.reasoning}")
        print(f"  {C.BD}Credits:{C.RS}    {'FREE' if query.is_facet else query.credit_cost}")


# ═══════════════════════════════════════════════════════════════════════
# STANDALONE TEST / DEMO
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    org    = " ".join(sys.argv[1:]) if len(sys.argv) > 1 else "Target Organization"
    domain = None

    class C:
        H='\033[95m'; B='\033[94m'; CY='\033[96m'; G='\033[92m'
        Y='\033[93m'; R='\033[91m'; BD='\033[1m';  DM='\033[2m'; RS='\033[0m'

    print(f"\n  {C.BD}ShodanX QueryIntelligence Demo{C.RS}")
    print(f"  Org: {org}\n")

    engine  = QueryIntelligence(org, domain)
    queries = engine.generate()

    p = engine.parser
    print(f"  Significant words:  {p.significant}")
    print(f"  Abbreviation:       {p.abbrev}")
    print(f"  Industry detected:  {p.industry}")
    print(f"  Base names:         {p.base_names[:5]}")
    print(f"  Probable domains:   {p.domains[:5]}")
    print(f"\n  Total queries generated: {len(queries)}")
    print(f"  Facets (free):           {sum(1 for q in queries if q.is_facet)}")
    print(f"  Paid queries:            {sum(1 for q in queries if not q.is_facet)}")
    print()

    for q in queries[:20]:
        bar = ('█' * int(q.confidence/5)).ljust(20, '░')
        print(f"  {bar}  {q.confidence:3d}%  {q.icon}  {q.query[:60]}")
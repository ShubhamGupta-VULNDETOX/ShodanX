#!/usr/bin/env python3
"""
ShodanX v1.0 — Enterprise Red Team Intelligence Suite

Usage: python shodanx.py
Requires: pip install shodan requests
Optional: pip install mmh3  (for favicon hashing)
"""

import shodan
import json
import time
import re
import sys
import socket
import urllib.parse
from datetime import datetime, timezone
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("ERROR: requests library required. Run: pip install requests")
    sys.exit(1)

try:
    import mmh3
    HAS_MMH3 = True
except ImportError:
    HAS_MMH3 = False

# QueryIntelligence — smart query planner (graceful fallback if missing)
try:
    from query_intelligence import QueryIntelligence, QueryPlanner, ShodanQuery as ShodanQueryObj
    HAS_QI = True
except ImportError:
    HAS_QI = False

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ═══════════════════════════════════════════════════════════════════════
# VERSION & CONSTANTS
# ═══════════════════════════════════════════════════════════════════════
VERSION = "1.0.0"

CRTSH_URL           = "https://crt.sh/?q=%25.{domain}&output=json"
INTERNETDB_URL     = "https://internetdb.shodan.io/{ip}"
HT_HOSTSEARCH_URL  = "https://api.hackertarget.com/hostsearch/?q={domain}"
HT_REVERSEIP_URL   = "https://api.hackertarget.com/reverseiplookup/?q={ip}"
BGP_VIEW_URL       = "https://api.bgpview.io/ip/{ip}"

REQUEST_TIMEOUT  = 10
DNS_TIMEOUT      = 3
MAX_DNS_WORKERS  = 30
MAX_ENRICH_WORKERS = 20
MAX_FAVICON_WORKERS = 15
SHODAN_RATE_SLEEP = 1.1

HIGH_RISK_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    502: "Modbus", 554: "RTSP", 873: "Rsync",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    2375: "Docker", 3306: "MySQL", 3389: "RDP", 4848: "GlassFish",
    5432: "PostgreSQL", 5900: "VNC", 5984: "CouchDB", 6379: "Redis",
    7001: "WebLogic", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8500: "Consul", 8888: "Jupyter", 9000: "Portainer",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    10000: "Webmin", 11211: "Memcached", 27017: "MongoDB",
    50070: "Hadoop", 61616: "ActiveMQ",
}

CRITICAL_PORTS = {
    23, 445, 3389, 5900, 6379, 9200, 27017, 161, 1433, 1521,
    3306, 2375, 7001, 11211, 50070, 873, 502
}

WAF_SIGNATURES = {
    "Cloudflare":  ["cloudflare", "cf-ray", "__cfduid"],
    "Akamai":      ["akamai", "akamaighost", "x-akamai"],
    "F5 BIG-IP":   ["bigip", "big-ip", "f5", "ts0"],
    "AWS WAF":     ["awswaf", "x-amzn-waf", "x-amz-cf"],
    "Imperva":     ["imperva", "incapsula", "visid_incap"],
    "Fortinet":    ["fortigate", "fortiweb", "fortios"],
    "Barracuda":   ["barracuda"],
    "Citrix":      ["citrix", "netscaler"],
    "Sucuri":      ["sucuri", "x-sucuri"],
    "ModSecurity": ["mod_security", "modsecurity"],
}

SERVER_PATTERNS = [
    (r"[Ss]erver:\s*(Apache[^\r\n]*)",       "Apache"),
    (r"[Ss]erver:\s*(nginx[^\r\n]*)",        "Nginx"),
    (r"[Ss]erver:\s*(Microsoft-IIS[^\r\n]*)", "IIS"),
    (r"[Ss]erver:\s*(LiteSpeed[^\r\n]*)",    "LiteSpeed"),
    (r"[Ss]erver:\s*(Apache-Coyote[^\r\n]*)", "Tomcat"),
    (r"[Ss]erver:\s*(Tomcat[^\r\n]*)",       "Tomcat"),
    (r"[Ss]erver:\s*(Jetty[^\r\n]*)",        "Jetty"),
    (r"[Ss]erver:\s*(OpenResty[^\r\n]*)",    "OpenResty"),
    (r"[Ss]erver:\s*(GWS[^\r\n]*)",          "Google"),
    (r"[Ss]erver:\s*(lighttpd[^\r\n]*)",     "lighttpd"),
]

KNOWN_CRITICAL_CVES = {
    "CVE-2021-44228", "CVE-2021-34473", "CVE-2021-26855",
    "CVE-2021-27065", "CVE-2023-46604", "CVE-2024-21887",
    "CVE-2023-4966",  "CVE-2021-40438", "CVE-2022-1388",
    "CVE-2023-22515", "CVE-2020-6287",  "CVE-2020-14882",
    "CVE-2022-26134", "CVE-2023-23397", "CVE-2024-3400",
    "CVE-2021-22005", "CVE-2022-47966", "CVE-2023-34362",
    "CVE-2023-27350", "CVE-2022-41082", "CVE-2022-0540",
}

# Favicon hashes for known products
FAVICON_PRODUCT_MAP = {
    -335242539:   "Cobalt Strike C2",
     116323821:   "Grafana",
    -1028703694:  "Fortinet/FortiGate",
     81586312:    "Jenkins",
     1621371862:  "VMware vSphere",
    -1286589462:  "Oracle WebLogic",
    -338745917:   "SAP Web GUI",
    -1659512841:  "Kibana",
     1722105798:  "phpMyAdmin",
     541088007:   "Jupyter Notebook",
     442749392:   "Outlook Web App",
     854992623:   "Harbor Registry",
    -1401658736:  "Rancher",
     893284639:   "Havoc C2",
    -127886975:   "Metasploit",
     1278323681:  "GitLab",
     542093262:   "Traefik",
    -471426521:   "Webmin",
    -1524558921:  "Netdata",
}


# ═══════════════════════════════════════════════════════════════════════
# TERMINAL COLORS & LOGGING
# ═══════════════════════════════════════════════════════════════════════
class C:
    H  = '\033[95m'; B  = '\033[94m'; CY = '\033[96m'; G  = '\033[92m'
    Y  = '\033[93m'; R  = '\033[91m'; BD = '\033[1m';  DM = '\033[2m';  RS = '\033[0m'

ICONS = {
    "info":  f"{C.B}[i]{C.RS}", "ok":    f"{C.G}[+]{C.RS}",
    "warn":  f"{C.Y}[!]{C.RS}", "err":   f"{C.R}[-]{C.RS}",
    "find":  f"{C.G}[*]{C.RS}", "scan":  f"{C.CY}[>]{C.RS}",
    "chain": f"{C.H}[~]{C.RS}", "dns":   f"{C.B}[D]{C.RS}",
    "crt":   f"{C.CY}[C]{C.RS}","asn":   f"{C.Y}[A]{C.RS}",
    "fav":   f"{C.H}[F]{C.RS}",
}

def log(level, msg):
    print(f"  {ICONS.get(level, '[?]')} {msg}")

def log_phase(title):
    print(f"\n  {C.BD}{'─'*50}{C.RS}")
    print(f"  {C.BD}{C.CY}  {title}{C.RS}")
    print(f"  {C.BD}{'─'*50}{C.RS}\n")

def pbar(cur, tot, prefix="", width=40):
    p = cur / tot if tot > 0 else 0
    filled = int(width * p)
    bar = f"{C.G}{'█' * filled}{C.DM}{'░' * (width - filled)}{C.RS}"
    sys.stdout.write(f"\r  [{bar}] {p*100:.0f}% {prefix[:45]}")
    sys.stdout.flush()
    if cur == tot:
        print()

def banner():
    print(f"""{C.CY}
  ╔══════════════════════════════════════════════════════════════════╗
  ║        ShodanX v{VERSION} — Enterprise Red Team Intelligence Suite  ║
  ╚══════════════════════════════════════════════════════════════════╝{C.RS}
""")


# ═══════════════════════════════════════════════════════════════════════
# TARGET DISCOVERY — Domain/Org name resolution
# ═══════════════════════════════════════════════════════════════════════
class TargetDiscovery:
    STOPWORDS = {"of","the","and","for","in","on","at","to","a","an",
                 "ltd","limited","inc","corp","pvt","private","bank","co"}

    def __init__(self, org_name, domain=None):
        self.org_name = org_name
        self.domain   = domain
        self.clean    = re.sub(r'[^a-zA-Z0-9\s]', '', org_name).strip()
        self.words    = self.clean.lower().split()

    def base_names(self):
        names = set()
        words = [w for w in self.words if w not in self.STOPWORDS]
        if not words:
            words = self.words
        names.add("".join(words))
        names.add("-".join(words))
        if len(words) >= 2:
            names.add(words[0] + words[-1])
            names.add(words[0])
        if self.domain:
            base = self.domain.split(".")[0]
            names.add(base)
        return {n for n in names if len(n) >= 4}

    def relevance_patterns(self):
        pats = set(self.base_names())
        pats.add(self.org_name.lower())
        if self.domain:
            pats.add(self.domain.lower())
            pats.add(self.domain.split(".")[0].lower())
        return pats

    def shodan_queries(self, mode="balanced"):
        q = []
        bases = sorted(self.base_names())
        # Always include org search
        q.append({"type": "org", "query": f'org:"{self.org_name}"',
                  "label": f"Org: {self.org_name}"})
        # SSL cert domain search
        if self.domain:
            q.append({"type": "ssl", "query": f'ssl.cert.subject.cn:"*.{self.domain}"',
                      "label": f"SSL: *.{self.domain}"})
            q.append({"type": "ssl", "query": f'ssl.cert.subject.o:"{self.org_name}"',
                      "label": f"SSL-Org: {self.org_name}"})

        if mode == "quick":
            for b in bases[:2]:
                q.append({"type": "hostname", "query": f"hostname:{b}",
                          "label": f"Host: {b}"})
        elif mode == "balanced":
            for b in bases:
                q.append({"type": "hostname", "query": f"hostname:{b}",
                          "label": f"Host: {b}"})
            for b in bases[:3]:
                q.append({"type": "ssl", "query": f'ssl:"{b}"',
                          "label": f"SSL-kw: {b}"})
        elif mode == "deep":
            for b in bases:
                q.append({"type": "hostname", "query": f"hostname:{b}",
                          "label": f"Host: {b}"})
                q.append({"type": "ssl", "query": f'ssl:"{b}"',
                          "label": f"SSL-kw: {b}"})
            q.append({"type": "title", "query": f'http.title:"{self.org_name}"',
                      "label": f"Title: {self.org_name}"})
            if self.domain:
                q.append({"type": "ssl",
                          "query": f'ssl.cert.subject.o:"{self.org_name}"',
                          "label": f"Cert-Org: {self.org_name}"})
        return q

    def guess_domains(self):
        """Generate likely primary domains from org name."""
        if self.domain:
            return [self.domain]
        domains = []
        bases = sorted(self.base_names())
        for b in bases[:4]:
            for tld in [".com", ".in", ".co.in", ".org", ".net"]:
                domains.append(b + tld)
        return domains


# ═══════════════════════════════════════════════════════════════════════
# RELEVANCE FILTER
# ═══════════════════════════════════════════════════════════════════════
class RelevanceFilter:
    def __init__(self, org_name, patterns):
        self.org_name  = org_name.lower()
        self.patterns  = patterns
        self.kw        = set(re.sub(r'[^a-z0-9\s]', '', self.org_name).split()) - \
                         TargetDiscovery.STOPWORDS

    def is_relevant(self, match, query_type):
        if query_type == "org":
            return True
        text_fields = (
            " ".join(match.get("hostnames", [])) + " " +
            " ".join(match.get("domains", [])) + " " +
            (match.get("org") or "") + " " +
            str(match.get("ssl", {}).get("cert", {}).get("subject", "")) + " " +
            self._get_san_text(match)
        ).lower()
        return any(p in text_fields for p in self.patterns)

    def _get_san_text(self, match):
        try:
            exts = match.get("ssl", {}).get("cert", {}).get("extensions", [])
            return " ".join(str(e.get("data","")) for e in (exts or []) if isinstance(e, dict))
        except Exception:
            return ""


# ═══════════════════════════════════════════════════════════════════════
# TECH FINGERPRINTER
# ═══════════════════════════════════════════════════════════════════════
class TechFingerprinter:
    @staticmethod
    def detect_waf(banner):
        bl = banner.lower()
        return [waf for waf, sigs in WAF_SIGNATURES.items() if any(s in bl for s in sigs)]

    @staticmethod
    def detect_server(banner):
        for pat, _ in SERVER_PATTERNS:
            m = re.search(pat, banner)
            if m:
                return m.group(1).strip()[:80]
        return None

    @staticmethod
    def detect_tech(banner):
        bl = banner.lower()
        techs = []
        m = re.search(r'x-powered-by:\s*([^\r\n]+)', bl, re.I)
        if m:
            techs.append(m.group(1).strip())
        if "x-aspnet-version" in bl:
            techs.append("ASP.NET")
        if "wp-content" in bl or "wordpress" in bl:
            techs.append("WordPress")
        if "drupal" in bl:
            techs.append("Drupal")
        if "joomla" in bl:
            techs.append("Joomla")
        if "laravel" in bl:
            techs.append("Laravel")
        if "django" in bl:
            techs.append("Django")
        if "react" in bl or "next.js" in bl:
            techs.append("React/Next.js")
        if "vue" in bl:
            techs.append("Vue.js")
        if "confluence" in bl:
            techs.append("Confluence")
        if "jira" in bl:
            techs.append("Jira")
        if "jenkins" in bl:
            techs.append("Jenkins")
        if "grafana" in bl:
            techs.append("Grafana")
        if "phpmyadmin" in bl:
            techs.append("phpMyAdmin")
        return list(dict.fromkeys(techs))  # deduplicate preserving order

    @staticmethod
    def compute_favicon_hash(url, timeout=5):
        """Compute MurmurHash3 of favicon for Shodan matching."""
        if not HAS_MMH3:
            return None
        import base64
        try:
            r = requests.get(url, timeout=timeout, verify=False,
                             allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0"})
            if r.status_code != 200 or not r.content:
                return None
            encoded = base64.encodebytes(r.content)
            return mmh3.hash(encoded)
        except Exception:
            return None

    @staticmethod
    def identify_favicon(hash_val):
        return FAVICON_PRODUCT_MAP.get(hash_val)


# ═══════════════════════════════════════════════════════════════════════
# CVE ANALYZER
# ═══════════════════════════════════════════════════════════════════════
class CVEAnalyzer:
    @staticmethod
    def classify(vulns):
        empty = {"critical": [], "high": [], "medium": [], "low": [], "total": 0}
        if not vulns:
            return empty
        cve_list = list(vulns.keys()) if isinstance(vulns, dict) else list(vulns)
        result = {"critical": [], "high": [], "medium": [], "low": [], "total": len(cve_list)}
        for cve in cve_list:
            cu = cve.upper().replace("CVE-", "CVE-")
            if cu in KNOWN_CRITICAL_CVES:
                result["critical"].append(cve)
            elif any(yr in cve for yr in ["2024", "2023", "2022"]):
                result["high"].append(cve)
            elif any(yr in cve for yr in ["2021", "2020"]):
                result["medium"].append(cve)
            else:
                result["low"].append(cve)
        return result

    @staticmethod
    def score_cves(classified):
        score = 0
        score += len(classified["critical"]) * 30
        score += len(classified["high"])     * 15
        score += len(classified["medium"])   * 5
        score += len(classified["low"])      * 1
        return min(score, 60)


# ═══════════════════════════════════════════════════════════════════════
# MODULE 1: CRT.SH — Certificate Transparency Recon
# ═══════════════════════════════════════════════════════════════════════
class CRTShRecon:
    def __init__(self, session):
        self.session = session

    def query(self, domain):
        """Query crt.sh for all subdomains of a domain."""
        url = CRTSH_URL.format(domain=urllib.parse.quote(domain))
        try:
            r = self.session.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code != 200:
                return set(), set()
            entries = r.json()
            subdomains = set()
            domains    = set()
            for e in entries:
                for name in (e.get("name_value","") + "\n" + e.get("common_name","")).split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name and "." in name and not name.startswith("-"):
                        subdomains.add(name)
                        # extract root domain
                        parts = name.split(".")
                        if len(parts) >= 2:
                            domains.add(".".join(parts[-2:]))
            return subdomains, domains
        except Exception as e:
            return set(), set()

    def query_org(self, org_name):
        """Query crt.sh by organization name in cert subject."""
        url = f"https://crt.sh/?O={urllib.parse.quote(org_name)}&output=json"
        try:
            r = self.session.get(url, timeout=REQUEST_TIMEOUT)
            if r.status_code != 200:
                return set()
            entries = r.json()
            domains = set()
            for e in entries:
                for name in (e.get("name_value","") + "\n" + e.get("common_name","")).split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name and "." in name:
                        domains.add(name)
            return domains
        except Exception:
            return set()


# ═══════════════════════════════════════════════════════════════════════
# MODULE 2: HACKERTARGET — Passive DNS & Subdomain Recon
# ═══════════════════════════════════════════════════════════════════════
class HackerTargetRecon:
    def __init__(self, session):
        self.session = session

    def hostsearch(self, domain):
        """Find subdomains via HackerTarget API (free, no key)."""
        try:
            r = self.session.get(HT_HOSTSEARCH_URL.format(domain=domain),
                                 timeout=REQUEST_TIMEOUT)
            if r.status_code != 200 or "error" in r.text.lower()[:50]:
                return set()
            results = set()
            for line in r.text.strip().split("\n"):
                parts = line.split(",")
                if len(parts) >= 1:
                    host = parts[0].strip().lower()
                    if host and "." in host:
                        results.add(host)
            return results
        except Exception:
            return set()

    def reverse_ip(self, ip):
        """Find other domains hosted on the same IP."""
        try:
            r = self.session.get(HT_REVERSEIP_URL.format(ip=ip),
                                 timeout=REQUEST_TIMEOUT)
            if r.status_code != 200 or "error" in r.text.lower()[:50]:
                return set()
            return {line.strip().lower() for line in r.text.strip().split("\n")
                    if line.strip() and "." in line.strip()}
        except Exception:
            return set()


# ═══════════════════════════════════════════════════════════════════════
# MODULE 3: DNS RESOLVER — Mass parallel resolution
# ═══════════════════════════════════════════════════════════════════════
class DNSResolver:
    def __init__(self):
        self.socket_timeout = DNS_TIMEOUT

    def resolve_one(self, hostname):
        """Resolve a single hostname to IP(s)."""
        try:
            results = socket.getaddrinfo(hostname, None, socket.AF_INET)
            ips = list({r[4][0] for r in results})
            return hostname, ips
        except Exception:
            return hostname, []

    def resolve_bulk(self, hostnames, workers=MAX_DNS_WORKERS):
        """Resolve a list of hostnames in parallel."""
        resolved = {}
        hostnames = list(set(hostnames))
        if not hostnames:
            return resolved
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(self.resolve_one, h): h for h in hostnames}
            done = 0
            for f in as_completed(futures):
                done += 1
                pbar(done, len(hostnames), "Resolving DNS...")
                host, ips = f.result()
                if ips:
                    resolved[host] = ips
        return resolved

    def reverse_lookup(self, ip):
        """PTR record for an IP."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════════════
# MODULE 4: INTERNETDB ENRICHER — Free Shodan data (no credits)
# ═══════════════════════════════════════════════════════════════════════
class InternetDBEnricher:
    def __init__(self, session):
        self.session = session

    def lookup(self, ip):
        """Fetch free Shodan InternetDB data for an IP."""
        try:
            r = self.session.get(INTERNETDB_URL.format(ip=ip), timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                return r.json()
            return None
        except Exception:
            return None

    def bulk_lookup(self, ips, workers=MAX_ENRICH_WORKERS):
        """Enrich a list of IPs with InternetDB data."""
        results = {}
        ips = list(set(ips))
        if not ips:
            return results
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(self.lookup, ip): ip for ip in ips}
            done = 0
            for f in as_completed(futures):
                done += 1
                pbar(done, len(ips), "InternetDB enrichment...")
                ip = futures[f]
                data = f.result()
                if data:
                    results[ip] = data
        return results


# ═══════════════════════════════════════════════════════════════════════
# MODULE 5: ASN ENRICHER — BGP/ASN data
# ═══════════════════════════════════════════════════════════════════════
class ASNEnricher:
    def __init__(self, session):
        self.session = session
        self._cache = {}

    def lookup(self, ip):
        if ip in self._cache:
            return self._cache[ip]
        try:
            r = self.session.get(BGP_VIEW_URL.format(ip=ip), timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                d = r.json()
                data = d.get("data", {})
                asns = data.get("rir_allocation", {})
                prefixes = data.get("prefixes", [])
                asn_info = {}
                if prefixes:
                    p = prefixes[0]
                    asn_info = {
                        "asn": p.get("asn", {}).get("asn"),
                        "name": p.get("asn", {}).get("name"),
                        "description": p.get("asn", {}).get("description"),
                        "prefix": p.get("prefix"),
                        "country": p.get("country_code"),
                    }
                self._cache[ip] = asn_info
                return asn_info
        except Exception:
            pass
        self._cache[ip] = {}
        return {}


# ═══════════════════════════════════════════════════════════════════════
# MODULE 6: FAVICON HASHER — Parallel favicon fingerprinting
# ═══════════════════════════════════════════════════════════════════════
class FaviconHasher:
    def __init__(self, session):
        self.session = session

    def hash_url(self, ip, port, use_https):
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{ip}:{port}/favicon.ico"
        h = TechFingerprinter.compute_favicon_hash(url)
        if h is not None:
            product = TechFingerprinter.identify_favicon(h)
            return ip, port, h, product
        return ip, port, None, None

    def bulk_hash(self, targets, workers=MAX_FAVICON_WORKERS):
        """targets: list of (ip, port, use_https)"""
        if not HAS_MMH3 or not targets:
            return {}
        results = {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(self.hash_url, ip, port, https): (ip, port)
                       for ip, port, https in targets}
            done = 0
            for f in as_completed(futures):
                done += 1
                pbar(done, len(targets), "Hashing favicons...")
                _, _, h, product = f.result()
                ip, port = futures[f]
                if h is not None:
                    results[(ip, port)] = {"hash": h, "product": product}
        return results


# ═══════════════════════════════════════════════════════════════════════
# SHODAN ENGINE
# ═══════════════════════════════════════════════════════════════════════
class ShodanEngine:
    def __init__(self, api_key, rel_filter, max_pages=2):
        self.api     = shodan.Shodan(api_key)
        self.filter  = rel_filter
        self.max_pages = max_pages
        self.results   = []
        self.seen      = set()
        self.rejected  = 0
        self.domains   = set()
        self.sans      = set()
        self.errors    = []
        self.stats     = []

    def run_facets(self, query_obj):
        """Run a facet query — free, returns statistical breakdown."""
        # Accept ShodanQuery object or dict
        if HAS_QI and isinstance(query_obj, ShodanQueryObj):
            q      = query_obj.query
            label  = query_obj.label
            facets = query_obj.facets or ["port:10", "product:10", "country:5", "vuln:10"]
        else:
            q      = query_obj.get("query", "")
            label  = query_obj.get("label", "facet")
            facets = query_obj.get("facets", ["port:10", "product:10", "country:5", "vuln:10"])

        # Parse facet spec: "port:20" → ("port", 20)
        parsed_facets = []
        for f in facets:
            parts = f.split(":")
            name  = parts[0]
            size  = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
            parsed_facets.append((name, size))

        try:
            result = self.api.search(q, page=1, facets=parsed_facets)
            facet_data = {}
            for fname, fsize in parsed_facets:
                items = result.get("facets", {}).get(fname, [])
                facet_data[fname] = {item["value"]: item["count"] for item in items}
            self.facet_results = getattr(self, "facet_results", {})
            self.facet_results[label] = {"query": q, "total": result.get("total", 0), "facets": facet_data}
            return facet_data
        except Exception as e:
            self.errors.append({"query": q, "error": f"Facet error: {e}"})
            return {}

    def search(self, query_obj):
        # Accept both ShodanQuery objects and legacy dicts
        if HAS_QI and isinstance(query_obj, ShodanQueryObj):
            q     = query_obj.query
            label = query_obj.label
            qtype = query_obj.qtype
        else:
            q     = query_obj["query"]
            label = query_obj["label"]
            qtype = query_obj.get("type", "org")
        added = 0
        try:
            for page in range(1, self.max_pages + 1):
                res     = self.api.search(q, page=page)
                total   = res["total"]
                matches = res["matches"]
                if not matches:
                    break
                for m in matches:
                    key = (m.get("ip_str"), m.get("port"))
                    if key in self.seen:
                        continue
                    self.seen.add(key)
                    if not self.filter.is_relevant(m, qtype):
                        self.rejected += 1
                        continue
                    enriched = self._enrich(m, query_obj)
                    self.results.append(enriched)
                    added += 1
                    for d in m.get("domains", []):
                        self.domains.add(d.lower())
                    self._extract_sans(m)
                if page * 100 >= total:
                    break
                if page < self.max_pages:
                    time.sleep(SHODAN_RATE_SLEEP)
            self.stats.append({"query": q, "label": label, "accepted": added,
                               "rejected": self.rejected})
            return total, added
        except shodan.APIError as e:
            self.errors.append({"query": q, "error": str(e)})
            self.stats.append({"query": q, "label": label, "accepted": 0,
                               "error": str(e)})
            return 0, 0

    def _extract_sans(self, m):
        try:
            for ext in (m.get("ssl",{}).get("cert",{}).get("extensions",[]) or []):
                if isinstance(ext, dict) and "subjectAltName" in str(ext.get("name","")):
                    for san in re.findall(r'DNS:([^\s,]+)', str(ext.get("data",""))):
                        self.sans.add(san.lower())
        except Exception:
            pass

    def _enrich(self, m, qobj):
        port = m.get("port", 0)
        data = m.get("data", "")
        vulns = m.get("vulns", {})
        loc  = m.get("location", {})
        svc  = self._svc_type(port, data, m)
        wafs = TechFingerprinter.detect_waf(data)
        svr  = TechFingerprinter.detect_server(data)
        techs = TechFingerprinter.detect_tech(data)
        cves = CVEAnalyzer.classify(vulns)

        # Risk scoring
        score, factors = 0, []
        if port in CRITICAL_PORTS:
            score += 40
            factors.append(f"Critical port {port} ({HIGH_RISK_PORTS.get(port,'?')})")
        elif port in HIGH_RISK_PORTS:
            score += 20
            factors.append(f"Sensitive port {port} ({HIGH_RISK_PORTS.get(port,'?')})")
        cve_score = CVEAnalyzer.score_cves(cves)
        if cve_score > 0:
            score += cve_score
            factors.append(f"{cves['total']} CVE(s) — {cves['critical'][:2]}" if cves["critical"] else f"{cves['total']} CVE(s)")
        if cves["critical"]:
            factors.append(f"CRITICAL: {', '.join(cves['critical'][:3])}")
        if "webvpn" in data.lower() or "ssl-vpn" in data.lower():
            score += 15; factors.append("VPN gateway exposed")
        if svr:
            score += 5
        if not wafs:
            score += 5; factors.append("No WAF detected")
        score = min(score, 100)
        level = ("CRITICAL" if score >= 75 else
                 "HIGH"     if score >= 50 else
                 "MEDIUM"   if score >= 25 else "LOW")

        ssl_info = None
        ssl_data = m.get("ssl", {})
        if ssl_data:
            cert = ssl_data.get("cert", {})
            ssl_info = {
                "subject":  cert.get("subject", {}),
                "issuer":   cert.get("issuer", {}),
                "expires":  cert.get("expires"),
                "expired":  ssl_data.get("cert", {}).get("expired", False),
            }

        return {
            "ip": m.get("ip_str"), "port": port,
            "transport": m.get("transport","tcp"),
            "hostnames": m.get("hostnames",[]),
            "domains":   m.get("domains",[]),
            "org":       m.get("org"), "asn": m.get("asn"),
            "isp":       m.get("isp"), "os":  m.get("os"),
            "product":   m.get("product"), "version": m.get("version"),
            "country":   loc.get("country_name","Unknown"),
            "city":      loc.get("city","Unknown"),
            "lat":       loc.get("latitude"), "lon": loc.get("longitude"),
            "service_type": svc,
            "wafs": wafs, "server": svr, "technologies": techs,
            "cves": cves, "ssl": ssl_info,
            "risk_score": score, "risk_level": level, "risk_factors": factors,
            "banner_snippet": data[:300] if data else "",
            "timestamp": m.get("timestamp"),
            "source":    qobj.label if hasattr(qobj, "label") else qobj.get("label",""),
            "source_module": "shodan",
            # enrichment fields (filled later)
            "asn_info":  {}, "favicon_hash": None, "favicon_product": None,
            "internetdb": {},
        }

    def _svc_type(self, port, data, m):
        dl   = data.lower()
        prod = (m.get("product") or "").lower()
        if port in (80,8080,8000,8888): return "HTTP"
        if port in (443,8443,4443):
            if "webvpn" in dl or "ssl-vpn" in dl: return "VPN"
            if "exchange" in dl or "owa" in dl:    return "Email"
            return "HTTPS"
        if port == 22:   return "SSH"
        if port == 21:   return "FTP"
        if port in (25,587): return "SMTP"
        if port == 161:  return "SNMP"
        if port == 3389: return "RDP"
        if port == 5900: return "VNC"
        if port in (3306,1433,1521,5432,27017,6379,9200,5984,11211): return "Database"
        if port == 53:   return "DNS"
        if port in (389,636): return "LDAP"
        if port in (139,445): return "SMB"
        if port == 2375: return "Docker"
        if port == 6443: return "Kubernetes"
        if port == 502:  return "ICS/SCADA"
        if port == 873:  return "Rsync"
        return "Other"


# ═══════════════════════════════════════════════════════════════════════
# RECON ORCHESTRATOR — Chains all modules together
# ═══════════════════════════════════════════════════════════════════════
class ReconOrchestrator:
    def __init__(self, api_key, org_name, domain=None, mode="balanced"):
        self.api_key  = api_key
        self.org_name = org_name
        self.domain   = domain
        self.mode     = mode
        self.session  = self._make_session()
        self.disc     = TargetDiscovery(org_name, domain)
        self.patterns = self.disc.relevance_patterns()
        self.rel_filter = RelevanceFilter(org_name, self.patterns)

        max_pages = {"quick": 1, "balanced": 2, "deep": 5}.get(mode, 2)
        self.shodan_engine = ShodanEngine(api_key, self.rel_filter, max_pages)
        self.crtsh     = CRTShRecon(self.session)
        self.ht        = HackerTargetRecon(self.session)
        self.dns       = DNSResolver()
        self.idb       = InternetDBEnricher(self.session)
        self.asn_enr   = ASNEnricher(self.session)
        self.fav_hasher = FaviconHasher(self.session)

        # Accumulated intelligence
        self.crtsh_domains   = set()
        self.crtsh_subdomains = set()
        self.ht_subdomains   = set()
        self.resolved_ips    = {}   # hostname -> [ips]
        self.idb_data        = {}   # ip -> InternetDB data
        self.asn_data        = {}   # ip -> ASN info
        self.favicon_data    = {}   # (ip,port) -> {hash, product}
        self.dns_assets      = []   # assets built from DNS resolution
        self.t0 = time.time()

    def _make_session(self):
        s = requests.Session()
        s.headers.update({"User-Agent": "ShodanX/4.0 Enterprise Recon"})
        s.verify = False
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass
        return s

    # ─────────────────────────────────────────────
    # PHASE 1: Passive DNS / Subdomain Discovery
    # ─────────────────────────────────────────────
    def phase1_passive_recon(self):
        log_phase("PHASE 1 — Passive Subdomain & Certificate Recon")

        domains_to_probe = self.disc.guess_domains()
        if self.domain:
            domains_to_probe = [self.domain] + [d for d in domains_to_probe if d != self.domain]

        log("crt", f"Querying crt.sh for {len(domains_to_probe)} domain(s)...")
        for d in domains_to_probe[:5]:
            subs, roots = self.crtsh.query(d)
            self.crtsh_subdomains.update(subs)
            self.crtsh_domains.update(roots)
            log("ok",  f"crt.sh [{d}] → {len(subs)} subdomains, {len(roots)} domains")
            time.sleep(0.5)

        # Query by org name in cert subject
        org_certs = self.crtsh.query_org(self.org_name)
        self.crtsh_subdomains.update(org_certs)
        log("ok", f"crt.sh [org search] → {len(org_certs)} additional names")

        log("chain", f"Querying HackerTarget for {len(domains_to_probe)} domain(s)...")
        for d in domains_to_probe[:3]:
            ht_subs = self.ht.hostsearch(d)
            self.ht_subdomains.update(ht_subs)
            log("ok",  f"HackerTarget [{d}] → {len(ht_subs)} subdomains")
            time.sleep(0.5)

        total_subs = self.crtsh_subdomains | self.ht_subdomains
        log("ok", f"Total unique subdomains discovered: {C.BD}{len(total_subs)}{C.RS}")
        return total_subs

    # ─────────────────────────────────────────────
    # PHASE 2: DNS Resolution
    # ─────────────────────────────────────────────
    def phase2_dns_resolution(self, subdomains):
        log_phase("PHASE 2 — Mass DNS Resolution")
        log("dns", f"Resolving {len(subdomains)} hostnames in parallel ({MAX_DNS_WORKERS} workers)...")
        self.resolved_ips = self.dns.resolve_bulk(list(subdomains))
        resolved_count = sum(1 for v in self.resolved_ips.values() if v)
        log("ok", f"Resolved: {C.G}{resolved_count}{C.RS} / {len(subdomains)} hostnames → IPs")

        # Build asset records from DNS results
        all_resolved_ips = set()
        for host, ips in self.resolved_ips.items():
            for ip in ips:
                all_resolved_ips.add(ip)
                # Create a lightweight asset record
                self.dns_assets.append({
                    "ip": ip, "hostname_source": host,
                    "port": None, "source_module": "dns"
                })

        log("ok", f"Unique IPs from DNS: {C.BD}{len(all_resolved_ips)}{C.RS}")
        return all_resolved_ips

    # ─────────────────────────────────────────────
    # PHASE 3: Shodan API Scan — powered by QueryIntelligence
    # ─────────────────────────────────────────────
    def phase3_shodan_scan(self, preselected_queries=None):
        log_phase("PHASE 3 — Shodan Intelligence Gathering")

        if preselected_queries is not None:
            # Queries already chosen by QueryPlanner in main()
            queries = preselected_queries
            log("scan", f"Using {len(queries)} pre-selected queries from QueryIntelligence")
        elif HAS_QI:
            # Auto-generate with QueryIntelligence, apply mode threshold
            log("scan", f"QueryIntelligence generating queries for '{self.org_name}'...")
            qi = QueryIntelligence(self.org_name, self.domain)
            all_queries = qi.generate()
            threshold = {"quick": 80, "balanced": 65, "deep": 50}.get(self.mode, 65)
            queries = [q for q in all_queries if q.confidence >= threshold or q.is_facet]
            log("ok", f"Generated {len(queries)} queries (confidence ≥ {threshold}%, "
                       f"mode: {self.mode.upper()})")
        else:
            # Fallback to legacy TargetDiscovery
            log("warn", "query_intelligence.py not found — using legacy query generator")
            queries = self.disc.shodan_queries(self.mode)

        # Separate facets (free) from paid queries
        facet_queries = [q for q in queries if (hasattr(q, 'is_facet') and q.is_facet)]
        paid_queries  = [q for q in queries if not (hasattr(q, 'is_facet') and q.is_facet)]

        # ── Run facets first — free intelligence ──
        if facet_queries:
            log("info", f"Running {len(facet_queries)} facet queries (FREE — 0 credits)...")
            self.shodan_engine.facet_results = {}
            for fq in facet_queries:
                facet_data = self.shodan_engine.run_facets(fq)
                label = fq.label if hasattr(fq, 'label') else str(fq)
                if facet_data:
                    # Display top findings from facets inline
                    for fname, fvals in facet_data.items():
                        if fname == "vuln" and fvals:
                            top_cves = list(fvals.items())[:5]
                            log("find", f"Facet CVEs: " +
                                ", ".join(f"{C.R}{c}{C.RS}({n})" for c, n in top_cves))
                        elif fname == "port" and fvals:
                            top_ports = list(fvals.items())[:5]
                            log("find", f"Facet top ports: " +
                                ", ".join(f"{C.CY}{p}{C.RS}({n})" for p, n in top_ports))
                time.sleep(SHODAN_RATE_SLEEP)

        # ── Run paid search queries ──
        total_credits = len(paid_queries)
        log("scan", f"Running {total_credits} paid queries ({total_credits} credit(s) estimated)...")

        for i, q in enumerate(paid_queries):
            label = q.label if hasattr(q, 'label') else q.get("label", str(q))
            pbar(i, len(paid_queries), label[:50])
            total, new = self.shodan_engine.search(q)
            if new > 0:
                log("find", f"{label[:50]} → {C.G}{new} accepted{C.RS} / {total} total")
            time.sleep(SHODAN_RATE_SLEEP)

        pbar(len(paid_queries), len(paid_queries), "Shodan scan complete")
        log("ok", f"Shodan assets: {C.BD}{len(self.shodan_engine.results)}{C.RS} | "
                  f"Rejected FPs: {C.Y}{self.shodan_engine.rejected}{C.RS}")

    # ─────────────────────────────────────────────
    # PHASE 4: InternetDB Enrichment (free)
    # ─────────────────────────────────────────────
    def phase4_internetdb_enrich(self, extra_ips=None):
        log_phase("PHASE 4 — InternetDB Enrichment (Free Shodan Data)")
        shodan_ips = {r["ip"] for r in self.shodan_engine.results}
        dns_ips    = {a["ip"] for a in self.dns_assets}
        all_ips    = shodan_ips | dns_ips | (extra_ips or set())

        log("chain", f"Enriching {len(all_ips)} unique IPs via InternetDB...")
        self.idb_data = self.idb.bulk_lookup(list(all_ips))
        log("ok", f"InternetDB data retrieved for {C.G}{len(self.idb_data)}{C.RS} IPs")

        # Apply InternetDB data to Shodan results
        for r in self.shodan_engine.results:
            idb = self.idb_data.get(r["ip"], {})
            if idb:
                r["internetdb"] = {
                    "ports":  idb.get("ports", []),
                    "cpes":   idb.get("cpes", []),
                    "vulns":  idb.get("vulns", []),
                    "tags":   idb.get("tags", []),
                }
                # Merge InternetDB CVEs into existing CVE analysis
                idb_vulns = idb.get("vulns", [])
                if idb_vulns:
                    extra_cves = CVEAnalyzer.classify({v: {} for v in idb_vulns})
                    for sev in ["critical","high","medium","low"]:
                        r["cves"][sev] = list(set(r["cves"][sev] + extra_cves[sev]))
                    r["cves"]["total"] = sum(len(r["cves"][s]) for s in ["critical","high","medium","low"])

    # ─────────────────────────────────────────────
    # PHASE 5: Favicon Hashing
    # ─────────────────────────────────────────────
    def phase5_favicon_hash(self):
        if not HAS_MMH3:
            log("warn", "mmh3 not installed — skipping favicon hashing. Run: pip install mmh3")
            return
        log_phase("PHASE 5 — Favicon Fingerprinting")
        targets = []
        for r in self.shodan_engine.results:
            if r["service_type"] in ("HTTP","HTTPS","VPN","Email"):
                use_https = r["service_type"] in ("HTTPS","VPN","Email") or r["port"] == 443
                targets.append((r["ip"], r["port"], use_https))

        log("fav", f"Hashing favicons for {len(targets)} HTTP/HTTPS services...")
        self.favicon_data = self.fav_hasher.bulk_hash(targets[:100])  # cap at 100
        identified = sum(1 for v in self.favicon_data.values() if v.get("product"))
        log("ok",  f"Favicon hashes computed: {len(self.favicon_data)} | "
                   f"Products identified: {C.G}{identified}{C.RS}")

        # Apply favicon data to Shodan results
        for r in self.shodan_engine.results:
            fav = self.favicon_data.get((r["ip"], r["port"]))
            if fav:
                r["favicon_hash"]    = fav.get("hash")
                r["favicon_product"] = fav.get("product")
                if fav.get("product") and fav["product"] not in (r.get("technologies") or []):
                    if r.get("technologies") is None:
                        r["technologies"] = []
                    r["technologies"].append(f"[Favicon] {fav['product']}")
                # Flag threat actor tooling
                if fav.get("product") in ("Cobalt Strike C2","Metasploit","Havoc C2"):
                    r["risk_score"] = min(r["risk_score"] + 30, 100)
                    r["risk_level"] = "CRITICAL"
                    r["risk_factors"].append(f"⚠ C2 Framework Detected: {fav['product']}")

    # ─────────────────────────────────────────────
    # RUN ALL PHASES
    # ─────────────────────────────────────────────
    def run(self, preselected_queries=None):
        # Phase 1 — Passive
        subdomains = self.phase1_passive_recon()

        # Phase 2 — DNS
        dns_ips = self.phase2_dns_resolution(subdomains)

        # Phase 3 — Shodan (uses QueryIntelligence)
        self.phase3_shodan_scan(preselected_queries=preselected_queries)

        # Phase 4 — InternetDB
        self.phase4_internetdb_enrich(extra_ips=dns_ips)

        # Phase 5 — Favicon
        self.phase5_favicon_hash()

        return self._build_report()

    # ─────────────────────────────────────────────
    # BUILD UNIFIED REPORT DATA
    # ─────────────────────────────────────────────
    def _build_report(self):
        assets   = self.shodan_engine.results
        port_d   = Counter(r["port"] for r in assets)
        svc_d    = Counter(r["service_type"] for r in assets)
        risk_d   = Counter(r["risk_level"] for r in assets)
        geo_d    = Counter(r["country"] for r in assets)
        isp_d    = Counter(r["isp"] or "Unknown" for r in assets)
        uips     = {r["ip"] for r in assets}
        uhosts   = {h for r in assets for h in r["hostnames"]}
        waf_set  = {w for r in assets for w in r["wafs"]}
        svr_set  = {r["server"] for r in assets if r["server"]}
        tech_set = {t for r in assets for t in (r.get("technologies") or [])}
        all_cves = {"critical":[],"high":[],"medium":[],"low":[]}
        for r in assets:
            for sev in all_cves:
                all_cves[sev].extend(r["cves"][sev])

        crit = risk_d.get("CRITICAL",0)
        high = risk_d.get("HIGH",0)
        if crit >= 3:   grade = "F"
        elif crit >= 1: grade = "D"
        elif high >= 5: grade = "C"
        elif high >= 1: grade = "B"
        else:           grade = "A"

        scan_time = round(time.time() - self.t0, 1)
        all_subs  = self.crtsh_subdomains | self.ht_subdomains

        return {
            "meta": {
                "tool": "ShodanX", "version": VERSION,
                "scan_date": datetime.now(timezone.utc).isoformat(),
                "target": self.org_name,
                "domain": self.domain or "",
                "mode": self.mode, "duration_sec": scan_time,
            },
            "executive_summary": {
                "risk_grade": grade,
                "total_assets": len(assets),
                "unique_ips": len(uips),
                "unique_hostnames": len(uhosts),
                "false_positives_removed": self.shodan_engine.rejected,
                "total_cves": sum(len(v) for v in all_cves.values()),
                "critical_cves": len(all_cves["critical"]),
                "high_cves": len(all_cves["high"]),
                "risk_distribution": dict(risk_d),
            },
            "passive_recon": {
                "crtsh_subdomains": sorted(self.crtsh_subdomains),
                "ht_subdomains":    sorted(self.ht_subdomains),
                "total_subdomains": len(all_subs),
                "crtsh_domains":    sorted(self.crtsh_domains),
                "dns_resolved":     {h: ips for h, ips in self.resolved_ips.items() if ips},
                "dns_resolved_count": sum(1 for v in self.resolved_ips.values() if v),
            },
            "attack_surface": {
                "ports":    dict(port_d.most_common()),
                "services": dict(svc_d.most_common()),
                "geographic": dict(geo_d.most_common()),
                "isps": dict(isp_d.most_common(10)),
                "wafs_detected":     sorted(waf_set),
                "servers_detected":  sorted(svr_set),
                "technologies":      sorted(tech_set),
                "discovered_domains": sorted(self.shodan_engine.domains | self.crtsh_domains),
                "ssl_sans": sorted(list(self.shodan_engine.sans)[:100]),
                "favicon_identifications": [
                    {"ip": ip, "port": port, "hash": v["hash"], "product": v["product"]}
                    for (ip, port), v in self.favicon_data.items() if v.get("product")
                ],
            },
            "cve_analysis": {
                "critical": sorted(set(all_cves["critical"])),
                "high":     sorted(set(all_cves["high"])),
                "medium":   sorted(set(all_cves["medium"])),
                "low_count": len(set(all_cves["low"])),
            },
            "critical_findings": [r for r in assets if r["risk_score"] >= 50],
            "all_assets":  assets,
            "scan_log":    self.shodan_engine.stats,
            "errors":      self.shodan_engine.errors,
            "internetdb_coverage": len(self.idb_data),
        }


# ═══════════════════════════════════════════════════════════════════════
# REPORT GENERATORS
# ═══════════════════════════════════════════════════════════════════════
def save_json(report, fname):
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

def save_html(report, fname):
    from shodanx_html_template import build_html
    report["meta"]["version"] = VERSION
    html_content = build_html(report)
    with open(fname, "w", encoding="utf-8") as f:
        f.write(html_content)


# ═══════════════════════════════════════════════════════════════════════
# INTERACTIVE CLI
# ═══════════════════════════════════════════════════════════════════════
def main():
    banner()

    # ── API Key ──────────────────────────────────────
    api_key = input(f"  {C.CY}[?]{C.RS} Shodan API Key: ").strip()
    if not api_key:
        log("err", "API key required."); return
    log("info", "Validating API key...")
    try:
        info = shodan.Shodan(api_key).info()
        log("ok", f"Key valid | Plan: {C.G}{info.get('plan','?')}{C.RS} | "
                  f"Query Credits: {C.G}{info.get('query_credits',0)}{C.RS}")
    except Exception as e:
        log("err", f"Invalid API key: {e}"); return

    print()

    # ── Target ───────────────────────────────────────
    org = input(f"  {C.CY}[?]{C.RS} Target organization name: ").strip()
    if not org:
        log("err", "Organization required."); return

    domain_input = input(f"  {C.CY}[?]{C.RS} Primary domain (optional, e.g. example.com): ").strip()
    domain = domain_input if domain_input else None

    # ── Mode ─────────────────────────────────────────
    print(f"""
  {C.BD}┌─ Scan Modes ──────────────────────────────────────────┐{C.RS}
  {C.G}│ [1] Quick    {C.RS} crt.sh + 1-page Shodan (~1 min)
  {C.Y}│ [2] Balanced {C.RS} All passive + 2-page Shodan (~3 min)
  {C.R}│ [3] Deep     {C.RS} Full chain + 5-page Shodan + all modules (~10 min)
  {C.BD}└───────────────────────────────────────────────────────┘{C.RS}
""")
    mc   = input(f"  {C.CY}[?]{C.RS} Mode [1/2/3] (default 2): ").strip()
    mode = {"1":"quick","2":"balanced","3":"deep","":"balanced"}.get(mc,"balanced")

    # ── QueryIntelligence Planning ────────────────────
    preselected_queries = None
    if HAS_QI:
        print(f"\n  {C.BD}{C.H}[~]{C.RS} QueryIntelligence available — generating smart query plan...\n")
        planner = QueryPlanner(org, domain)
        preselected_queries = planner.run()
        if preselected_queries is None:
            log("warn", "No queries selected. Aborted."); return
        print()
    else:
        log("warn", "query_intelligence.py not found — using built-in query generator")
        log("info", "Place query_intelligence.py in the same folder for smart query planning")

    # ── Confirm ───────────────────────────────────────
    disc    = TargetDiscovery(org, domain)
    guessed = disc.guess_domains()
    print(f"""
  {C.BD}┌─ Scan Configuration ──────────────────────────────────┐{C.RS}
  │  Target:     {C.BD}{org}{C.RS}
  │  Domain:     {C.BD}{domain or f'auto-detect ({", ".join(guessed[:3])})'}{C.RS}
  │  Mode:       {C.BD}{mode.upper()}{C.RS}
  │  QI Queries: {C.BD}{len(preselected_queries) if preselected_queries else 'auto'}{C.RS}
  │  Modules:    {C.G}Shodan · crt.sh · HackerTarget · DNS · InternetDB · Favicon{C.RS}
  {C.BD}└───────────────────────────────────────────────────────┘{C.RS}
""")

    if input(f"  {C.CY}[?]{C.RS} Start scan? [Y/n]: ").strip().lower() == "n":
        log("warn", "Aborted."); return

    # ── Run ───────────────────────────────────────────
    orch   = ReconOrchestrator(api_key, org, domain, mode)
    report = orch.run(preselected_queries=preselected_queries)

    # ── Summary ───────────────────────────────────────
    es = report["executive_summary"]
    pr = report["passive_recon"]
    grade_color = {"A":C.G,"B":C.G,"C":C.Y,"D":C.Y,"F":C.R}.get(es["risk_grade"],C.RS)

    print(f"""
  {C.BD}╔══════════════════════════════════════════════════════════╗
  ║                    SCAN COMPLETE                         ║
  ╚══════════════════════════════════════════════════════════╝{C.RS}

  {C.BD}Risk Grade:{C.RS}  {grade_color}{C.BD}{es['risk_grade']}{C.RS}
  {C.BD}Assets:{C.RS}      {es['total_assets']} verified ({es['unique_ips']} unique IPs)
  {C.BD}Subdomains:{C.RS}  {pr['total_subdomains']} discovered | {pr['dns_resolved_count']} resolved
  {C.BD}CVEs:{C.RS}        {C.R}{es['critical_cves']} Critical{C.RS} | {C.Y}{es['high_cves']} High{C.RS} | {es['total_cves']} Total
  {C.BD}FP Removed:{C.RS}  {es['false_positives_removed']}
  {C.BD}Duration:{C.RS}    {report['meta']['duration_sec']}s
""")

    # ── Save Reports ──────────────────────────────────
    safe = re.sub(r'[^a-zA-Z0-9]', '_', org).lower()
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    jf   = f"shodanx_{safe}_{ts}.json"
    hf   = f"shodanx_{safe}_{ts}.html"

    log("info", "Generating reports...")
    save_json(report, jf)
    log("ok",   f"JSON  → {C.CY}{jf}{C.RS}")
    save_html(report, hf)
    log("ok",   f"HTML  → {C.CY}{hf}{C.RS}")

    print(f"\n  {C.G}{C.BD}Open {hf} in your browser for the full enterprise report.{C.RS}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {C.Y}Interrupted.{C.RS}\n")
"""ShodanX v4.0 — Enterprise HTML Report Template"""
import json
import html as _h

def esc(s):
    return _h.escape(str(s)) if s else ""

def build_html(data):
    meta    = data["meta"]
    es      = data["executive_summary"]
    atk     = data["attack_surface"]
    cves    = data["cve_analysis"]
    pr      = data["passive_recon"]
    assets  = data.get("all_assets", [])
    finding = data.get("critical_findings", [])
    favs    = atk.get("favicon_identifications", [])
    org     = esc(meta["target"])
    domain  = esc(meta.get("domain",""))
    mode    = meta["mode"].upper()
    date    = meta["scan_date"][:19] + " UTC"
    dur     = meta["duration_sec"]
    grade   = es["risk_grade"]
    VER     = meta.get("version","4.0.0")

    GRADE_COLOR = {"A":"#22c55e","B":"#84cc16","C":"#eab308","D":"#f97316","F":"#ef4444"}
    gc = GRADE_COLOR.get(grade,"#94a3b8")
    rd = es["risk_distribution"]

    # ── Chart Data ────────────────────────────────────────────────────
    port_items = list(atk["ports"].items())[:12]
    port_labels = json.dumps([str(k) for k, _ in port_items])
    port_vals   = json.dumps([v for _, v in port_items])

    svc_items = list(atk["services"].items())
    svc_labels = json.dumps([k for k, _ in svc_items])
    svc_vals   = json.dumps([v for _, v in svc_items])

    risk_labels = json.dumps(["CRITICAL","HIGH","MEDIUM","LOW"])
    risk_vals   = json.dumps([rd.get("CRITICAL",0),rd.get("HIGH",0),rd.get("MEDIUM",0),rd.get("LOW",0)])

    geo_items  = sorted(atk.get("geographic",{}).items(), key=lambda x: -x[1])[:10]
    geo_labels = json.dumps([k for k,_ in geo_items])
    geo_vals   = json.dumps([v for _,v in geo_items])

    # ── Asset Table Rows ──────────────────────────────────────────────
    rows = ""
    RC = {"CRITICAL":"#ef4444","HIGH":"#f97316","MEDIUM":"#eab308","LOW":"#22c55e"}
    for a in sorted(assets, key=lambda x: x["risk_score"], reverse=True):
        rc   = RC.get(a["risk_level"],"#94a3b8")
        hn   = esc(", ".join(a.get("hostnames",[])[0:1]) or "—")
        cve_t= a["cves"]["total"]
        cve_d= ""
        if a["cves"]["critical"]: cve_d = "🔴 " + esc(", ".join(a["cves"]["critical"][:2]))
        elif a["cves"]["high"]:   cve_d = "🟠 " + esc(", ".join(a["cves"]["high"][:2]))
        waf  = esc(", ".join(a.get("wafs",[]))) or "—"
        srv  = esc(a.get("server") or "—")
        fav  = esc(a.get("favicon_product") or "—")
        tech = esc(", ".join((a.get("technologies") or [])[:2]) or "—")
        facs = esc("; ".join(a.get("risk_factors",[])[:2]) or "—")
        idb_ports = ", ".join(str(p) for p in (a.get("internetdb",{}).get("ports",[]) or [])[:5])
        rows += f"""<tr class="row-{a['risk_level'].lower()}">
<td class="mono">{esc(a['ip'])}</td>
<td class="mono">{a['port']}</td>
<td><span class="svc-badge">{esc(a['service_type'])}</span></td>
<td class="hn-cell">{hn}</td>
<td><span class="risk-pill" style="background:{rc}20;color:{rc};border:1px solid {rc}40">{a['risk_level']}</span> <span class="score-muted">{a['risk_score']}</span></td>
<td class="cve-cell">{cve_t}{(' — ' + cve_d) if cve_d else ''}</td>
<td class="dim-cell">{waf}</td>
<td class="dim-cell">{srv}</td>
<td class="dim-cell">{fav}</td>
<td class="dim-cell">{tech}</td>
<td class="fac-cell" title="{facs}">{facs}</td>
</tr>"""

    # ── Finding Cards ──────────────────────────────────────────────────
    fcards = ""
    for f in finding[:20]:
        rc   = RC.get(f["risk_level"],"#eab308")
        host = f["hostnames"][0] if f["hostnames"] else f["ip"]
        fac_html = "".join(f"<li>{esc(x)}</li>" for x in f.get("risk_factors",[])[:4])
        cve_html = ""
        if f["cves"]["critical"]:
            cve_html = f'<div class="fc-cves critical">CRITICAL: {esc(", ".join(f["cves"]["critical"][:3]))}</div>'
        elif f["cves"]["high"]:
            cve_html = f'<div class="fc-cves high">HIGH: {esc(", ".join(f["cves"]["high"][:3]))}</div>'
        fav_html = ""
        if f.get("favicon_product"):
            fav_html = f'<div class="fc-fav">🎯 {esc(f["favicon_product"])}</div>'
        fcards += f"""<div class="fc" style="--rc:{rc}">
<div class="fc-header">
  <span class="fc-badge" style="background:{rc}20;color:{rc};border:1px solid {rc}50">{f['risk_level']}</span>
  <span class="fc-score">{f['risk_score']}/100</span>
</div>
<div class="fc-ip">{esc(f['ip'])}:{f['port']}</div>
<div class="fc-host">{esc(host)}</div>
<div class="fc-svc">{esc(f['service_type'])} · {esc(f.get('country',''))}</div>
{cve_html}{fav_html}
<ul class="fc-factors">{fac_html}</ul>
</div>"""

    # ── Domain Tags ───────────────────────────────────────────────────
    def tag_cloud(items, cls="dtag"):
        return " ".join(f'<span class="{cls}">{esc(d)}</span>' for d in sorted(items)[:60])

    dom_cloud  = tag_cloud(atk.get("discovered_domains",[]))
    san_cloud  = tag_cloud(atk.get("ssl_sans",[]), "dtag san")
    sub_cloud  = tag_cloud(pr.get("crtsh_subdomains",[])[:80], "dtag crt")
    ht_cloud   = tag_cloud(pr.get("ht_subdomains",[])[:50], "dtag ht")

    # ── Geo Bars ──────────────────────────────────────────────────────
    geo_rows = ""
    for c, n in geo_items:
        pct = n / max(len(assets), 1) * 100
        geo_rows += f'<div class="geo-row"><span class="geo-name">{esc(c)}</span><div class="geo-track"><div class="geo-fill" style="width:{pct:.1f}%"></div></div><span class="geo-n">{n}</span></div>'

    # ── WAF & Tech Chips ──────────────────────────────────────────────
    waf_chips = " ".join(f'<span class="chip waf-chip">{esc(w)}</span>' for w in sorted(atk.get("wafs_detected",[])))  or "None detected"
    svr_chips = " ".join(f'<span class="chip svr-chip">{esc(s)}</span>' for s in sorted(atk.get("servers_detected",[]))) or "None identified"
    tech_chips= " ".join(f'<span class="chip">{esc(t)}</span>' for t in sorted(atk.get("technologies",[]))[:20]) or "—"

    # ── CVE Section ───────────────────────────────────────────────────
    def cve_pills(lst, cls):
        return " ".join(f'<span class="cve-pill {cls}">{esc(c)}</span>' for c in lst[:15]) or "None"

    crit_pills = cve_pills(cves.get("critical",[]), "cve-crit")
    high_pills = cve_pills(cves.get("high",[]),     "cve-high")
    med_pills  = cve_pills(cves.get("medium",[]),   "cve-med")

    # ── Favicon Findings ─────────────────────────────────────────────
    fav_rows = ""
    for fv in favs:
        fav_rows += f'<tr><td class="mono">{esc(fv["ip"])}</td><td>{esc(str(fv["port"]))}</td><td><strong>{esc(fv["product"])}</strong></td><td class="mono">{esc(str(fv["hash"]))}</td></tr>'

    # ── DNS Resolution Table (sample) ────────────────────────────────
    dns_rows = ""
    for host, ips in list(pr.get("dns_resolved",{}).items())[:50]:
        dns_rows += f'<tr><td class="mono">{esc(host)}</td><td class="mono">{esc(", ".join(ips))}</td></tr>'

    # ── ISP Distribution ─────────────────────────────────────────────
    isp_rows = ""
    for isp, cnt in list(atk.get("isps",{}).items())[:10]:
        isp_rows += f'<tr><td>{esc(isp)}</td><td class="mono">{cnt}</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ShodanX v{VER} — {org}</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
/* ── Reset & Base ─────────────────────────────────────────── */
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{
  --bg:#0f1117;--surface:#181c27;--surface2:#1e2333;--surface3:#252b3b;
  --border:#2a3044;--border2:#3a4060;
  --text:#e2e6f0;--muted:#8892aa;--faint:#555f7a;
  --accent:#3b82f6;--accent2:#06b6d4;--accent3:#8b5cf6;
  --crit:#ef4444;--high:#f97316;--med:#eab308;--low:#22c55e;
  --font:'Inter','Segoe UI',system-ui,sans-serif;
  --mono:'JetBrains Mono','Fira Code',Consolas,monospace;
}}
html{{scroll-behavior:smooth}}
body{{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.6;display:flex;min-height:100vh}}

/* ── Sidebar ───────────────────────────────────────────────── */
.sidebar{{
  width:220px;flex-shrink:0;background:var(--surface);
  border-right:1px solid var(--border);
  position:fixed;top:0;left:0;height:100vh;
  display:flex;flex-direction:column;overflow-y:auto;z-index:100;
}}
.sb-logo{{padding:20px 16px 12px;border-bottom:1px solid var(--border)}}
.sb-logo h1{{font-size:15px;font-weight:700;color:#fff;letter-spacing:-.3px}}
.sb-logo p{{font-size:10px;color:var(--muted);margin-top:2px}}
.sb-grade{{
  margin:16px;padding:12px;border-radius:10px;
  background:var(--surface2);border:1px solid var(--border);
  text-align:center;
}}
.sb-grade .g-letter{{font-size:42px;font-weight:800;line-height:1;color:{gc}}}
.sb-grade .g-label{{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-top:4px}}
.sb-nav{{padding:8px 0;flex:1}}
.sb-section{{padding:6px 16px 2px;font-size:10px;color:var(--faint);text-transform:uppercase;letter-spacing:.1em;margin-top:8px}}
.sb-nav a{{
  display:flex;align-items:center;gap:8px;
  padding:8px 16px;color:var(--muted);text-decoration:none;
  font-size:13px;border-left:3px solid transparent;
  transition:all .15s;
}}
.sb-nav a:hover{{color:var(--text);background:var(--surface2);border-left-color:var(--accent)}}
.sb-nav a.active{{color:var(--accent);background:var(--surface2);border-left-color:var(--accent)}}
.sb-nav a .nav-icon{{font-size:14px;width:18px;text-align:center}}
.sb-stat{{
  margin:12px;padding:12px;border-radius:8px;
  background:var(--surface2);border:1px solid var(--border);
}}
.sb-stat .ss-row{{display:flex;justify-content:space-between;align-items:center;padding:3px 0}}
.sb-stat .ss-label{{font-size:11px;color:var(--muted)}}
.sb-stat .ss-val{{font-size:12px;font-weight:600}}
.ss-val.crit{{color:var(--crit)}}
.ss-val.high{{color:var(--high)}}

/* ── Main Content ───────────────────────────────────────────── */
.main{{margin-left:220px;flex:1;display:flex;flex-direction:column;min-height:100vh}}

/* ── Top Bar ────────────────────────────────────────────────── */
.topbar{{
  background:var(--surface);border-bottom:1px solid var(--border);
  padding:0 28px;height:56px;display:flex;align-items:center;
  justify-content:space-between;position:sticky;top:0;z-index:50;
}}
.topbar-left h2{{font-size:15px;font-weight:600;color:#fff}}
.topbar-left p{{font-size:11px;color:var(--muted)}}
.topbar-right{{display:flex;gap:10px;align-items:center}}
.tb-chip{{
  font-size:11px;padding:4px 10px;border-radius:20px;
  background:var(--surface2);border:1px solid var(--border);color:var(--muted);
}}
.tb-chip.mode{{border-color:var(--accent);color:var(--accent)}}
.conf-bar{{
  background:#7f1d1d;color:#fca5a5;text-align:center;
  padding:5px;font-size:11px;font-weight:700;letter-spacing:.12em;
}}

/* ── Content Sections ───────────────────────────────────────── */
.content{{padding:24px 28px;flex:1}}
.section{{
  background:var(--surface);border:1px solid var(--border);
  border-radius:12px;padding:20px 24px;margin-bottom:20px;
}}
.section-header{{
  display:flex;align-items:center;gap:10px;
  margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid var(--border);
}}
.section-header h2{{font-size:15px;font-weight:600;color:#fff}}
.section-header .sh-icon{{font-size:16px}}
.section-header .sh-count{{
  margin-left:auto;font-size:11px;padding:2px 8px;border-radius:12px;
  background:var(--surface2);color:var(--muted);border:1px solid var(--border);
}}
h3.sub-heading{{font-size:12px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:16px 0 8px}}

/* ── Stats Grid ─────────────────────────────────────────────── */
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin-bottom:20px}}
.stat-card{{
  background:var(--surface);border:1px solid var(--border);
  border-radius:10px;padding:16px;text-align:center;
}}
.stat-card.crit{{border-color:rgba(239,68,68,.3)}}
.stat-card.high{{border-color:rgba(249,115,22,.3)}}
.stat-n{{font-size:28px;font-weight:800;line-height:1;margin-bottom:4px;color:#fff}}
.stat-card.crit .stat-n{{color:var(--crit)}}
.stat-card.high .stat-n{{color:var(--high)}}
.stat-l{{font-size:11px;color:var(--muted)}}

/* ── Charts ─────────────────────────────────────────────────── */
.charts-row{{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px}}
.charts-row-3{{display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;margin-bottom:20px}}
.chart-box{{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px}}
.chart-box h3{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px}}
.chart-wrap{{position:relative;height:200px}}

/* ── Finding Cards ──────────────────────────────────────────── */
.finding-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}}
.fc{{
  background:var(--surface2);border:1px solid var(--border);
  border-radius:10px;padding:16px;
  border-left:3px solid var(--rc,#94a3b8);
  transition:box-shadow .2s;
}}
.fc:hover{{box-shadow:0 4px 20px rgba(0,0,0,.4)}}
.fc-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}}
.fc-badge{{font-size:10px;font-weight:700;padding:3px 8px;border-radius:4px;text-transform:uppercase;letter-spacing:.06em}}
.fc-score{{font-size:12px;color:var(--muted)}}
.fc-ip{{font-family:var(--mono);font-size:13px;color:var(--accent2);margin-bottom:2px}}
.fc-host{{font-size:12px;color:var(--text);margin-bottom:2px;word-break:break-all}}
.fc-svc{{font-size:11px;color:var(--muted);margin-bottom:8px}}
.fc-cves{{font-size:11px;padding:4px 8px;border-radius:4px;margin-bottom:6px}}
.fc-cves.critical{{background:rgba(239,68,68,.1);color:var(--crit)}}
.fc-cves.high{{background:rgba(249,115,22,.1);color:var(--high)}}
.fc-fav{{font-size:11px;color:#8b5cf6;margin-bottom:6px}}
.fc-factors{{list-style:none;margin-top:8px}}
.fc-factors li{{font-size:11px;color:var(--muted);padding:2px 0 2px 12px;position:relative}}
.fc-factors li::before{{content:"›";position:absolute;left:0;color:var(--accent)}}

/* ── Table ───────────────────────────────────────────────────── */
.table-wrap{{overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:12px}}
thead th{{
  background:var(--surface2);padding:8px 10px;text-align:left;
  font-size:10px;text-transform:uppercase;letter-spacing:.06em;
  color:var(--muted);border-bottom:1px solid var(--border2);
  cursor:pointer;white-space:nowrap;user-select:none;
}}
thead th:hover{{color:var(--accent)}}
thead th::after{{content:" ↕";opacity:.3}}
tbody td{{
  padding:7px 10px;border-bottom:1px solid var(--border);
  max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
}}
tbody tr:hover td{{background:var(--surface2)}}
.mono{{font-family:var(--mono);font-size:11px;color:var(--accent2)}}
.hn-cell{{max-width:180px;color:var(--text)}}
.cve-cell{{font-size:11px}}
.dim-cell{{color:var(--muted);font-size:11px;max-width:120px}}
.fac-cell{{font-size:11px;color:var(--faint);max-width:200px}}

.risk-pill{{font-size:10px;font-weight:700;padding:2px 7px;border-radius:10px;text-transform:uppercase;letter-spacing:.05em}}
.score-muted{{font-size:11px;color:var(--muted)}}
.svc-badge{{
  font-size:10px;background:var(--surface3);border:1px solid var(--border);
  padding:1px 6px;border-radius:4px;color:var(--text);
}}

/* ── Filter Bar ──────────────────────────────────────────────── */
.filter-bar{{display:flex;gap:10px;margin-bottom:14px;flex-wrap:wrap}}
.filter-bar input,.filter-bar select{{
  background:var(--surface2);border:1px solid var(--border);
  padding:7px 12px;border-radius:7px;font-size:12px;color:var(--text);
  outline:none;
}}
.filter-bar input{{flex:1;min-width:200px}}
.filter-bar input:focus,.filter-bar select:focus{{border-color:var(--accent)}}
.filter-bar select option{{background:var(--surface2)}}
.export-btn{{
  background:var(--surface2);border:1px solid var(--border2);
  padding:7px 14px;border-radius:7px;font-size:12px;color:var(--muted);
  cursor:pointer;transition:all .15s;
}}
.export-btn:hover{{color:var(--text);border-color:var(--accent)}}

/* ── Chips & Pills ────────────────────────────────────────────── */
.chip{{
  display:inline-block;font-size:11px;padding:3px 10px;border-radius:12px;
  background:var(--surface2);border:1px solid var(--border);color:var(--text);margin:2px;
}}
.waf-chip{{border-color:rgba(139,92,246,.4);color:#a78bfa;background:rgba(139,92,246,.08)}}
.svr-chip{{border-color:rgba(6,182,212,.4);color:var(--accent2);background:rgba(6,182,212,.08)}}

.dtag{{
  display:inline-block;font-family:var(--mono);font-size:10px;
  padding:2px 8px;border-radius:10px;margin:2px;
  background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.25);color:#60a5fa;
}}
.dtag.san{{background:rgba(34,197,94,.08);border-color:rgba(34,197,94,.25);color:#4ade80}}
.dtag.crt{{background:rgba(139,92,246,.08);border-color:rgba(139,92,246,.25);color:#a78bfa}}
.dtag.ht{{background:rgba(249,115,22,.08);border-color:rgba(249,115,22,.25);color:#fb923c}}

/* ── CVE Pills ────────────────────────────────────────────────── */
.cve-pill{{
  display:inline-block;font-family:var(--mono);font-size:10px;
  padding:2px 8px;border-radius:4px;margin:2px;font-weight:600;
}}
.cve-crit{{background:rgba(239,68,68,.12);color:var(--crit);border:1px solid rgba(239,68,68,.3)}}
.cve-high{{background:rgba(249,115,22,.12);color:var(--high);border:1px solid rgba(249,115,22,.3)}}
.cve-med{{background:rgba(234,179,8,.12);color:var(--med);border:1px solid rgba(234,179,8,.3)}}

/* ── Geo Bars ─────────────────────────────────────────────────── */
.geo-row{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.geo-name{{min-width:140px;font-size:12px;color:var(--text)}}
.geo-track{{flex:1;background:var(--surface3);border-radius:4px;height:6px}}
.geo-fill{{background:var(--accent);border-radius:4px;height:6px;min-width:2px}}
.geo-n{{min-width:30px;text-align:right;font-size:11px;color:var(--muted);font-weight:600}}

/* ── Small table ─────────────────────────────────────────────── */
.mini-table{{width:100%;border-collapse:collapse;font-size:12px}}
.mini-table td,.mini-table th{{padding:6px 10px;border-bottom:1px solid var(--border);text-align:left}}
.mini-table th{{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);background:var(--surface2)}}
.mini-table tr:hover td{{background:var(--surface2)}}

/* ── Methodology ─────────────────────────────────────────────── */
.method-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.method-card{{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:14px}}
.method-card h4{{font-size:12px;font-weight:600;color:var(--accent2);margin-bottom:6px}}
.method-card p{{font-size:12px;color:var(--muted);line-height:1.6}}
.method-card code{{font-family:var(--mono);font-size:11px;color:var(--text);background:var(--surface3);padding:1px 5px;border-radius:3px}}

/* ── Footer ────────────────────────────────────────────────────  */
.footer{{
  border-top:1px solid var(--border);padding:16px 28px;
  display:flex;justify-content:space-between;align-items:center;
  font-size:11px;color:var(--faint);
}}

/* ── Responsive ─────────────────────────────────────────────── */
@media(max-width:900px){{
  .sidebar{{display:none}}
  .main{{margin-left:0}}
  .charts-row{{grid-template-columns:1fr}}
  .charts-row-3{{grid-template-columns:1fr}}
  .method-grid{{grid-template-columns:1fr}}
}}

/* ── Print ──────────────────────────────────────────────────── */
@media print{{
  .sidebar{{display:none}}
  .main{{margin-left:0}}
  .topbar{{position:static}}
  .section{{break-inside:avoid}}
  body{{background:#fff;color:#000}}
  .section{{background:#fff;border:1px solid #ddd}}
}}
</style>
</head>
<body>

<!-- ══ SIDEBAR ══════════════════════════════════════════════════ -->
<nav class="sidebar">
  <div class="sb-logo">
    <h1>ShodanX v{VER}</h1>
    <p>Enterprise Intelligence Suite</p>
  </div>
  <div class="sb-grade">
    <div class="g-letter">{grade}</div>
    <div class="g-label">Risk Grade</div>
  </div>
  <div class="sb-stat">
    <div class="ss-row"><span class="ss-label">Assets</span><span class="ss-val">{es['total_assets']}</span></div>
    <div class="ss-row"><span class="ss-label">Unique IPs</span><span class="ss-val">{es['unique_ips']}</span></div>
    <div class="ss-row"><span class="ss-label">Critical CVEs</span><span class="ss-val crit">{es['critical_cves']}</span></div>
    <div class="ss-row"><span class="ss-label">High CVEs</span><span class="ss-val high">{es['high_cves']}</span></div>
    <div class="ss-row"><span class="ss-label">Subdomains</span><span class="ss-val">{pr['total_subdomains']}</span></div>
    <div class="ss-row"><span class="ss-label">DNS Resolved</span><span class="ss-val">{pr['dns_resolved_count']}</span></div>
  </div>
  <div class="sb-nav">
    <div class="sb-section">Overview</div>
    <a href="#summary"><span class="nav-icon">📋</span> Executive Summary</a>
    <a href="#charts"><span class="nav-icon">📊</span> Charts & Stats</a>
    <div class="sb-section">Intelligence</div>
    <a href="#findings"><span class="nav-icon">🎯</span> Critical Findings</a>
    <a href="#cves"><span class="nav-icon">🔴</span> CVE Analysis</a>
    <a href="#favicons"><span class="nav-icon">🖼</span> Favicon Hits</a>
    <div class="sb-section">Recon</div>
    <a href="#passive"><span class="nav-icon">🌐</span> Passive Recon</a>
    <a href="#dns"><span class="nav-icon">🔍</span> DNS Resolution</a>
    <a href="#geo"><span class="nav-icon">🗺</span> Geographic</a>
    <div class="sb-section">Assets</div>
    <a href="#stack"><span class="nav-icon">🛡</span> Tech Stack</a>
    <a href="#inventory"><span class="nav-icon">📦</span> Full Inventory</a>
    <a href="#method"><span class="nav-icon">📖</span> Methodology</a>
  </div>
</nav>

<!-- ══ MAIN ═════════════════════════════════════════════════════ -->
<div class="main">
<div class="conf-bar">⚠ CONFIDENTIAL — AUTHORIZED PERSONNEL ONLY — ShodanX ENTERPRISE RED TEAM REPORT ⚠</div>

<div class="topbar">
  <div class="topbar-left">
    <h2>{org}</h2>
    <p>Attack Surface Assessment · {date} · {dur}s</p>
  </div>
  <div class="topbar-right">
    <span class="tb-chip mode">{mode}</span>
    <span class="tb-chip">{domain or 'auto-detect'}</span>
    <button class="export-btn" onclick="exportCSV()">↓ Export CSV</button>
    <button class="export-btn" onclick="window.print()">🖨 Print</button>
  </div>
</div>

<div class="content">

<!-- ── Executive Summary ─────────────────────────────────────── -->
<div id="summary" class="section">
  <div class="section-header">
    <span class="sh-icon">📋</span>
    <h2>Executive Summary</h2>
    <span class="sh-count">Risk Grade: <strong style="color:{gc}">{grade}</strong></span>
  </div>
  <p style="font-size:13px;color:#b0bac8;line-height:1.8;max-width:800px">
    This report presents the external attack surface assessment for <strong style="color:#fff">{org}</strong>
    conducted by ShodanX v{VER} using chained intelligence from Shodan, crt.sh, HackerTarget, 
    DNS resolution, and InternetDB. The assessment identified <strong style="color:#fff">{es['total_assets']}</strong> 
    verified assets across <strong style="color:#fff">{es['unique_ips']}</strong> unique IP addresses, 
    with <strong style="color:var(--crit)">{es['critical_cves']}</strong> critical and 
    <strong style="color:var(--high)">{es['high_cves']}</strong> high severity CVEs detected. 
    <strong>{es['false_positives_removed']}</strong> false positives were removed through 
    strict relevance filtering. Passive reconnaissance discovered 
    <strong style="color:#fff">{pr['total_subdomains']}</strong> subdomains, of which 
    <strong>{pr['dns_resolved_count']}</strong> were resolved to active IP addresses.
  </p>
</div>

<!-- ── Stats ─────────────────────────────────────────────────── -->
<div class="stats-grid">
  <div class="stat-card"><div class="stat-n">{es['total_assets']}</div><div class="stat-l">Verified Assets</div></div>
  <div class="stat-card"><div class="stat-n">{es['unique_ips']}</div><div class="stat-l">Unique IPs</div></div>
  <div class="stat-card"><div class="stat-n">{pr['total_subdomains']}</div><div class="stat-l">Subdomains Found</div></div>
  <div class="stat-card"><div class="stat-n">{pr['dns_resolved_count']}</div><div class="stat-l">DNS Resolved</div></div>
  <div class="stat-card crit"><div class="stat-n">{rd.get('CRITICAL',0)}</div><div class="stat-l">Critical Risk</div></div>
  <div class="stat-card high"><div class="stat-n">{rd.get('HIGH',0)}</div><div class="stat-l">High Risk</div></div>
  <div class="stat-card"><div class="stat-n">{es['total_cves']}</div><div class="stat-l">Total CVEs</div></div>
  <div class="stat-card"><div class="stat-n">{es['false_positives_removed']}</div><div class="stat-l">FP Removed</div></div>
  <div class="stat-card"><div class="stat-n">{len(atk.get('discovered_domains',[]))}</div><div class="stat-l">Domains</div></div>
  <div class="stat-card"><div class="stat-n">{data.get('internetdb_coverage',0)}</div><div class="stat-l">InternetDB Coverage</div></div>
</div>

<!-- ── Charts ────────────────────────────────────────────────── -->
<div id="charts" class="charts-row">
  <div class="chart-box"><h3>Risk Distribution</h3><div class="chart-wrap"><canvas id="riskChart"></canvas></div></div>
  <div class="chart-box"><h3>Service Classification</h3><div class="chart-wrap"><canvas id="svcChart"></canvas></div></div>
</div>
<div class="charts-row">
  <div class="chart-box"><h3>Port Distribution</h3><div class="chart-wrap"><canvas id="portChart"></canvas></div></div>
  <div class="chart-box"><h3>Geographic Distribution</h3><div class="chart-wrap"><canvas id="geoChart"></canvas></div></div>
</div>

<!-- ── Critical Findings ─────────────────────────────────────── -->
<div id="findings" class="section">
  <div class="section-header">
    <span class="sh-icon">🎯</span>
    <h2>Critical & High Findings</h2>
    <span class="sh-count">{len(finding)} findings</span>
  </div>
  <div class="finding-grid">
    {fcards if fcards else '<p style="color:var(--muted)">No critical findings detected.</p>'}
  </div>
</div>

<!-- ── CVE Analysis ───────────────────────────────────────────── -->
<div id="cves" class="section">
  <div class="section-header">
    <span class="sh-icon">🔴</span>
    <h2>CVE / Vulnerability Analysis</h2>
    <span class="sh-count">{es['total_cves']} total</span>
  </div>
  <h3 class="sub-heading">Critical ({len(cves.get('critical',[]))})</h3>
  <div>{crit_pills}</div>
  <h3 class="sub-heading" style="margin-top:14px">High ({len(cves.get('high',[]))})</h3>
  <div>{high_pills}</div>
  <h3 class="sub-heading" style="margin-top:14px">Medium ({len(cves.get('medium',[]))})</h3>
  <div>{med_pills}</div>
  <h3 class="sub-heading" style="margin-top:14px">Low</h3>
  <p style="color:var(--muted);font-size:12px">{cves.get('low_count',0)} CVEs categorized as low severity</p>
</div>

<!-- ── Favicon Identifications ────────────────────────────────── -->
<div id="favicons" class="section">
  <div class="section-header">
    <span class="sh-icon">🖼</span>
    <h2>Favicon Fingerprint Identifications</h2>
    <span class="sh-count">{len(favs)} hits</span>
  </div>
  {f'''<div class="table-wrap"><table class="mini-table">
  <thead><tr><th>IP</th><th>Port</th><th>Identified Product</th><th>Hash</th></tr></thead>
  <tbody>{fav_rows}</tbody>
  </table></div>''' if fav_rows else '<p style="color:var(--muted);font-size:12px">No favicon products identified (install mmh3: pip install mmh3)</p>'}
</div>

<!-- ── Passive Recon ──────────────────────────────────────────── -->
<div id="passive" class="section">
  <div class="section-header">
    <span class="sh-icon">🌐</span>
    <h2>Passive Reconnaissance</h2>
    <span class="sh-count">{pr['total_subdomains']} subdomains</span>
  </div>
  <h3 class="sub-heading">crt.sh Certificate Transparency ({len(pr.get('crtsh_subdomains',[]))})</h3>
  <div style="max-height:120px;overflow-y:auto;margin-bottom:12px">{sub_cloud or '<span style="color:var(--muted)">None found</span>'}</div>
  <h3 class="sub-heading">HackerTarget Passive DNS ({len(pr.get('ht_subdomains',[]))})</h3>
  <div style="max-height:100px;overflow-y:auto;margin-bottom:12px">{ht_cloud or '<span style="color:var(--muted)">None found</span>'}</div>
  <h3 class="sub-heading">Shodan Discovered Domains & SSL SANs</h3>
  <div style="max-height:100px;overflow-y:auto;margin-bottom:8px">{dom_cloud or '<span style="color:var(--muted)">None</span>'}</div>
  {f'<div style="max-height:80px;overflow-y:auto">{san_cloud}</div>' if san_cloud else ''}
</div>

<!-- ── DNS Resolution ─────────────────────────────────────────── -->
<div id="dns" class="section">
  <div class="section-header">
    <span class="sh-icon">🔍</span>
    <h2>DNS Resolution Results</h2>
    <span class="sh-count">{pr['dns_resolved_count']} resolved</span>
  </div>
  <div class="table-wrap" style="max-height:320px;overflow-y:auto">
    <table class="mini-table">
      <thead><tr><th>Hostname</th><th>Resolved IPs</th></tr></thead>
      <tbody>{dns_rows or '<tr><td colspan="2" style="color:var(--muted)">No DNS resolution data</td></tr>'}</tbody>
    </table>
  </div>
</div>

<!-- ── Geographic ─────────────────────────────────────────────── -->
<div id="geo" class="section">
  <div class="section-header">
    <span class="sh-icon">🗺</span>
    <h2>Geographic & ISP Distribution</h2>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;flex-wrap:wrap">
    <div>
      <h3 class="sub-heading">By Country</h3>
      {geo_rows or '<p style="color:var(--muted)">No location data</p>'}
    </div>
    <div>
      <h3 class="sub-heading">By ISP / Hosting Provider</h3>
      <table class="mini-table"><thead><tr><th>ISP</th><th>Count</th></tr></thead>
      <tbody>{isp_rows or '<tr><td colspan="2" style="color:var(--muted)">No ISP data</td></tr>'}</tbody></table>
    </div>
  </div>
</div>

<!-- ── Technology Stack ───────────────────────────────────────── -->
<div id="stack" class="section">
  <div class="section-header">
    <span class="sh-icon">🛡</span>
    <h2>Technology Stack</h2>
  </div>
  <h3 class="sub-heading">WAF / Security Appliances</h3>
  <div style="margin-bottom:12px">{waf_chips}</div>
  <h3 class="sub-heading">Web Servers</h3>
  <div style="margin-bottom:12px">{svr_chips}</div>
  <h3 class="sub-heading">Frameworks & Technologies</h3>
  <div>{tech_chips}</div>
</div>

<!-- ── Full Inventory ─────────────────────────────────────────── -->
<div id="inventory" class="section">
  <div class="section-header">
    <span class="sh-icon">📦</span>
    <h2>Full Asset Inventory</h2>
    <span class="sh-count">{len(assets)} assets</span>
  </div>
  <div class="filter-bar">
    <input type="text" id="si" placeholder="Filter by IP, hostname, service, CVE..." oninput="filterTable()">
    <select id="rf" onchange="filterTable()">
      <option value="">All Risk Levels</option>
      <option value="CRITICAL">Critical</option>
      <option value="HIGH">High</option>
      <option value="MEDIUM">Medium</option>
      <option value="LOW">Low</option>
    </select>
    <select id="sf" onchange="filterTable()">
      <option value="">All Services</option>
      <option value="HTTP">HTTP</option>
      <option value="HTTPS">HTTPS</option>
      <option value="RDP">RDP</option>
      <option value="Database">Database</option>
      <option value="SSH">SSH</option>
      <option value="VPN">VPN</option>
    </select>
  </div>
  <div class="table-wrap">
    <table id="assetTable">
      <thead><tr>
        <th onclick="sortTable(0)">IP</th>
        <th onclick="sortTable(1)">Port</th>
        <th onclick="sortTable(2)">Service</th>
        <th onclick="sortTable(3)">Hostname</th>
        <th onclick="sortTable(4)">Risk</th>
        <th onclick="sortTable(5)">CVEs</th>
        <th>WAF</th>
        <th>Server</th>
        <th>Favicon Product</th>
        <th>Technology</th>
        <th>Risk Factors</th>
      </tr></thead>
      <tbody id="assetBody">{rows}</tbody>
    </table>
  </div>
  <p id="rowCount" style="margin-top:8px;font-size:11px;color:var(--muted)"></p>
</div>

<!-- ── Methodology ────────────────────────────────────────────── -->
<div id="method" class="section">
  <div class="section-header">
    <span class="sh-icon">📖</span>
    <h2>Methodology & Appendix</h2>
  </div>
  <div class="method-grid">
    <div class="method-card">
      <h4>Phase 1 — Passive Recon</h4>
      <p>Certificate transparency logs queried via <code>crt.sh</code> for all subdomains. HackerTarget passive DNS queried. No active scanning in this phase.</p>
    </div>
    <div class="method-card">
      <h4>Phase 2 — DNS Resolution</h4>
      <p>All discovered subdomains resolved to IP addresses using parallel DNS lookups ({MAX_DNS_WORKERS} workers). PTR records correlated.</p>
    </div>
    <div class="method-card">
      <h4>Phase 3 — Shodan Intelligence</h4>
      <p>Shodan API queried with org, hostname, SSL, and title filters. Mode: <code>{mode}</code>. False positives removed via RelevanceFilter.</p>
    </div>
    <div class="method-card">
      <h4>Phase 4 — InternetDB Enrichment</h4>
      <p>All discovered IPs enriched via Shodan InternetDB (free, no credits). Additional CVEs and port data merged into results.</p>
    </div>
    <div class="method-card">
      <h4>Phase 5 — Favicon Hashing</h4>
      <p>MurmurHash3 favicon hashes computed for HTTP/HTTPS services. Matched against known product fingerprints including threat actor C2 frameworks.</p>
    </div>
    <div class="method-card">
      <h4>Risk Scoring</h4>
      <p>0–100 composite score: port criticality (40pts max), CVE severity (60pts max), WAF absence, VPN exposure. Grades: A (clean) to F (3+ critical).</p>
    </div>
  </div>
</div>

</div><!-- /content -->

<div class="footer">
  <span>ShodanX v{VER} · {date}</span>
  <span>Target: {org} · Mode: {mode}</span>
  <span>CONFIDENTIAL — Authorized Use Only</span>
</div>
</div><!-- /main -->

<script>
// Chart defaults
Chart.defaults.color = '#8892aa';
Chart.defaults.borderColor = '#2a3044';

const riskColors = ['#ef4444','#f97316','#eab308','#22c55e'];
const accentPalette = ['#3b82f6','#06b6d4','#8b5cf6','#22c55e','#f97316','#ef4444','#eab308','#a855f7','#ec4899','#14b8a6','#fb923c','#84cc16'];

// Risk donut
new Chart(document.getElementById('riskChart'), {{
  type:'doughnut',
  data:{{labels:{risk_labels},datasets:[{{data:{risk_vals},backgroundColor:riskColors,borderWidth:0}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{position:'right',labels:{{font:{{size:11}},boxWidth:12}}}}}}}}
}});

// Service bar
new Chart(document.getElementById('svcChart'), {{
  type:'bar',
  data:{{labels:{svc_labels},datasets:[{{label:'Count',data:{svc_vals},backgroundColor:'#3b82f6',borderRadius:4,borderSkipped:false}}]}},
  options:{{responsive:true,maintainAspectRatio:false,indexAxis:'y',
    plugins:{{legend:{{display:false}}}},
    scales:{{x:{{grid:{{color:'#1e2333'}},ticks:{{font:{{size:10}}}}}},y:{{grid:{{display:false}},ticks:{{font:{{size:10}}}}}}}}
  }}
}});

// Port distribution
new Chart(document.getElementById('portChart'), {{
  type:'bar',
  data:{{labels:{port_labels},datasets:[{{label:'Assets',data:{port_vals},backgroundColor:accentPalette,borderRadius:3,borderSkipped:false}}]}},
  options:{{responsive:true,maintainAspectRatio:false,
    plugins:{{legend:{{display:false}}}},
    scales:{{x:{{grid:{{color:'#1e2333'}},ticks:{{font:{{size:10}}}}}},y:{{grid:{{color:'#1e2333'}},ticks:{{font:{{size:10}}}}}}}}
  }}
}});

// Geo chart
new Chart(document.getElementById('geoChart'), {{
  type:'bar',
  data:{{labels:{geo_labels},datasets:[{{label:'Assets',data:{geo_vals},backgroundColor:'#06b6d4',borderRadius:4,borderSkipped:false}}]}},
  options:{{responsive:true,maintainAspectRatio:false,indexAxis:'y',
    plugins:{{legend:{{display:false}}}},
    scales:{{x:{{grid:{{color:'#1e2333'}},ticks:{{font:{{size:10}}}}}},y:{{grid:{{display:false}},ticks:{{font:{{size:10}}}}}}}}
  }}
}});

// Filtering
function filterTable() {{
  const s = document.getElementById('si').value.toLowerCase();
  const r = document.getElementById('rf').value;
  const sv = document.getElementById('sf').value;
  const rows = document.querySelectorAll('#assetBody tr');
  let vis = 0;
  rows.forEach(row => {{
    const t = row.textContent.toLowerCase();
    const show = (!s || t.includes(s)) && (!r || t.includes(r.toLowerCase())) && (!sv || t.includes(sv.toLowerCase()));
    row.style.display = show ? '' : 'none';
    if (show) vis++;
  }});
  document.getElementById('rowCount').textContent = `Showing ${{vis}} of ${{rows.length}} assets`;
}}
filterTable();

// Sorting
let sortDir = {{}};
function sortTable(col) {{
  const tbody = document.getElementById('assetBody');
  const rows = Array.from(tbody.rows);
  sortDir[col] = !sortDir[col];
  rows.sort((a, b) => {{
    let va = a.cells[col].textContent.trim();
    let vb = b.cells[col].textContent.trim();
    const na = parseFloat(va), nb = parseFloat(vb);
    if (!isNaN(na) && !isNaN(nb)) return sortDir[col] ? na - nb : nb - na;
    return sortDir[col] ? va.localeCompare(vb) : vb.localeCompare(va);
  }});
  rows.forEach(r => tbody.appendChild(r));
}}

// Export CSV
function exportCSV() {{
  const rows = document.querySelectorAll('#assetTable tr');
  const csv = Array.from(rows).map(r =>
    Array.from(r.cells).map(c => '"' + c.textContent.replace(/"/g,'""') + '"').join(',')
  ).join('\\n');
  const a = document.createElement('a');
  a.href = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv);
  a.download = 'shodanx_{esc(meta["target"].replace(" ","_"))}.csv';
  a.click();
}}

// Active nav on scroll
const sections = document.querySelectorAll('[id]');
const navLinks = document.querySelectorAll('.sb-nav a');
window.addEventListener('scroll', () => {{
  let cur = '';
  sections.forEach(s => {{ if (window.scrollY >= s.offsetTop - 80) cur = s.id; }});
  navLinks.forEach(l => l.classList.toggle('active', l.getAttribute('href') === '#' + cur));
}});
</script>
</body></html>"""

MAX_DNS_WORKERS = 30  # used in methodology text above — replicate here for template

#!/usr/bin/env python3
"""
OT THREAT RADAR — build script
================================
Aggregates OT/ICS threat intelligence from free public sources and renders a
single static dashboard page (index.html). Designed to run on a schedule
(GitHub Actions cron) where the network is open.

LIVE SOURCES (pulled at build time):
  - CISA ICS Advisories            (RSS/Atom, no key)
  - NVD CVE API, ICS-vendor filter (no key; optional NVD_API_KEY for rate limit)
  - abuse.ch ThreatFox             (optional ABUSE_CH_API_KEY -> OT-tagged IOCs)
  - OT/ICS security news           (RSS, no key)

ALWAYS-ON REFERENCE (curated, offline, no network):
  - Industrial malware families    (Stuxnet -> FrostyGoop)
  - ICS protocol exposure table    (Modbus, S7, DNP3, ...)

MODES:
  python build.py           # live fetch; falls back to seed per-source on error
  python build.py --offline # render entirely from seed_data.json (no network)

Each section records its own "updated" timestamp and status, so a source that
fails (e.g. an expired abuse.ch key) is shown as stale instead of silently
breaking the whole page.
"""
import os, sys, json, html, datetime, re, time

try:
    import requests
except Exception:
    requests = None
try:
    import feedparser
except Exception:
    feedparser = None

HERE = os.path.dirname(os.path.abspath(__file__))
OFFLINE = "--offline" in sys.argv
UA = {"User-Agent": "ot-threat-radar/1.0 (+https://github.com/YOUR_USERNAME/ot-threat-radar)"}
NOW = datetime.datetime.now(datetime.timezone.utc)

# ---- OT / ICS scope ---------------------------------------------------------
ICS_VENDORS = [
    "Siemens", "Schneider Electric", "Rockwell", "Allen-Bradley", "Honeywell",
    "Emerson", "ABB", "Yokogawa", "Mitsubishi Electric", "OMRON", "WAGO",
    "Phoenix Contact", "Beckhoff", "Moxa", "Hitachi Energy", "Delta Electronics",
    "Advantech", "CODESYS", "Iconics", "AVEVA", "Inductive Automation", "GE",
]
ICS_KEYWORDS = [v.lower() for v in ICS_VENDORS] + [
    "scada", "plc", "hmi", "ics", "ot ", "industrial control", "modbus",
    "dnp3", "iec 61850", "iec 60870", "profinet", "ethernet/ip", "bacnet",
    "opc ua", "rtu", "safety instrumented",
]

# ---- Curated industrial-malware reference (always rendered) ------------------
ICS_MALWARE = [
    ("Stuxnet", "2010", "Siemens S7-300/400 PLCs (Step7/WinCC)",
     "First known malware to physically damage a process — Natanz uranium centrifuges."),
    ("Havex (Dragonfly)", "2013", "OPC servers, energy/pharma",
     "RAT that enumerated OPC/ICS assets for espionage across energy sector."),
    ("BlackEnergy 2/3", "2015", "HMIs, Ukraine power grid",
     "Enabled the 2015 Ukraine grid outage; operators regained control manually."),
    ("Industroyer / CrashOverride", "2016", "IEC 60870-5-101/104, IEC 61850, OPC DA",
     "First malware purpose-built to speak grid protocols; 2016 Kyiv outage."),
    ("TRITON / TRISIS", "2017", "Schneider Triconex Safety Instrumented System",
     "Targeted a safety system at a petrochemical plant — risk to human life."),
    ("Industroyer2", "2022", "IEC 60870-5-104 (hardcoded config)",
     "Tailored variant aimed at a Ukrainian high-voltage substation."),
    ("INCONTROLLER / PIPEDREAM", "2022", "Schneider & OMRON PLCs, OPC UA, Modbus, CODESYS",
     "Modular, reusable ICS attack framework (CHERNOVITE) — not incident-specific."),
    ("FrostyGoop / BUSTLEBERM", "2024", "Modbus TCP",
     "Used against a district-heating utility in Lviv; manipulated controllers over Modbus."),
]

# ---- ICS protocol exposure reference (always rendered) ----------------------
ICS_PROTOCOLS = [
    ("502",   "Modbus TCP",            "No authentication by design"),
    ("102",   "S7comm / ISO-TSAP",     "Siemens S7 PLCs"),
    ("20000", "DNP3",                  "Electric & water utilities"),
    ("44818", "EtherNet/IP (CIP)",     "Rockwell / ODVA devices"),
    ("47808", "BACnet/IP",             "Building automation (HVAC, access)"),
    ("4840",  "OPC UA",                "Modern interoperability layer"),
    ("1911",  "Niagara Fox",           "Tridium building controllers"),
    ("9600",  "OMRON FINS",            "Omron PLCs"),
    ("2404",  "IEC 60870-5-104",       "Electric power telecontrol"),
    ("789",   "Red Lion Crimson",      "HMIs / data loggers"),
]

# =============================================================================
# Fetch helpers (live mode)
# =============================================================================
def _get_json(url, **kw):
    kw.setdefault("headers", UA)   # don't clobber a caller-supplied headers=
    kw.setdefault("timeout", 30)
    r = requests.get(url, **kw)
    r.raise_for_status()
    return r.json()

def _fetch_feed(url):
    """Fetch an RSS/Atom feed with our own user-agent, then parse the bytes.
    More robust than feedparser's built-in HTTP, which some sites (CISA) block."""
    r = requests.get(url, headers=UA, timeout=30)
    r.raise_for_status()
    return feedparser.parse(r.content)

def fetch_cisa_ics(limit=12):
    """CISA ICS advisories via RSS. Tries the ICS feed, falls back to all-advisories filtered."""
    feeds = [
        "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://us-cert.cisa.gov/ics/advisories/advisories.xml",
    ]
    for fu in feeds:
        try:
            d = _fetch_feed(fu)
            items = []
            for e in d.entries:
                title = e.get("title", "")
                if "ics-advisories" not in fu and "ICS" not in title and "Industrial" not in title:
                    continue
                items.append({
                    "title": title.strip(),
                    "link": e.get("link", ""),
                    "date": _fmt_entry_date(e),
                    "vendor": _guess_vendor(title),
                })
                if len(items) >= limit:
                    break
            if items:
                return items, "live"
        except Exception as ex:
            print(f"  CISA feed error ({fu}): {ex}", file=sys.stderr)
    return [], "error"

def fetch_nvd_ics(limit=12, days=21):
    """Recent CVEs mentioning ICS vendors, via NVD 2.0 API (keyword search)."""
    key = os.environ.get("NVD_API_KEY")
    hdr = dict(UA)
    if key:
        hdr["apiKey"] = key
    start = (NOW - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    end = NOW.strftime("%Y-%m-%dT%H:%M:%S.000")
    out = []
    # NVD throttles unauthenticated clients to ~5 requests / 30s, so space them out.
    gap = 2 if key else 6
    vendors = ("Siemens", "Schneider Electric", "Rockwell", "Moxa")
    for idx, kw in enumerate(vendors):
        if idx:
            time.sleep(gap)
        try:
            data = _get_json(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                headers=hdr,
                params={"keywordSearch": kw, "pubStartDate": start, "pubEndDate": end,
                        "resultsPerPage": 8},
            )
            for v in data.get("vulnerabilities", []):
                c = v.get("cve", {})
                cid = c.get("id", "")
                desc = next((x["value"] for x in c.get("descriptions", []) if x["lang"] == "en"), "")
                metrics = c.get("metrics", {})
                score, sev = _nvd_severity(metrics)
                out.append({"id": cid, "desc": desc[:180], "score": score,
                            "severity": sev, "vendor": kw,
                            "link": f"https://nvd.nist.gov/vuln/detail/{cid}"})
        except Exception as ex:
            print(f"  NVD error ({kw}): {ex}", file=sys.stderr)
    # dedupe by CVE id, sort by score desc
    seen, uniq = set(), []
    for x in sorted(out, key=lambda r: r["score"] or 0, reverse=True):
        if x["id"] in seen:
            continue
        seen.add(x["id"]); uniq.append(x)
    return (uniq[:limit], "live") if uniq else ([], "error")

def fetch_threatfox_ot(limit=15):
    """abuse.ch ThreatFox recent IOCs, filtered to OT-relevant malware families.
    Requires a free Auth-Key in ABUSE_CH_API_KEY (abuse.ch now gates the API)."""
    key = os.environ.get("ABUSE_CH_API_KEY")
    if not key:
        return [], "nokey"
    try:
        hdr = dict(UA); hdr["Auth-Key"] = key
        r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                          json={"query": "get_iocs", "days": 3}, headers=hdr, timeout=30)
        r.raise_for_status()
        data = r.json()
        ot_fams = ("stuxnet", "triton", "trisis", "industroyer", "pipedream",
                   "incontroller", "frostygoop", "havex", "blackenergy", "plc", "scada", "ics")
        out = []
        for ioc in data.get("data", []):
            mal = (ioc.get("malware_printable") or "").lower()
            tags = " ".join(ioc.get("tags") or []).lower()
            if any(f in mal or f in tags for f in ot_fams):
                out.append({"ioc": ioc.get("ioc", ""), "type": ioc.get("ioc_type", ""),
                            "malware": ioc.get("malware_printable", "unknown"),
                            "link": f"https://threatfox.abuse.ch/browse/tag/{ioc.get('ioc_type','')}/"})
            if len(out) >= limit:
                break
        return (out, "live") if out else ([], "empty")
    except Exception as ex:
        print(f"  ThreatFox error: {ex}", file=sys.stderr)
        return [], "error"

def fetch_news(limit=8):
    """OT/ICS-leaning security news from public RSS feeds."""
    feeds = [
        "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "https://www.bleepingcomputer.com/feed/",
        "https://feeds.feedburner.com/TheHackersNews",
    ]
    out = []
    for fu in feeds:
        try:
            d = _fetch_feed(fu)
            for e in d.entries[:6]:
                out.append({"title": e.get("title", "").strip(),
                            "link": e.get("link", ""),
                            "src": _domain(e.get("link", "")),
                            "date": _fmt_entry_date(e)})
        except Exception as ex:
            print(f"  news error ({fu}): {ex}", file=sys.stderr)
    return (out[:limit], "live") if out else ([], "error")

# ---- small utils ------------------------------------------------------------
def _fmt_entry_date(e):
    for k in ("published_parsed", "updated_parsed"):
        t = e.get(k)
        if t:
            return datetime.datetime(*t[:6]).strftime("%b %d, %Y")
    return ""

def _guess_vendor(text):
    t = (text or "").lower()
    for v in ICS_VENDORS:
        if v.lower() in t:
            return v
    return ""

def _domain(url):
    m = re.search(r"https?://([^/]+)/?", url or "")
    return (m.group(1).replace("www.", "") if m else "")

def _nvd_severity(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            score = data.get("baseScore")
            sev = data.get("baseSeverity") or arr[0].get("baseSeverity") or ""
            if not sev and score is not None:
                sev = ("CRITICAL" if score >= 9 else "HIGH" if score >= 7
                       else "MEDIUM" if score >= 4 else "LOW")
            return score, (sev or "").upper()
    return None, ""

# =============================================================================
# Assemble data (live or offline)
# =============================================================================
def load_seed():
    with open(os.path.join(HERE, "seed_data.json"), encoding="utf-8") as f:
        return json.load(f)

def gather():
    seed = load_seed()
    data = {"generated": NOW.strftime("%b %d, %Y %H:%M UTC"), "sections": {}}

    def section(name, live_fn, seed_key):
        if OFFLINE or requests is None or feedparser is None:
            return {"items": seed.get(seed_key, []), "status": "seed",
                    "updated": seed.get("_seed_date", "sample")}
        print(f"Fetching {name} ...", file=sys.stderr)
        try:
            items, status = live_fn()
        except Exception as ex:
            print(f"  {name} hard error: {ex}", file=sys.stderr)
            items, status = [], "error"
        if not items:  # fall back to seed so the card is never empty
            return {"items": seed.get(seed_key, []),
                    "status": "seed" if status in ("nokey", "error", "empty") else status,
                    "updated": seed.get("_seed_date", "sample")}
        return {"items": items, "status": status, "updated": NOW.strftime("%b %d, %Y %H:%M UTC")}

    data["sections"]["cisa"] = section("CISA ICS advisories", fetch_cisa_ics, "cisa")
    data["sections"]["cves"] = section("NVD ICS CVEs", fetch_nvd_ics, "cves")
    data["sections"]["iocs"] = section("ThreatFox OT IOCs", fetch_threatfox_ot, "iocs")
    data["sections"]["news"] = section("OT security news", fetch_news, "news")
    return data

# =============================================================================
# Render
# =============================================================================
def e(s):
    return html.escape(str(s if s is not None else ""))

def badge(status):
    m = {"live": ("● LIVE", "ok"), "seed": ("◆ SAMPLE", "warn"),
         "nokey": ("○ NO KEY", "muted"), "error": ("▲ STALE", "crit"),
         "empty": ("○ NONE", "muted")}
    label, cls = m.get(status, ("◆ SAMPLE", "warn"))
    return f'<span class="st st-{cls}">{label}</span>'

def sev_class(sev):
    return {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}.get((sev or "").upper(), "muted")

def render(data):
    S = data["sections"]

    def card_cisa(sec):
        rows = "".join(
            f'<li><a href="{e(i.get("link"))}" target="_blank" rel="noopener">{e(i.get("title"))}</a>'
            f'<span class="meta">{(" · "+e(i["vendor"])) if i.get("vendor") else ""}'
            f'{(" · "+e(i["date"])) if i.get("date") else ""}</span></li>'
            for i in sec["items"]) or '<li class="empty">No advisories.</li>'
        return card("CISA ICS Advisories", len(sec["items"]), sec, rows,
                    "Latest U.S. CISA industrial control system advisories.")

    def card_cves(sec):
        rows = "".join(
            f'<li><a href="{e(i.get("link"))}" target="_blank" rel="noopener">{e(i.get("id"))}</a> '
            f'<span class="sev sev-{sev_class(i.get("severity"))}">{e(i.get("severity") or "—")}'
            f'{(" "+str(i["score"])) if i.get("score") is not None else ""}</span>'
            f'<span class="desc">{e(i.get("desc"))}</span>'
            f'<span class="meta">{(" "+e(i["vendor"])) if i.get("vendor") else ""}</span></li>'
            for i in sec["items"]) or '<li class="empty">No recent CVEs.</li>'
        return card("ICS / OT Vulnerabilities", len(sec["items"]), sec, rows,
                    "Recent CVEs affecting industrial vendors (NVD).", wide=True)

    def card_iocs(sec):
        rows = "".join(
            f'<li><a href="{e(i.get("link"))}" target="_blank" rel="noopener"><code>{e(i.get("ioc"))}</code></a>'
            f'<span class="tag">{e(i.get("malware"))}</span>'
            f'<span class="meta">{(" · "+e(i["type"])) if i.get("type") else ""}</span></li>'
            for i in sec["items"]) or '<li class="empty">No OT-tagged IOCs (needs abuse.ch key).</li>'
        return card("OT-Tagged IOCs", len(sec["items"]), sec, rows,
                    "Indicators tied to ICS malware families (abuse.ch ThreatFox).")

    def card_news(sec):
        rows = "".join(
            f'<li><a href="{e(i.get("link"))}" target="_blank" rel="noopener">{e(i.get("title"))}</a>'
            f'<span class="meta">{e(i.get("src"))}{(" · "+e(i["date"])) if i.get("date") else ""}</span></li>'
            for i in sec["items"]) or '<li class="empty">No news.</li>'
        return card("Security News", len(sec["items"]), sec, rows,
                    "OT/ICS-relevant headlines.")

    def card_malware():
        rows = "".join(
            f'<li><b>{e(n)}</b> <span class="yr">{e(y)}</span>'
            f'<span class="tgt">{e(t)}</span><span class="desc">{e(d)}</span></li>'
            for (n, y, t, d) in ICS_MALWARE)
        return card("Industrial Malware Reference", len(ICS_MALWARE),
                    {"status": "ref", "updated": "curated"}, rows,
                    "Landmark ICS/OT malware and what each targeted.", wide=True, ref=True)

    def card_proto():
        rows = "".join(
            f'<li><code>{e(p)}</code> <b>{e(name)}</b><span class="desc">{e(note)}</span></li>'
            for (p, name, note) in ICS_PROTOCOLS)
        return card("ICS Protocol Exposure", len(ICS_PROTOCOLS),
                    {"status": "ref", "updated": "curated"}, rows,
                    "Industrial protocols and the ports that expose them.", ref=True)

    # order so the two narrow cards pair in a row before each wide card,
    # leaving no empty grid gaps
    cards = (card_cisa(S["cisa"]) + card_iocs(S["iocs"]) +
             card_cves(S["cves"]) + card_malware() +
             card_proto() + card_news(S["news"]))

    return PAGE.replace("{{GENERATED}}", e(data["generated"])).replace("{{CARDS}}", cards)

def card(title, count, sec, rows, sub, wide=False, ref=False):
    st = '<span class="st st-ref">◈ REFERENCE</span>' if ref else badge(sec.get("status"))
    upd = e(sec.get("updated", ""))
    return f'''
    <section class="card{' wide' if wide else ''}">
      <div class="ch">
        <div><h2>{e(title)}</h2><div class="csub">{e(sub)}</div></div>
        <div class="cmeta"><span class="cnt">{count}</span>{st}<span class="upd">Updated {upd}</span></div>
      </div>
      <ul class="rows">{rows}</ul>
    </section>'''

# ---- page shell (Tracelight visual family) ----------------------------------
PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>OT Threat Radar</title>
<meta name="description" content="Scheduled OT/ICS threat-intelligence dashboard — CISA ICS advisories, industrial-vendor CVEs, OT-tagged IOCs, and an industrial-malware reference.">
<style>
:root{
  --fire:linear-gradient(180deg,#FFE44D 0%,#FFB21C 32%,#FF7A1F 60%,#FF3B2F 84%,#E0261B 100%);
  --fire-x:linear-gradient(90deg,#FFE44D 0%,#FFB21C 30%,#FF7A1F 58%,#FF3B2F 82%,#E0261B 100%);
  --cyan:#3DE0FF; --lapis:#15317E; --lapis-text:#8FA8FF;
  --red:#FF2D3D; --warn:#FF9A3C; --ok:#35C08A;
  --ink:#ECE8DA; --ground:#06080E; --panel:#0C101A; --panel-2:#111623;
  --muted:#8A90A4; --line:#1C2334;
  --mono:ui-monospace,"SF Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
  --display:"Arial Black",system-ui,sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%}
body{background:radial-gradient(900px 500px at 0% 0%,rgba(21,49,126,.35),transparent 70%),radial-gradient(700px 500px at 100% 100%,rgba(61,224,255,.06),transparent 70%),var(--ground);color:var(--ink);font:15px/1.55 var(--sans)}
a{color:var(--lapis-text);text-decoration:none}
a:hover{color:var(--cyan)}
.wrap{max-width:1180px;margin:0 auto;padding:22px 18px 60px}
header.top{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:6px}
.brand{display:flex;align-items:center;gap:13px}
.mark{width:42px;height:42px;border-radius:11px;background:var(--fire);display:grid;place-items:center;color:#0A0A0A;box-shadow:0 0 22px -4px rgba(255,120,30,.6)}
.brand h1{margin:0;font:900 27px/1 var(--display);letter-spacing:.04em;text-transform:uppercase;background:var(--fire);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand small{display:block;font:500 11px/1.3 var(--mono);color:var(--muted);letter-spacing:.12em;text-transform:uppercase;margin-top:4px}
.gen{font:500 12px/1.4 var(--mono);color:var(--muted);text-align:right}
.gen b{color:var(--cyan)}
.ticker{margin:16px 0 22px;border:1px solid var(--line);border-radius:12px;background:linear-gradient(90deg,rgba(255,45,61,.08),transparent 60%);padding:11px 14px;font:600 11px/1.5 var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);display:flex;gap:22px;flex-wrap:wrap}
.ticker b{color:var(--ink)}
.ticker .live::before{content:"● ";color:var(--red)}
.grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.card{border:1px solid var(--line);border-radius:14px;background:var(--panel);padding:16px 16px 10px;overflow:hidden}
.card.wide{grid-column:1 / -1}
@media (max-width:820px){.grid{grid-template-columns:1fr}.card.wide{grid-column:auto}}
.ch{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;border-bottom:1px solid var(--line);padding-bottom:11px;margin-bottom:6px}
.ch h2{margin:0;font:700 15px/1.2 var(--sans)}
.csub{font:500 12px/1.4 var(--mono);color:var(--muted);margin-top:3px}
.cmeta{display:flex;align-items:center;gap:9px;flex-shrink:0;flex-wrap:wrap;justify-content:flex-end}
.cnt{font:800 18px/1 var(--display);color:var(--cyan)}
.upd{font:500 10px/1 var(--mono);color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.st{font:700 10px/1 var(--mono);letter-spacing:.05em;padding:4px 7px;border-radius:6px;border:1px solid var(--line);white-space:nowrap}
.st-ok{color:var(--ok);border-color:rgba(53,192,138,.4)}
.st-warn{color:var(--warn);border-color:rgba(255,154,60,.4)}
.st-crit{color:var(--red);border-color:rgba(255,45,61,.4)}
.st-muted{color:var(--muted)}
.st-ref{color:var(--cyan);border-color:rgba(61,224,255,.35)}
ul.rows{list-style:none;margin:0;padding:6px 0}
ul.rows li{padding:9px 2px;border-bottom:1px solid rgba(28,35,52,.6);font-size:13.5px}
ul.rows li:last-child{border-bottom:none}
ul.rows li.empty{color:var(--muted);font-family:var(--mono);font-size:12px}
.rows .meta{color:var(--muted);font:500 11px/1 var(--mono)}
.rows .desc{display:block;color:#C4C8D4;font-size:12.5px;margin-top:3px}
.rows .tag{display:inline-block;margin-left:7px;font:600 10px/1 var(--mono);color:var(--warn);text-transform:uppercase;letter-spacing:.04em}
.rows code{font-family:var(--mono);font-size:12px;color:var(--ink);background:var(--panel-2);padding:2px 6px;border-radius:5px;border:1px solid var(--line)}
.rows .yr{color:var(--muted);font:600 11px var(--mono);margin-left:6px}
.rows .tgt{display:block;color:var(--lapis-text);font:600 11px/1.4 var(--mono);margin-top:2px}
.sev{font:700 10px/1 var(--mono);padding:3px 6px;border-radius:5px;margin-left:4px}
.sev-crit{color:#fff;background:var(--red)}
.sev-high{color:#1A0A00;background:var(--warn)}
.sev-med{color:var(--ink);background:#3A3A42}
.sev-low{color:var(--muted);border:1px solid var(--line)}
.sev-muted{color:var(--muted)}
footer{margin-top:30px;border-top:1px solid var(--line);padding-top:16px;font:500 12px/1.6 var(--mono);color:var(--muted)}
footer b{color:var(--ink)}
footer .note{margin-top:8px;color:var(--muted)}
</style></head>
<body><div class="wrap">
  <header class="top">
    <div class="brand">
      <div class="mark" aria-hidden="true"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M12 12l6-3M12 3v3M12 18v3M3 12h3M18 12h3"/></svg></div>
      <div><h1>OT Threat Radar</h1><small>Industrial threat intelligence · refreshed on schedule</small></div>
    </div>
    <div class="gen">Dashboard generated<br><b>{{GENERATED}}</b></div>
  </header>
  <div class="ticker">
    <span class="live">CISA ICS advisories</span>
    <span>Industrial-vendor CVEs</span>
    <span>OT-tagged IOCs</span>
    <span>ICS malware reference</span>
    <span>Protocol exposure</span>
  </div>
  <div class="grid">{{CARDS}}</div>
  <footer>
    <b>OT Threat Radar</b> — a static dashboard rebuilt on a schedule from free public sources:
    CISA ICS Advisories, NVD, abuse.ch ThreatFox, and public security RSS. Reference sections are curated.
    For defensive, educational use. Verify every indicator against its primary source before acting.
    <div class="note">Sources update independently; a card marked ▲ STALE or ◆ SAMPLE means that feed
    hasn't refreshed (often a missing API key) — the rest of the page is still current.</div>
  </footer>
</div></body></html>"""

# =============================================================================
if __name__ == "__main__":
    data = gather()
    out = render(data)
    path = os.path.join(HERE, "index.html")
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"Wrote {path} ({len(out)} bytes) — mode={'offline' if OFFLINE or requests is None else 'live'}")

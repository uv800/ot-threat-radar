# OT Threat Radar

A **static OT/ICS threat-intelligence dashboard** that rebuilds itself on a schedule.
It is the scheduled-aggregation counterpart to a live-lookup OSINT tool: instead of
querying when a user types, a cron job pulls fresh data, ranks it, and bakes it into a
single static `index.html` served from GitHub Pages. No backend, no database, no cost.

## What it shows

| Section | Source | Live? |
|---|---|---|
| **CISA ICS Advisories** | CISA RSS | ✅ no key |
| **ICS / OT Vulnerabilities** | NVD CVE API, filtered to industrial vendors | ✅ no key (optional `NVD_API_KEY` for rate limit) |
| **OT-Tagged IOCs** | abuse.ch ThreatFox, filtered to ICS malware families | ⚙️ needs free `ABUSE_CH_API_KEY` |
| **Security News** | public security RSS | ✅ no key |
| **Industrial Malware Reference** | curated (Stuxnet → FrostyGoop) | 📘 always on |
| **ICS Protocol Exposure** | curated (Modbus, S7, DNP3 …) | 📘 always on |

Every live section shows its own **status badge** and **"Updated"** time, so if one feed
stalls (e.g. an expired key) it reads `▲ STALE` or `◆ SAMPLE` while the rest stays current.

## How it works

```
GitHub Action (cron)  →  build.py  →  fetch sources + curated layer  →  render index.html  →  GitHub Pages
```

`build.py` has two modes:
- `python build.py` — **live fetch** (what the Action runs). Any source that fails falls back to the seed so no card is ever empty.
- `python build.py --offline` — renders entirely from `seed_data.json`, no network. Used to produce the first page before deployment.

## Deploy (GitHub Pages — free)

1. Create a new GitHub repo and push these files.
2. In the repo: **Settings → Pages → Build and deployment → Source: GitHub Actions**.
3. (Optional) add API keys for the gated sources:
   **Settings → Secrets and variables → Actions → New repository secret**
   - `ABUSE_CH_API_KEY` — free from https://auth.abuse.ch (enables the IOC section)
   - `NVD_API_KEY` — free from https://nvd.nist.gov/developers/request-an-api-key (higher rate limit)
4. Go to the **Actions** tab → run **Build OT Threat Radar** once (or wait for the daily cron).
5. Your dashboard is live at `https://YOUR_USERNAME.github.io/REPO_NAME/`.

Prefer Netlify or Cloudflare Pages? Point it at the repo and set the build command to
`pip install -r requirements.txt && python build.py` with publish directory `.` — or just
drag the generated `index.html` onto Netlify Drop for a no-build version.

## Customize

- **Schedule** — edit the `cron` line in `.github/workflows/build.yml`.
- **Vendors watched** — edit `ICS_VENDORS` in `build.py`.
- **Malware / protocol reference** — edit `ICS_MALWARE` and `ICS_PROTOCOLS` in `build.py`.
- **Branding** — the page uses an inline theme at the bottom of `build.py`; change the title,
  colors, and the `YOUR_USERNAME` placeholders.

## Scope & ethics

Defensive and educational. It aggregates **already-public** advisories, CVEs, and indicators
and links back to each primary source. It does **not** scan, enumerate, or target anyone's
infrastructure. Verify every indicator against its source before acting on it.

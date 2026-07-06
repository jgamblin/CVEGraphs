# Graph backlog

Idea bank for the social engine. Status: ✅ built · 🔨 next · 💡 idea.
Tiers: **Evergreen** (re-render on cadence) · **Rotating** (topic changes) ·
**Novelty** (occasional, high-share). Full rationale in `../PLAN.md`.

## Evergreen (weekly workhorses)
- ✅ **pace** — YTD CVEs by year, apples-to-apples, "one every N minutes" hook
- ✅ **kev** — monthly KEV additions (trailing 12mo), ransomware-linked highlighted
- ✅ **cna** — top CNA issuers year-to-date leaderboard
- 💡 **forecast** — 2026 run-rate vs CVEForecast projection
- 💡 **severity** — critical/high/med/low mix of the trailing window

## EPSS (predicted exploitation) — pairs with the KEV thesis
Data: `processed/epss.parquet`; join with `data.load_nvd(with_epss=True)`.
- ✅ **epss_funnel** — exploitation signal: all CVEs vs EPSS ≥ 0.1 / on KEV /
  EPSS ≥ 0.5. One image showing predicted-rare AND confirmed-rare. Strong evergreen.
- 💡 **epss_vs_kev** — EPSS distribution of KEV vs non-KEV CVEs: does the model
  score the truly-exploited ones higher?
- 💡 **high_epss_board** — the highest-EPSS CVEs published this period (a watchlist).
- 💡 **cvss_epss_gap** — high CVSS but low EPSS: severe on paper, unlikely to be
  exploited. The prioritization reframe in one scatter.

## Rotating deep-dives
- 💡 **cwe** — weakness class of the week (trend + top examples)
- 💡 **vendor** — one vendor's count + YoY, rotating the top 20
- 💡 **product** — hot target spotlight (e.g. OpenClaw tracker)
- 💡 **rhythm** — day-of-week / hour publishing heatmap ("Patch Wednesday")
- 💡 **time_to_kev** — days from publication to KEV listing
- 💡 **cvss_drift** — average/median CVSS over years
- 💡 **us_vs_world** — who *publishes* the world's CVEs (July 4 post)
- 💡 **reserved_gap** — reserved-but-unpublished ID backlog
- 💡 **id_burn** — annual CVE ID block consumption rate

## Themed / one-off (reusable as data updates)
- ✅ **chrome_day** — "Out with Patch Tuesday, in with Chrome Day": monthly
  biggest-single-day head-to-head, Microsoft vs Chrome CNA. Caption in
  `captions/chrome_day.md`.

## Novelty formats
- 💡 **cna_race** — animated bar-chart-race GIF of top CNAs over time
- 💡 **calendar** — GitHub-style daily-publishing heatmap grid
- 💡 **streamgraph** — severity composition month over month
- 💡 **woke_up** — "since you woke up" real-time-ish stat card
- 💡 **milestone** — auto-fire cards on round numbers (350,000th CVE, etc.)

## Adding a chart
1. Create `charts/<name>.py` exposing `render(nvd=None, ratios=DEFAULT_RATIOS)`
   that returns the written paths (copy `charts/pace.py` as the template).
2. Register it in `make.py` `CHARTS`.
3. Add a caption template in `content/captions/<name>.md`.
4. Slot it into `content/CALENDAR.md`.

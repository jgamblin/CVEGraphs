# CVEGraphs — Social Media Graph Engine

A plan to turn the one-shot `H12026CVEBlog` pipeline into a **repeatable engine**
that ships unique, interesting CVE graphs to social media a few times a week.

## The core idea

`H12026CVEBlog` was built for a single event: one mid-year blog launch, milked
into ~6 days of drip posts (`CAMPAIGN.md`). That machinery — data download,
parquet cache, `style_config.py`, ~18 chart functions — is 80% of what we need.
The missing 20% is **making it evergreen**: a refreshable data snapshot, a
library of standalone social-sized charts, a rotating content backlog, and a
lightweight publishing rhythm.

Goal: **2–3 graphs/week, indefinitely, each self-contained** (no blog required),
each with a strong single-stat hook and a caption ready to paste.

---

## Architecture

Reuse, don't rebuild. `CVEGraphs` becomes the output engine; it borrows the
proven pieces from `H12026CVEBlog`.

```
CVEGraphs/
  refresh_data.py        # weekly: pull NVD + CVEList + KEV + CVEForecast -> parquet
  style_social.py        # style_config.py, retuned for square/mobile-first social
  charts/                # one module per chart type, each renders a social PNG
    pace.py  kev.py  cna.py  cwe.py  vendor.py  product.py  calendar.py ...
  make.py                # `python make.py kev` -> renders graphs/kev_2026-07-05.png
  content/
    BACKLOG.md           # the idea bank (what to build), tagged evergreen/rotating
    CALENDAR.md          # rolling schedule of what posts when
    captions/            # per-chart caption + alt-text templates
  graphs/                # dated output PNGs, gitignored except samples
```

**Key differences from the blog charts**

| Blog charts | Social charts |
|---|---|
| 12×6 landscape | 1080×1080 square (IG/LI) + 1600×900 (X) variants |
| Small fonts, dense | Big fonts, one idea, mobile-legible |
| Titles as chart titles | Title = the takeaway ("One CVE every 7.4 min") |
| `@jgamblin` watermark | Watermark + date stamp + rogolabs.net |
| Rendered in a batch | Rendered on demand, one at a time |

---

## What to build — the graph backlog

Three tiers. Evergreen = same chart re-rendered on a cadence (numbers move).
Rotating = a deep-dive that changes topic each time. Novelty = eye-catching
formats to break the feed.

### Tier 1 — Evergreen recurring (the reliable weekly beats)

1. **YTD Pace Tracker** — running 2026 total vs same-day-last-year, with the
   "one every X minutes / N per day" hook. *The workhorse; post weekly.*
2. **KEV Watch** — CVEs added to CISA KEV this week/month, ransomware-linked
   flagged. Leads with exploitation, not volume (your thesis).
3. **CNA Leaderboard** — top issuers this month with ▲▼ movement vs last month.
4. **Forecast Scorecard** — 2026 actual run-rate vs CVEForecast's projection,
   updated as the year fills in (your public flag: "I say ~72k, model says 90k").
5. **Severity Mix** — critical/high/med/low split of the current period.

### Tier 2 — Rotating deep-dives (fresh topic each post)

6. **CWE of the Week** — spotlight one weakness class, its trend, top examples.
7. **Vendor Spotlight** — one vendor's CVE count + YoY, rotating through the top 20.
8. **Product Spotlight** — e.g. the OpenClaw tracker; hot new targets.
9. **Publishing Rhythm** — day-of-week / hour-of-day heatmap (the "Patch
   Wednesday, not Tuesday" myth-buster).
10. **Time-to-KEV** — how fast (days) CVEs land on KEV after publication.
11. **CVSS Drift** — average/median CVSS over years; is severity inflating?
12. **US vs World CNAs** — who *publishes* the world's CVEs (your July 4 post).
13. **Reserved vs Published gap** — the backlog of reserved-but-unpublished IDs.
14. **First-time CNAs** — new orgs that started issuing CVEs this quarter.
15. **CVE ID block burn** — how fast the annual ID range is being consumed.

### Tier 3 — Novelty formats (occasional, high-share)

16. **Bar-chart race GIF** — top CNAs over time, animated (you already ship GIFs).
17. **Calendar heatmap** — GitHub-style daily-publishing grid for the year.
18. **Streamgraph** — severity composition flowing month over month.
19. **"Since you woke up" stat card** — real-time-ish counter, very screenshot-able.
20. **Milestone cards** — auto-fire when a round number hits (350,000th CVE,
    40k in H1, etc.).

---

## Cadence & workflow (how to make it sustainable)

The failure mode is manual effort per post. Kill it with automation + a queue.

1. **Weekly data refresh** (Mon AM, cron/scheduled task): `refresh_data.py`
   pulls fresh NVD/KEV/CVEForecast into parquet. Everything else reads the cache.
2. **Batch-render on refresh**: `make.py all` renders the whole current backlog
   into `graphs/` with today's date. You now have a *shelf* of ready images.
3. **Post from the shelf** 2–3×/week per `content/CALENDAR.md`. Caption + alt
   text already drafted in `content/captions/`. Copy, attach, post.
4. **Milestone triggers**: refresh script checks thresholds and flags "post me"
   when a milestone chart is worth firing off-schedule.

Rough weekly rotation:
- **Mon** — Pace Tracker (evergreen, always fresh)
- **Wed** — a Tier-2 rotating deep-dive
- **Fri** — KEV Watch or a Tier-3 novelty piece

That's 3/week with only one genuinely new idea to write each week.

---

## Build phases

- **Phase 0 — Lift the engine.** Copy `01/02_*` data steps + `style_config.py`
  into `CVEGraphs`; strip out blog-specific coupling. Confirm parquet loads.
- **Phase 1 — Social style.** Fork `style_config.py` → `style_social.py`: square
  canvas, big fonts, takeaway-as-title, date stamp + handle + rogolabs.net.
- **Phase 2 — Chart library.** Port the 5 evergreen charts first (they reuse
  existing functions almost verbatim), then add rotating/novelty over time.
- **Phase 3 — `make.py` CLI + content calendar.** `python make.py <chart>` and
  `make.py all`; seed `BACKLOG.md` / `CALENDAR.md` / caption templates.
- **Phase 4 — Automate.** Scheduled weekly refresh + batch render + milestone
  checks. Optional: auto-draft captions with the numbers filled in.

---

## Decisions (locked 2026-07-05)

1. **Platforms & sizes** — the blog's 4 (LinkedIn, X, Mastodon, Bluesky) **plus
   Instagram**. Generate three aspect ratios per chart: **1:1 square (1080×1080)**,
   **16:9 (1600×900)** for X, and **4:5 portrait (1080×1350)** for IG/LinkedIn feed.
2. **Data window** — **rolling / YTD as of today.** Numbers always current
   ("2026 YTD", "KEV added last 30 days"). Nothing goes stale.
3. **Automation depth** — **render the shelf, Jerry posts manually.** Weekly
   refresh + batch render; human reviews and posts. (Caption auto-draft is a
   later optional add.)
4. **Repo** — build inside `CVEGraphs`; `H12026CVEBlog` is read-only proven source.

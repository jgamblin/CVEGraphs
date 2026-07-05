# CVEGraphs

CVE graphs to share on social media, a few times a week.

An evergreen engine that renders unique, self-contained CVE charts sized for the
feed. It reuses the proven data pipeline and design language from
[H12026CVEBlog](../H12026CVEBlog) but is built to run *continuously* rather than
for a single blog launch. See [PLAN.md](PLAN.md) for the full strategy.

## Quick start

```bash
pip install -r requirements.txt

python refresh_data.py     # populate ./processed (weekly)
python make.py list        # show available charts
python make.py pace        # render one chart, all aspect ratios
python make.py all         # render the whole shelf into ./graphs
```

Each chart renders three aspect ratios into `graphs/`:
**square** (1080×1080, LinkedIn/X/Mastodon/Bluesky/IG), **portrait** (1080×1350,
IG + LinkedIn feed), and **wide** (1600×900, X landscape).

## How it fits together

| File | Role |
|------|------|
| `refresh_data.py` | Weekly: pull fresh data into `processed/` |
| `data.py` | Load the NVD / CVE List parquet snapshots |
| `rolling_config.py` | Rolling "as of today" window + YTD comparison helpers |
| `style_social.py` | Social styling: ratios, big fonts, handle/date/site stamp |
| `charts/*.py` | One module per chart; each exposes `render()` |
| `make.py` | CLI: render one chart, `all`, or `list` |
| `insights.py` | Mine + score share-worthy findings -> ranked brief |
| `run_weekly.sh` | One-shot pipeline: refresh + insights + render |
| `deploy/` | launchd agent + install steps for the weekly schedule |
| `content/` | `BACKLOG.md`, `CALENDAR.md`, `INSIGHTS.md`, `captions/` |

## Workflow

1. `refresh_data.py` (Mon AM, ideally scheduled) refreshes the data snapshot.
2. `insights.py` mines a ranked brief of share-worthy findings.
3. Curate the top few into posts (Claude + `content/INSIGHTS.md`), pairing each
   with its `suggested_chart`.
4. `make.py <chart>` (or `all`) renders the shelf with today's date in filenames.
5. Post 2–3×/week per `content/CALENDAR.md`.

See `content/INSIGHTS.md` for the discovery-to-post pipeline (code extracts and
scores; Claude curates and writes).

### Automate it

`run_weekly.sh` chains steps 1–2–4 (refresh → insights → render) and leaves a
ranked brief at `content/insights_latest.md`. To run it every Monday, install the
launchd agent per `deploy/README.md` (a one-time manual step, since it schedules
code beyond a single session). Curation and posting stay in your hands.

## Status

Phase 0–1 complete: rolling data layer, social style, the **Pace Tracker** and
**EPSS Funnel** charts, an insight miner (`insights.py`), and a weekly runner
(`run_weekly.sh` + `deploy/`). `refresh_data.py` is now **self-contained** — it rebuilds
the parquet from upstream feeds (NVD, CVE List V5, CISA KEV, CVEForecast, and
production EPSS V5 scores) with no dependency on any sibling repo. EPSS is available via
`data.load_nvd(with_epss=True)` or `data.load_epss()`. Next up per
`content/BACKLOG.md`: the KEV Watch, CNA Leaderboard, and EPSS funnel charts.

Built on free CVE tooling from [RogoLabs](https://rogolabs.net).

# CVEGraphs

The engine behind **CVE Insights**: standalone, feed-sized CVE charts posted to
LinkedIn (and X, Bluesky, Mastodon) about twice a week. It keeps its own local
snapshot of NVD, CVE List V5, CISA KEV, EPSS and a few smaller feeds, and
renders each chart in three aspect ratios with a post-ready text file next to it.

Every post is a one-off: a chart is built for a finding, reviewed, posted, and
then frozen with the exact images and text that went out.

## Setup

Python 3.12+ and pip.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt -e .
cvegraphs refresh          # first run downloads ~7 GB into data/ and builds processed/
```

`requirements.txt` pins the exact versions the golden renders were made with;
`pyproject.toml` holds the looser ranges. Recording the cvenado video also needs
`pip install -e ".[media]"`, `playwright install chromium` and ffmpeg.

## Making a post

```bash
cvegraphs refresh --feeds-only            # or a full `cvegraphs refresh` if it has been a week
cvegraphs render kev_weekend              # -> content/drafts/kev_weekend/*.png
$EDITOR content/drafts/kev_weekend/post.md   # the copy lives next to the images
#   ask Claude: "run the post-review workflow on kev_weekend"
CVEGRAPHS_POST_DATE=2026-10-13 cvegraphs render kev_weekend   # stamp the day it goes out
cvegraphs publish kev_weekend --link https://www.linkedin.com/...
#   -> content/posts/2026-10-13-kev_weekend/, then log it in content/planning/CALENDAR.md
```

`cvegraphs list` shows every chart with a one-line description.

## Commands

| Command | What it does |
|---|---|
| `cvegraphs list` | Every renderable chart, media item and paper |
| `cvegraphs render <name ...>` | Render into `content/drafts/<name>/` (older renders move to `superseded/`) |
| `cvegraphs render all` | The whole shelf; a failing chart is reported, not fatal |
| `cvegraphs publish <name>` | Move a draft to `content/posts/<date>-<name>/` with front matter (chart, date, data as-of, commit) |
| `cvegraphs refresh` | Download + parse upstream data, then run every precompute step |
| `cvegraphs refresh --feeds-only` | Just KEV, EUVD, forecast, EPSS and CWE (fast) |
| `cvegraphs precompute [name ...]` | Rerun derived datasets in `processed/` |
| `cvegraphs insights --top 15` | Mine a ranked brief of candidate findings into `content/insights/` |

`cvegraphs pace` (no verb) still means `render pace`.

## Layout

```
src/cvegraphs/        the code (see src/cvegraphs/README.md)
  charts/             one module per chart
  precompute/         derived datasets built after a refresh
  data/               loaders + the refresh (nvd, cvelist, feeds)
  media/ papers/      the CVE tornado page and long-form HTML reports
content/              everything produced or written for posting (see content/README.md)
  drafts/<chart>/     post.md + renders not yet posted
  posts/<date>-<chart>/   frozen once it goes out
  planning/           BACKLOG, CALENDAR (posting log), INSIGHTS (copy rules)
  insights/           the mined insight brief
docs/                 data rules, adding a chart, history
ops/                  weekly launchd job (refresh, insights, render all)
tests/                pytest suite + golden-render check
data/ processed/      raw clones and parquet snapshot (gitignored, local only)
```

## Checks

```bash
ruff check src tests
pytest                               # snapshot tests skip when processed/ is absent
python tests/golden_render.py        # pixel-compare every chart against logs/golden/
```

CI (`.github/workflows/ci.yml`) runs lint and the tests that need no data. The
refresh and rendering run only on this machine; see `ops/README.md` for the
weekly schedule.

## Reading the data correctly

Several fields measure process rather than reality (KEV date granularity, MITRE
timestamps, NVD Deferred status, CISA-ADP scores echoing the CNA, and more).
Read [docs/data-rules.md](docs/data-rules.md) before building a chart on a new
field.

Built on free CVE tooling from [RogoLabs](https://rogolabs.net).

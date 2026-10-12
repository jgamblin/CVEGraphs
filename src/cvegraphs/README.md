# cvegraphs package

| Module | Role |
|---|---|
| `cli.py` | The `cvegraphs` command (list, render, publish, refresh, precompute, insights) |
| `registry.py` | Finds every renderable (anything with `DESCRIPTION` + `render()`) and renders into a draft folder |
| `paths.py` | Every location the project reads or writes; the per-render `OUTPUT` target |
| `rolling.py` | "As of today" window: `today_utc` (honors `CVEGRAPHS_POST_DATE`), `data_asof`, `ytd_mask` |
| `style.py` | Social chart style: ratios, fonts, header, stamp-and-save |
| `insights.py` | Mines and scores share-worthy findings into `content/insights/` |
| `charts/` | One module per chart (see docs/adding-a-chart.md) |
| `precompute/` | Derived datasets built after a refresh; ordered in `precompute/__init__.py` |
| `data/load.py` | `load_nvd`, `load_cvelist`, `load_epss` from `processed/` |
| `data/refresh/` | The refresh: `nvd.py`, `cvelist.py`, `feeds.py` (KEV, EUVD, forecast, EPSS, CWE), `common.py` |
| `media/cvenado/` | The CVE tornado web page (`build.py`) and its MP4/GIF recorder (`record.py`) |
| `papers/short_lived_cves/` | The short-lived CVEs HTML paper and its backtest |
| `fonts/` | Bundled Host Grotesk + Roboto |

Data flows one way: `data/refresh` writes `processed/`, `precompute` adds derived
files to `processed/`, and charts read `processed/` and write `content/drafts/`.

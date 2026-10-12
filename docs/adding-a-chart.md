# Adding a chart

A chart is one module in `src/cvegraphs/charts/`. Create the file and it is
registered automatically: `cvegraphs list` shows it, `cvegraphs render <name>`
draws it, and the tests check that it follows the contract.

## The contract

```python
"""
<Title>: one paragraph on what the chart shows and why.

Data: which processed/ file(s) it reads, and any rule from docs/data-rules.md it applies.
"""

import matplotlib.pyplot as plt
import pandas as pd

from cvegraphs.data import load_cvelist
from cvegraphs.paths import OUTPUT, PROCESSED
from cvegraphs.rolling import data_asof
from cvegraphs.style import COLORS, DEFAULT_RATIOS, draw_header, figsize_for, stamp_and_save

DESCRIPTION = "Bars: one line for `cvegraphs list`, form first"


def render(nvd=None, ratios=DEFAULT_RATIOS):
    """Draw every ratio; return the paths written. ``nvd`` is the shared NVD frame
    the CLI loads once per run; ignore it if the chart reads something else."""
    df = load_cvelist()
    asof = data_asof(df)
    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        ...
        draw_header(fig, "Factual Title Saying What Is Shown", "One-line subtitle.", ratio=ratio)
        path = OUTPUT / f"my_chart_{ratio}_{asof:%Y-%m-%d}.png"
        out.append(stamp_and_save(fig, path))
    return out
```

- **The file name is the chart name** and also its draft folder,
  `content/drafts/<name>/`.
- **Write output through `OUTPUT`** (or `GRAPHS = OUTPUT`, as the older charts do).
  It points at whatever folder the caller is rendering into, so never build a
  path to the repo yourself.
- **Read inputs through `PROCESSED` / `DATA`** from `cvegraphs.paths`.
- **Save through `stamp_and_save`.** It adds the handle, site and post-date stamp,
  and makes the date in the filename match the stamp.
- **Name files `<name>_<ratio>_<YYYY-MM-DD>.png`.** Later renders then move earlier
  ones into `superseded/` instead of piling up next to them.
- **Don't do work at import time.** CI imports every chart without any data.

## Data the chart needs that does not exist yet

If the chart needs a scan of the raw clones or a slow fetch, put that in
`src/cvegraphs/precompute/<name>.py` with a `main()` that writes to `PROCESSED`.
Add it to `STEPS` in `precompute/__init__.py`: `after="parse"` if it only reads
`data/`, `after="feeds"` if it needs `kev_catalog.json`. Run it once with
`cvegraphs precompute <name>`. After that, every `cvegraphs refresh` keeps it current.

## Before posting

1. `cvegraphs render <name>` and look at all three ratios.
2. Write the copy in `content/drafts/<name>/post.md`. House rules are in
   `content/planning/INSIGHTS.md`.
3. Run the post-review workflow (see `.claude/workflows/README.md`).
4. `pytest` (the smoke test renders the new chart), then commit.
5. Once it is live: `cvegraphs publish <name> --link <url>`, and log it in
   `content/planning/CALENDAR.md`.

## Non-chart output

The CVE tornado (`media/cvenado/`) and the short-lived CVEs paper
(`papers/short_lived_cves/`) are subpackages. Their `__init__.py` exposes
`DESCRIPTION` and `render()` the same way, so they render into drafts like any chart.

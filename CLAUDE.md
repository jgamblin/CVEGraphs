# CVEGraphs: notes for Claude

Jerry Gamblin's CVE Insights chart engine. Read README.md for commands and layout.

## Working rules

- **Environment:** `.venv` with pip (`pip install -r requirements-dev.txt -e .`). No uv.
  The global pip config forces `--user`; inside the venv use `PIP_USER=0`.
- **Run things through the CLI:** `.venv/bin/cvegraphs render <chart>`, not by
  importing chart modules by hand. Output goes to `content/drafts/<chart>/`.
- **Never edit `content/posts/`.** Those folders are what went out. To revisit
  a chart, render a new draft.
- **Refactors:** run `python tests/golden_render.py` before and after. It must
  print MATCH. Don't run `cvegraphs refresh` partway through a refactor; the
  baseline is tied to the current `processed/` snapshot.
- **Before claiming a number:** check docs/data-rules.md (KEV date granularity,
  MITRE timestamps, NVD Deferred, ADP echo, CNA-composition confound, and more).
- **Copy and charts:** the rules are in `content/planning/INSIGHTS.md` (opinion-first
  hook, no em dashes, no "n=", factual chart titles, one footnote) and the cadence
  is in `content/planning/CALENDAR.md` (2 posts a week). Run the post-review
  workflow before anything is published.
- **Lint and tests:** `ruff check src tests` and `pytest` before committing.

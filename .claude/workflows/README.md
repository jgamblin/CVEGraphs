# Review workflows

## post-review

A pre-publish critical review of a chart post: it verifies the data, pressure-tests
the copy, critiques the rendered graph as an image, and returns an editor-in-chief
go/no-go verdict with prioritized, concretely-worded fixes.

### How to run
Ask Claude: **"run the post-review workflow on `<chart>`"** (e.g. `product_id`).
Claude invokes it with:

```
Workflow({ scriptPath: ".claude/workflows/post-review.js", args: "<chart>" })
```

`args` is the chart name: the stem shared by `src/cvegraphs/charts/<name>.py` and the draft
folder `content/drafts/<name>/` (which holds `post.md` and the `<name>_wide_*.png` renders).
Render the chart first (`cvegraphs render <name>`) so a current PNG exists for the visual
reviewers. A chart that already went out is read from `content/posts/<date>-<name>/` instead.

### The panel (9 agents)
1. **Prep** — reads the caption + module, finds the newest wide PNG, extracts the
   LinkedIn/X copy and every load-bearing numeric claim.

Copy + data:
2. **factcheck** — independently recomputes every claim from source (data.py, KEV
   catalog, parquet, raw CVE List). A correct number is not a finding.
3. **domain-skeptic** — overclaims, causation-as-correlation, survivorship bias.
4. **brand-editor** — house style (no em dashes, no "n=", ~3 tight paragraphs, ends
   on a question, blue/grey palette), voice, hype.
5. **consistency** — reads `content/planning/CALENDAR.md` to catch repeats, over-stacked
   themes, and contradictions with earlier posts.

Visual (these open and look at the PNG):
6. **dataviz-craft** — Tufte lens: honest encoding, axes, bubble-area scaling, chart
   choice, sorting.
7. **legibility-design** — typography, hierarchy, label collisions, alignment,
   spacing, "does it look professionally made."
8. **color-accessibility** — color-blind safety, contrast, grayscale legibility,
   palette consistency, justified red.

9. **editor-in-chief** — dedupes, dismisses reviewer overreach, and returns a COPY
   verdict (POST AS-IS / WITH FIXES / REWORK) and a GRAPH verdict (SHIP AS-IS / FIX
   FIRST / REWORK), each with an exact-wording fix list.

### Tuning
Personas are a plain list in the script; add or drop lenses as needed. To iterate,
edit `post-review.js` and re-run with the same `scriptPath`.

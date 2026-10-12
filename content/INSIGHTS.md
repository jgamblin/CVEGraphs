# Finding what to post — the discovery pipeline

The hardest part of posting a few times a week is deciding *what* is worth
posting. This is a hybrid: **code extracts and scores**, **Claude curates and
writes**. The LLM never crunches raw rows, only judges and phrases a short
ranked list.

## 1. Code: mine + score (deterministic)

```bash
python insights.py            # ranked brief -> content/insights_brief.md + insights.json
python insights.py --top 20   # widen the candidate list
```

`insights.py` scans several dimensions and scores each finding for
share-worthiness (records/flips and exploitation rank highest):

| Category | Looks for |
|----------|-----------|
| `record` | YTD beating prior full years, busiest month ever, milestones |
| `exploitation` | KEV share, EPSS funnel, highest-EPSS CVE not yet on KEV |
| `kev` | recent KEV additions, ransomware-linked |
| `mover` | top CNA, month-over-month issuer surges |
| `pace` | run-rate, "one every N minutes", projected year-end |
| `curio` | busiest weekday (Patch-Wednesday), biggest single day |

Each finding carries a `headline`, `detail`, `score`, `evidence` (the raw
numbers), and a `suggested_chart` that pairs with it in `BACKLOG.md`.

## 2. Claude: curate + write (editorial)

Hand the brief to Claude to do what a threshold can't, novelty judgment and
voice:

> Read `content/insights.json`. Pick the 3 most genuinely surprising and
> share-worthy findings for this week (avoid repeating last week's angles in
> `CALENDAR.md`). For each, draft a LinkedIn + X + Bluesky post following the
> **Copy formula** below: open on a one-sentence arguable claim (not a stat),
> put the load-bearing number in line two, no em dashes, no "n=" (spell it out,
> e.g. "373 CVEs"), end on a genuine question. Note the `suggested_chart` to attach.

House style for the **chart itself**: the heading is factual and descriptive,
it states what the chart shows ("How 2026 CVEs Identify the Affected Product"),
never an argument or verdict ("Enrichment nearly halves the no-ID pile"). The
heading AND the chart labels (axis / category / bucket / legend labels) are in
**Title Case** (keep acronyms as-is: CVE, CPE, PURL, NVD, CISA). Only the
subtitle and footnote stay sentence case (they are full sentences). The angle,
the opinion, and the story live in the post copy, not the chart.

**Text budget on the chart (Jerry, 2026-09-08, stated twice): ONE footnote per
chart, maximum, and it fits on one line at every ratio.** The subtitle is one
line too. Jerry's words: "Once again there is way too much text on the graph."
The failure mode this corrects is stacking method disclosure, baseline
comparisons and caveats into a four-line footnote block: it squeezes the plot,
nobody reads it in a feed, and it reads as hedging. What goes where:

| Belongs on the chart | Belongs in the caption / post copy |
|---|---|
| Factual Title-Case heading | The argument and the opinion |
| One-line subtitle saying what a bar is | Baseline comparisons and rates |
| Value labels on the bars that carry the finding | CWE/CPE set definitions, exclusions, thresholds |
| One short callout naming the finding | Severity or robustness checks |
| One footnote: source and as-of date | Every caveat, and the numbers for comments |

Do not read this as licence to drop the rigor. The disclosure still has to
exist, in `content/captions/<chart>.md`, and the load-bearing caveats still have
to survive into the post copy. Charts that need a derived figure available for
the copy should expose it in code (see `charts/patch_tuesday.py:stats()`) rather
than printing it on the image.

**Date stamp:** always stamp the chart with the date it is posted (the render
date, `today_utc()`), never the data-source date (KEV release, data refresh).
Data provenance goes in the footnote / Source line, not the corner stamp.

### Copy formula (the post text) — highest-leverage lever on reach

From the Jul 2026 engagement pull: opinion-first posts pulled 2,000-3,500
impressions with 8-17 comments; number-first posts pulled about half and near-zero
comments. So:

1. **Line one is a one-sentence opinion, not a statistic.** The opener must be an
   arguable claim a reasonable person could disagree with. A fact can only be read;
   a claim can be argued, and argument is what drives comments and reposts.
   - Gut check: could someone reply "no it isn't"? If not, it's a stat, not a hook.
   - Winners led with a stance: "A CVSS score is not a fact about a bug. It's an
     opinion with a decimal point." / "The bugs that get exploited are not the ones you
     see most often."
   - Underperformers led with a number: "A third of 2026 CVEs carry a CVSS v4
     score..." / "On July 21, Oracle published 1,097 CVEs..." (0-1 comments each).
2. **The number is the evidence; it goes in line two.** Lead with the claim, prove it
   with the stat immediately after.
3. **At most one line of caveat.** Rigor is required for accuracy (the review panel
   enforces it), but do not let hedging bury the hook. Make the point, qualify once,
   move on.
4. **End on a genuine, specific question.** The question is the comment engine; a
   statement ending kills comments. Vary it; never reuse a formula like "how does your
   pipeline handle X?".
5. **North-star metric: reposts + comments, not impressions or reactions.** Reposts put
   you in someone else's feed; comments signal a real nerve. Optimize for those.
6. **Authority + stakes travels.** The best-performing post of the period was commentary
   borrowing an outside authority's warning (J.P. Morgan) with a stakes frame: 12
   reposts, more than any chart. Periodically pair a chart with "even \[credible
   outsider\] is warning about X." Never manufacture alarm the data does not support.

The chart heading stays factual (above); all of this opinion lives in the post copy.

### KEV language (accuracy rule)

CISA KEV is a curated catalog, not the universe of exploited CVEs. Always describe KEV
membership as **"added to KEV"** or **"on the CISA KEV list"**, never as a blanket
"exploited". Many CVEs are exploited in the wild without ever being added (no reliable
public evidence, no available fix, or below CISA's bar), and a CVE being absent from KEV
does NOT mean it was not exploited. The honest contrast is **"on KEV" vs "not on KEV"**,
not "exploited" vs "not exploited". EPSS is the "probability of exploitation"; KEV is
"documented / added to KEV" — keep the two distinct in both chart labels and post copy.

For fully on-brand drafts, run this through the **brand-voice** skill
(`/brand-voice:enforce-voice`) once its connectors are authorized; until then
the house style above (from the launch `CAMPAIGN.md`) is enough.

Claude adds value the scorer can't:
- spotting when two findings combine into one stronger story (volume up + KEV flat)
- rejecting a technically-high-scoring finding that is stale or repetitive
- writing the hook, the caption, and the closing question

## 3. Render + post

```bash
python make.py <suggested_chart>   # render the paired chart, all ratios
```

Then post per `CALENDAR.md`, log it, and move on. Next week, re-run from step 1
on fresh data.

## Tuning what counts as "share-worthy"

Scores live in `insights.py` scanners. Raise a category's base score to see it
surface more often; add a scanner for a new angle (copy an existing one). The
goal is that the top 3-5 are always genuinely postable without hand-digging.

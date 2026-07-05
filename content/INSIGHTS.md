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
> `CALENDAR.md`). For each, draft a LinkedIn + X + Bluesky post. House style:
> no em dashes, lead with the number, end with a question. Note the
> `suggested_chart` to attach.

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

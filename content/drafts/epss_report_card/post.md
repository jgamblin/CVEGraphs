# Caption — EPSS vs CVSS, one month before the KEV list (`epss_report_card` + `epss_gain`)

**Two-image post.** Image 1: `graphs/epss_report_card_<ratio>_<date>.png`
(policy bars). Image 2: `graphs/epss_gain_<ratio>_<date>.png` (gain curves,
built on Jay Jacobs' Slack feedback, see below). House style: no em dashes.
The first POSITIVE EPSS post, and the first backtest format: instead of
plotting today's scores, it rolls the clock back and scores the scorers.
Thursday exploitation lane. Data: `processed/epss_report_card.parquet` +
`_meta.json` via `src/cvegraphs/precompute/epss_report_card.py` (historical
production EPSS snapshots at each KEV-minus-30-days date; runs inside
`refresh_data.py` after the KEV feed fetch).

**Jay Jacobs review 2026-08-19 (Slack), addressed with `epss_gain`.** Jay's
critique: fixed thresholds (CVSS 9.0 vs EPSS 0.10) are unrelated operating
points, so compare the systems by sweeping thresholds into a gain plot,
coverage (future KEV entries caught) vs effort (share of all scored CVEs
flagged), KEV as the outcome. Built as image 2, split fresh/backfill. The
matched-effort result STRENGTHENS the split story and retires the pooled
one: on additions under a year old CVSS dominates at every budget (gain
AUC 0.77 vs EPSS 0.48; at 1% effort the 9.8s alone catch 36% vs EPSS 5%),
on the year-plus backlog EPSS dominates every realistic budget (AUC 0.86
vs 0.77; at 5% effort 58% vs 21%). Pooled, CVSS actually wins on AUC (0.77
vs 0.66) because the fresh cohort and the high-effort tail dominate the
integral, one more reason the pooled bar comparison must never be the
claim. EPSS effort axis uses each CVE's percentile within its own
minus-30-day snapshot, so effort is measured on the decision date. Per
Jerry's note that percent-effort hides the real cost, every policy dot on
the gain chart carries its absolute remediation workload (22K CVEs for
EPSS 0.10+, 34K for CVSS 9.0+, 146K for 7.0+, 7K for 0.50+) and the
footnote gives the conversion: every 10% of effort is roughly 32K CVEs to
remediate for EPSS (321K scored) and 28K for CVSS (282K scored).

**Post-review 2026-08-19, verdict "rework copy / fix chart", all applied.**
The panel's decisive catch: the pooled "EPSS beats Critical-only 33 vs 28"
headline is a Simpson's-paradox artifact. On additions under a year old
(44 CVEs) patch-every-Critical wins 20 vs 10; EPSS's pooled edge comes
entirely from the year-plus backfill slice (23 vs 8 of 38). The copy is
now built ON the split (static score vs living score), which is sharper and
fully defensible. Chart fixes applied: red callout deleted, navy ink on the
light bars (contrast), neutral parallel sub-labels, split stated as a
factual footnote line so a bare screenshot cannot be read against the copy.

Finding (data as of 2026-08-19): CISA added 182 CVEs to KEV in 2026. 48 hit
KEV within a day of the CVE going public (33 the same calendar day) and 52
more within 30 days, so 82 were public at least 30 days before their KEV
date. Reading each of those 82 at the EPSS snapshot 30 days before its KEV
date:

| policy | caught | flags (share of all scored CVEs) |
|---|---|---|
| CVSS 7.0+ (High and Critical) | 72 of 82 (88%) | 146K (52%) |
| CVSS 9.0+ (Critical only) | 28 of 82 (34%) | 34K (12%) |
| EPSS 0.10+ | 33 of 82 (40%) | 22K (7%) |
| EPSS 0.50+ | 23 of 82 (28%) | 7K (2%) |

The split that carries the post: under a year old (44 CVEs) CVSS 9.0+ leads
20 vs 10; a year or older (38 CVEs, the backlog CISA keeps back-filling)
EPSS 0.10+ leads 23 vs 8. Named fresh-cohort catches, verified at the
minus-30-day snapshot: Craft CMS CVE-2025-32432 (EPSS 0.77 at the snapshot,
first crossed 0.10 a full 319 days before its KEV date), Roundcube
CVE-2025-49113 (0.92 at snapshot, 249 days), Fortinet FortiSandbox
CVE-2026-39808 (0.66 at snapshot, 80 days). Do NOT cite Vite
CVE-2025-31125: it crossed 0.10 early but had decayed to 0.036 by the
minus-30-day snapshot, a miss under the chart's own policy.

Caveats to carry:
- **The pooled head-to-head is NOT the story; the split is.** Never quote
  "33 vs 28" as forward-looking patch-queue advice: it inverts on the
  under-a-year cohort. The honest claim is severity carries fresh bugs,
  exploitation evidence carries the backlog, and a static score never
  updates.
- **KEV is the yardstick, not ground truth.** Say "added to KEV", never
  "exploited" as a blanket. KEV is a curated subset; not-on-KEV does not
  mean not-exploited. Both rankers face the same target set, so the
  comparison survives the caveat.
- **EPSS is not prophecy and the copy must not claim it is.** EPSS ingests
  public exploitation evidence, and CISA often confirms weeks later. The
  claim is lead time over the official list, "which is exactly the job".
- **The fast half is out of reach for every ranking.** 100 of 182
  additions (48 within a day of publication, 52 more under 30 days) allowed
  no 30-day warning from any scoring system. Scores prioritize the slow
  half; only patch speed covers the fast half.
- **Small sample.** 82 CVEs in the head-to-head, 44/38 in the split.
  Directionally strong; do not hang decimal places on it.
- **Workload denominators differ by design and the footnote says so.**
  EPSS flag shares are historical (averaged over the fair-set
  KEV-minus-30d snapshots, corpus ~324K scored CVEs; today's v5 snapshot
  would give smaller shares, so historical is the conservative choice).
  CVSS shares are today's v3-scored corpus (281.5K), CNA score with NVD
  fallback.
- **"Whose CVSS?" (Aug 18 continuity):** score_disagreement showed CNA and
  NVD disagree; the copy carries the parenthetical that swapping feeds
  moves counts by a few CVEs and not the ordering.
- EPSS scores are production daily snapshots from the empiricalsec mirror;
  the weekly lattice used for lead times has 7-day resolution.

## LinkedIn / Mastodon
Attach: `epss_report_card_square_<date>.png` + `epss_gain_square_<date>.png`.
```
A CVSS score tells you how bad a bug was the day it was born. EPSS tells you what attackers are doing with it now, and on the exploited backlog that difference is three to one.

I took the 182 CVEs CISA added to KEV in 2026, rolled the clock back to 30 days before each addition, and checked what four common policies had already flagged. It turns out the KEV list is two different lists wearing one name. On additions less than a year old (44 CVEs), patch-every-Critical still wins, 20 catches to EPSS 0.10's 10: when a bug is fresh, severity is most of the signal anyone has. But on the 38 additions older than a year, the known-exploited backlog CISA keeps back-filling, EPSS caught 23 and Critical-only caught 8. A static score never updates. A living one had been flagging Craft CMS for 319 days and Roundcube for 249 before CISA acted, reading public exploit signal ahead of the official confirmation, which is exactly the job. And it is not a threshold trick: sweep every threshold into a gain curve (image 2, with thanks to Jay Jacobs for the push) and severity wins the fresh cohort at any budget while EPSS wins the backlog at any realistic one. (Each CNA's own v3 score, NVD fallback; swap feeds and the counts move by a few CVEs, not the ordering.)

And the third list is the one nobody gets to rank: 48 additions hit KEV within a day of the CVE going public and 52 more within a month. Scores prioritize the slow half; only patch speed covers the fast half. EPSS does its part while flagging 7% of scored CVEs against Critical-only's 12%. I suspect the real reason nobody keys SLAs on it is contractual, not technical. Has anyone actually gotten an auditor to sign off on EPSS-keyed SLAs, or does yours still want CVSS?

#vulnerabilitymanagement #cybersecurity #CVE #EPSS
```

## X / Bluesky
Attach: `epss_report_card_wide_<date>.png` + `epss_gain_wide_<date>.png`.
```
A CVSS score is a birth certificate. EPSS is a pulse, and on the exploited backlog it is not close.

I rolled the clock back 30 days before each of CISA's 182 KEV additions in 2026. On additions under a year old, patch-every-Critical beat EPSS 0.10+, 20 catches to 10. On the 38 older than a year, EPSS won 23 to 8. Static scores never update.

The other 100 went public less than 30 days before hitting KEV, 48 within a day. No score saves you there, only speed.

Would your auditor let you write SLAs against EPSS?
```

## Alt text (image 2, epss_gain)
```
Two gain plots titled "Coverage vs Effort, One Month Before the KEV List".
Each panel plots, for one cohort of 2026 KEV additions, the share of future
KEV entries caught (y axis, coverage) against the share of all scored CVEs
flagged (x axis, effort), as each scoring system's threshold sweeps from
strict to loose. A dark navy curve is EPSS read 30 days before each KEV
date; a pale blue step curve is CVSS v3; a dashed diagonal marks random.
Dots mark the fixed policies CVSS 7.0+, CVSS 9.0+, EPSS 0.10+ and EPSS
0.50+. Left or top panel, the 44 additions under a year old at KEV: the
CVSS curve sits above EPSS at essentially every effort level. Right or
bottom panel, the 38 additions a year or older: the EPSS curve rises almost
vertically, reaching about 58% coverage at 5% effort, and stays above CVSS
until very high effort. The footnote notes the 100 of 182 additions public
under 30 days are excluded because no score had time to help.
```

## Alt text (image 1, epss_report_card)
```
Two-panel horizontal bar chart titled "EPSS vs CVSS, One Month Before the
KEV List". Four prioritization policies are compared on the 82 CVEs added
to CISA's KEV list in 2026 after being public at least 30 days. Left panel,
future KEV entries caught of 82: CVSS 7.0+ (High and Critical) 72, or 88%;
CVSS 9.0+ (Critical Only) 28, or 34%; EPSS 0.10+ (a common low bar) 33, or
40%; EPSS 0.50+ (a 50% probability) 23, or 28%. Right panel, share of all
scored CVEs each policy flags: CVSS 7.0+ flags 52%, about 146,000 CVEs;
CVSS 9.0+ flags 12%, about 34,000; EPSS 0.10+ flags 7%, about 22,000; EPSS
0.50+ flags 2%, about 7,000. CVSS bars are pale blue, EPSS bars dark navy.
The footnote records that of 182 total 2026 KEV additions, 48 hit KEV
within a day of the CVE going public and 52 more within 30 days; that among
additions under a year old CVSS 9.0+ led (20 vs 10 of 44) while EPSS's edge
is the year-plus backlog (23 vs 8 of 38); and that EPSS scores and flag
shares were read from production snapshots 30 days before each KEV date
while CVSS shares come from today's v3-scored corpus.
```

## Notes (comment ammunition, do not put in the body)
- **Matched-effort table (gain curves, quote freely):** fresh cohort at 1% /
  5% / 12% / 20% effort, CVSS catches 36% / 36% / 45% / 64% vs EPSS 5% /
  20% / 27% / 34%. Backfill cohort: CVSS 21% / 21% / 21% / 45% vs EPSS 26% /
  58% / 63% / 74%. Gain AUC: fresh CVSS 0.77 vs EPSS 0.48; backfill EPSS
  0.86 vs CVSS 0.77; pooled CVSS 0.77 vs EPSS 0.66.
- **Never lead with the pooled numbers.** Pooled AUC favors CVSS, and the
  pooled 33-vs-28 bar comparison favors EPSS only at those two operating
  points. Both pooled framings are composition artifacts; the split is the
  claim.
- **Why this differs from Jay's BSides all-KEV charts (EPSS >> CVSS):** his
  compare current scores against the whole KEV catalog, which is dominated
  by old CVEs where EPSS has had years of signal (and current EPSS reacts to
  KEV listing itself). This backtest reads EPSS 30 days before each 2026
  addition, the harder and fairer test, and there the advantage splits by
  cohort age. Same tools, different question: his charts answer "rank the
  existing exploited set", this answers "warn me before CISA acts".
- **Why CVSS is strong on fresh additions:** a month before KEV, a fresh
  CVE has had little time to accumulate public exploit signal, so EPSS has
  little pulse to read (the model is doing its job with the information
  that exists). Severity is available on day one. The flip side of a
  living score is that it needs signal to live on.
- **"So EPSS loses on fresh bugs?" (the sharpest reply):** yes, and the
  post says so out loud; that concession is the credibility move. On
  under-a-year additions Critical-only caught 20 of 44 vs EPSS 0.10's 10.
  The claim is not "EPSS everywhere", it is that a score which updates
  beats a score which cannot, exactly where updating is possible: the
  backlog. Mature guidance (including FIRST's own) is severity plus
  exploitation evidence, not either alone.
- **"EPSS just reacts to the news" rebuttal:** partially true and absorbed
  in the copy ("reading public exploit signal ahead of the official
  confirmation, which is exactly the job"). The claim is lead time over
  the official list, not prophecy.
- **"Why not CVSS plus EPSS together?":** fair, most mature programs do
  exactly that. The chart prices the pure policies people actually write
  into SLAs; composite policies inherit EPSS's efficiency to the degree
  they let it drive.
- **Efficiency lines if wanted:** pooled, EPSS 0.10+ flags 22K to catch 33
  (about 664 per catch) vs Critical-only 34K for 28 (about 1,222). Use
  only WITH the split stated, never as the headline.
- **KEV-cohort composition:** the usual KEV-vs-all-CVEs CNA confound does
  not bite; both rankers are judged against the same 82 CVEs.
- **Day-before robustness:** of the 134 additions public at least 2 days
  before KEV, 42 (31%) were at or above EPSS 0.10 the day before. Lower
  than 40% because that set includes very fresh CVEs where EPSS has had
  days, not months, to move.
- **Vite is the cautionary tale, usable in comments:** CVE-2025-31125
  crossed EPSS 0.10 some 220 days before KEV, then decayed to 0.036 by the
  minus-30-day snapshot. EPSS scores go DOWN too; a threshold policy reads
  the score on the day you act, not the high-water mark.
- The same-day count is 33; 48 is the within-one-day count (KEV dateAdded
  is date-only, so day-level comparisons are the honest resolution).
```

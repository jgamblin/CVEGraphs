# Caption — EPSS in the 90 days before a KEV listing (`epss_early_warning`, `epss_early_warning_lines`, `epss_early_warning_pct`)

**One or two images.** `graphs/epss_early_warning_<ratio>_<date>.png` and/or
`graphs/epss_early_warning_lines_<ratio>_<date>.png` (see below). House
style: no em dashes, no "n=", spell out sample sizes. Thursday exploitation
lane. Companion to `epss_report_card` / `epss_gain`: those ask *what a policy
had flagged* at one lookback, this asks *whether the score moves at all* as the
KEV date approaches. Data: `processed/epss_early_warning.parquet` + `_meta.json`
via `scripts_precompute_epss_early_warning.py` (exact-date production EPSS
snapshots at six lookbacks; runs inside `refresh_data.py` after the report card,
sharing `processed/epss_history_cache`).

**Two renderings of the same cohort.** `epss_early_warning` is the stacked-band
version (distribution at each lookback); `epss_early_warning_lines` is the
per-CVE spaghetti version (one grey path per CVE, cohort mean in navy, log
y-axis; no 0.10 reference line, it crowded the paths). The bands version is the better standalone post image because it needs
no log-scale explanation; the lines version is the better *proof* image because
you can see the individual paths are flat rather than taking it on faith. If both
go in one post, lead with the lines and let the bands quantify.

The lines chart needs a log y-axis: 20 of the 62 sit entirely below EPSS 0.01 at
every lookback and collapse onto the baseline on a linear scale. It plots the
mean (0.28 at 90 days, 0.31 at 1 day, essentially flat) and the median alongside
it, because on this bimodal cohort neither is a good summary on its own: the mean
parks in the empty valley between the two clumps, and the median sits in that
same sparse middle so it swings from 0.028 to 0.099 on the movement of only a few
CVEs. Do not quote the median climb as a trend; it is the least stable number in
this whole analysis.

**Percentile variant: `epss_early_warning_pct`.** Same cohort and same paths,
but EPSS percentile on a linear 0-100% axis instead of the raw score on a log
axis. Two reasons it earns its own render: percentile is each CVE's rank among
all scored CVEs so a model retrain cannot move it, which retires the retrain
caveat entirely; and it needs no log-scale explanation, which makes it the
easier standalone post image of the two line charts.

It also reframes the finding, and this is the more interesting version. In
percentile terms the mean goes 69% to 76% and the median sat at 86% a full 90
days out, rising to 93% the day before. So EPSS had already ranked this cohort
in the top 10 to 15% of all CVEs three months before CISA acted. What stayed low
was the ABSOLUTE probability, not the rank. 48 of 62 moved less than 5 percentile
points across the whole window, and the share in the top decile goes 47% to 55%.

That distinction matters for the copy: "EPSS never flagged half of them" is true
of the 0.10 threshold and false of the ranking. The defensible claim is that
EPSS's opinion was fixed early and that a raw-score threshold is where the
information gets lost, not in the model's ordering.

**Post copy is NOT drafted yet.** Run `/post-review epss_early_warning` and
settle the opinion-first hook before this goes out; the cadence cap is two posts
a week, so slotting it is Jerry's call.

Finding (data as of 2026-08-19): CISA added 182 CVEs to KEV in 2026. 33 were
added the same calendar day the CVE went public, 48 within a day, and 120 had
under 90 days of public history, so 62 could be read at a 90-day lookback. Those
62 are the fixed cohort: the same CVEs at all six horizons. Every one of the 372
CVE-horizon cells resolved to the exact target date, with zero days of snapshot
slippage.

| lookback | median EPSS | at or above 0.10 | at or above 0.50 | percentile 90+ |
|---|---|---|---|---|
| 90 days | 0.0281 | 27 of 62 (44%) | 19 (31%) | 47% |
| 60 days | 0.0527 | 29 of 62 (47%) | 20 (32%) | 50% |
| 30 days | 0.0889 | 30 of 62 (48%) | 21 (34%) | 53% |
| 15 days | 0.1033 | 32 of 62 (52%) | 20 (32%) | 55% |
| 7 days | 0.1033 | 32 of 62 (52%) | 20 (32%) | 55% |
| 1 day | 0.0989 | 31 of 62 (50%) | 20 (32%) | 55% |

The curve is flat. Across the full 90 days, 51 of the 62 moved less than 0.05 in
either direction (8 rose, 3 fell). Only 5 crossed 0.10 upward at any point in
the window; 27 were already at or above 0.10 a full 90 days out; 30 never
reached 0.10 at all, right up to the day CISA acted. The 0.50-and-up band is
19 CVEs at 90 days and 20 at 1 day. Interquartile range at 90 days runs 0.002 to
0.569, so the median is a weak summary of a badly bimodal cohort: EPSS either
already loved these CVEs or had written them off.

The honest reading is that EPSS behaves like a **static prior, not a tripwire**.
It does not escalate into a KEV listing. Both halves of that cut matter: you
lose almost nothing by reading EPSS 90 days early instead of the day before
(good, and the opposite of what most people assume about a "daily" score), and
EPSS never revises its mind on the half of this cohort it had already discounted
(bad, and the reason a threshold policy alone leaves half these CVEs unflagged).

Caveats to carry:
- **The cohort is fixed at 90 days and must stay fixed.** The shorter horizons
  would each admit more additions (82 at 30 days, 94 at 15, 114 at 7, 149 at 1).
  Letting the cohort grow as the horizon shortens makes the bands move because
  membership changed, not because EPSS learned anything. Same trap as the
  KEV-versus-all-CVEs CNA composition confound.
- **The 1-day column is not early warning, and normally it is contaminated.** By
  then EPSS has usually ingested the same public reporting CISA is reacting to.
  Here it is flat, which is itself the finding, but never sell the 1-day number
  as a prediction.
- **The excluded 120 are the ceiling on the whole question.** 33 additions hit
  KEV the same day the CVE went public and 48 within a day. No score existed to
  warn with. "Is EPSS a good early warning system" is capped by KEV's own
  composition before EPSS gets a vote.
- **A model retrain sits inside the window.** The v2026.06.15 model superseded
  v2025.03.14 on 2026-06-15, which falls inside 8 of the 62 lookback windows. On
  the 54 whose windows do not straddle it the pattern is unchanged (46 of 54
  moved under 0.05; the at-or-above-0.10 share goes 48% to 50%), so the flatness
  is not a recalibration artifact. Percentile is carried in the parquet as the
  robustness check because it survives recalibration better than the raw score.
- **Small sample, and one CVE is 1.6 points.** The 44% to 50% climb in the
  at-or-above-0.10 share is about four CVEs. Do not hang a trend on it, and do
  not put decimal places on these percentages.
- **Say "added to KEV", never a blanket "exploited".** KEV is a curated subset;
  not-on-KEV does not mean not-exploited.
- Scores are production daily files from the empiricalsec mirror, read on the
  exact lookback dates (maximum snapshot slippage across all 372 cells: 0 days).

## Alt text (bands, epss_early_warning)
```
Stacked bar chart titled "EPSS in the 90 Days Before a KEV Listing". Six bars
show the same 62 CVEs that CISA added to its Known Exploited Vulnerabilities
list in 2026 after being public at least 90 days, read at six lookbacks before
each CVE's KEV date: 90, 60, 30, 15, 7 and 1 day. Each bar splits the 62 CVEs
into four EPSS score bands, pale blue for under 0.01 up to dark navy for 0.50
and above. The bands barely change across the six bars. Under 0.01 holds 25
CVEs at 90 days and 20 at 1 day; 0.50 and up holds 19 at 90 days and 20 at 1
day. A red line traces the number of CVEs below EPSS 0.10, drifting only from
35 down to 31 across the whole 90 days. The share at or above EPSS 0.10, printed
above each bar, moves from 44% at 90 days out to 50% the day before the KEV
listing. The footnote records that of 182 CVEs added to KEV in 2026, 33 were
added the same day the CVE went public and 48 within a day, and 120 had under
90 days of public history; that 51 of the 62 moved less than 0.05 over the full
window, 5 crossed 0.10 upward and 30 never reached 0.10; and that EPSS retrained
inside 8 of the 62 windows while the pattern holds on the other 54.
```

## Alt text (lines, epss_early_warning_lines)
```
Line chart titled "Every CVE's EPSS Path Into a KEV Listing". The x axis runs
left to right from 90 days before each CVE was added to CISA's Known Exploited
Vulnerabilities list to 1 day before, with points at 90, 60, 30, 15, 7 and 1
day. The y axis is EPSS score on a log scale from 0.0001 to 1.0. Each of the 62
CVEs added to KEV in 2026 after being public at least 90 days draws its own
faint grey line. Almost every grey line runs flat across the chart: a dense band
sits near the top above EPSS 0.50, a second dense band sits near the bottom
below 0.01, and the middle is sparse. A handful of grey lines climb steeply, and
a few drift down. A thick dark navy line marks the cohort average, which is
nearly horizontal at 0.28 ninety days out and 0.31 the day before the listing. A
dashed mid-blue line marks the cohort median, which rises from about 0.03 to
about 0.10 and then flattens. The footnote
records that of 182 CVEs added to KEV in 2026, 33 were added the same day the CVE
went public and 48 within a day, and 120 had under 90 days of public history;
that 51 of the 62 moved under 0.05 across the full window, 5 crossed 0.10 upward
and 30 never reached 0.10; and that 20 CVEs sit always under 0.01 while 19 sit
always over 0.50, so the mean falls between the clumps.
```

## Notes (comment ammunition, do not put in the body)
- **"So EPSS is useless here?" No, and do not let the post imply it.** 27 of 62
  were already at or above 0.10 ninety days before CISA acted. That is real lead
  time over the official list, and it is the same point `epss_report_card`
  makes. What this chart kills is the *escalation* story: the score that was
  going to flag these CVEs was already flagging them, and waiting did not help.
- **The strongest counter-read, worth conceding up front:** flatness is partly
  what a well-calibrated model *should* look like if no new public evidence
  arrived in those 90 days. EPSS can only move on signal it can see. The claim
  is about what the score delivers to a defender on a schedule, not that the
  model is misbehaving.
- **Why this differs from the report card's framing:** the report card holds the
  lookback fixed (30 days) and sweeps the policy; this holds the cohort fixed and
  sweeps the lookback. The report card's 30-day column and this chart's 30-day
  column are different denominators on purpose (82 versus 62), so never quote
  them side by side without saying which cohort.
- **The 5 that crossed 0.10 upward inside the window** are the only CVEs where
  EPSS behaved like a tripwire at all. If a named example is wanted for
  comments, pull them from the parquet rather than guessing; and check the score
  on the day, not the high-water mark, because EPSS decays too (the Vite
  CVE-2025-31125 lesson from the report card).
- **The 0.50+ band going 19 to 20 while 0.10+ goes 27 to 31** means the movement
  such as it is happens in the low-confidence middle, not at the top. Nothing
  got dramatically more certain.
- **The steep grey climbers are the story's exceptions, and there are few.** On
  the lines chart the eye is drawn to the handful of paths that rise two orders
  of magnitude; those are most of the 5 that crossed 0.10 upward. Naming one in
  comments is fine, but the point of the chart is the flat majority around them.
- KEV `dateAdded` is date-only, so publication dates are normalized to calendar
  dates before differencing; day-level is the honest resolution and that is why
  the same-day count (33) and the within-one-day count (48) differ.

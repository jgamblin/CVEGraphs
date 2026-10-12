# Caption — What the KEV listing does to EPSS (`epss_kev_window` + `epss_kev_window_pct`)

**Single-image post.** `graphs/epss_kev_window_<ratio>_<date>.png`. House style:
no em dashes, no "n=", spell out sample sizes. Thursday exploitation lane. The
sequel to `epss_early_warning` / `epss_early_warning_lines`: those stop at the
KEV date and show EPSS is flat on the way in, this extends the window 60 days
past the listing. Data: `processed/epss_kev_window.parquet` + `_meta.json` via
`scripts_precompute_epss_kev_window.py` (exact-date production EPSS snapshots at
11 signed offsets; runs inside `refresh_data.py`, sharing
`processed/epss_history_cache`).

**Percentile variant: `epss_kev_window_pct`.** Same cohort and window, EPSS
percentile on a linear axis. It is the more conservative render and the one to
reach for if the raw-score version feels too strong.

In raw-score terms the step reads as a discovery: median 0.09 to 0.51 overnight.
In rank terms the same CVEs were already at the 93rd percentile the day before
the listing and move to the 98th, with the top-decile share going 54% to 85%. So
the step is a shuffle within the top of the distribution, not EPSS noticing these
CVEs for the first time. Both readings describe the same data; the percentile one
is much harder to overclaim from, and it pre-empts the sharpest reply to the
raw-score chart ("EPSS already had these ranked high, you are just showing a
probability recalibration").

Use the raw-score version if the post is about what a threshold policy would have
done, and the percentile version if it is about what the model believed.

**Post copy DRAFT (2026-08-20), pending review.** Posting the PERCENTILE render
(`epss_kev_window_pct_<ratio>_2026-08-20.png`), not the raw-score one. The angle
is deliberately POSITIVE toward EPSS per Jerry's read: the pre-listing half of
the chart shows the signal was already there and already stable, and what hides
it is the 0-to-1 scale, not the model. The day +1 step is conceded openly rather
than led with, which is also what keeps the post honest.

The load-bearing fact is the score-to-percentile mapping on the live corpus
(360,482 scored CVEs, snapshot 2026-08-17, model v2026.06.15):

| raw EPSS | percentile | share of corpus at or above |
|---|---|---|
| 0.01 | 60th | 40.1% |
| 0.041 | 90th | 10% |
| 0.05 | 91.5th | 8.5% |
| 0.10 | 95th | 4.8% |
| 0.50 | 98.8th | 1.2% |

So a 0.10 threshold is not a low bar, it is the top 5% of all CVEs. And the
median CVE in this cohort scored 0.041 sixty days before its listing, which is
exactly the 90th percentile.

Pre-listing distribution, 60 days out (61 CVEs): 30 in the top decile, 9 between
the 75th and 90th, 5 between the 50th and 75th, 17 below the median. Cumulative:
64% above the 75th percentile, 49% above the 90th. Stability: all 30 that were in
the top decile at 60 days out were STILL in it the day before the listing (zero
dropped out), 3 more joined, and 28 never got there.

Finding (data as of 2026-08-19): the cohort is the 61 CVEs added to KEV in 2026
that have both 60 days of public history before the listing and 60 days of EPSS
scores after it. The second bound forces the cohort into the earlier part of the
year (KEV dates 2026-01-07 to 2026-06-02), because no recent addition can have
60 days of future scores yet. All 671 CVE-offset cells resolved to their exact
target date, zero days of slippage.

| offset | mean EPSS | median EPSS | at or above 0.10 |
|---|---|---|---|
| 60 days before | 0.295 | 0.041 | 44% |
| 30 days before | 0.317 | 0.088 | 48% |
| 15 days before | 0.314 | 0.079 | 49% |
| 7 days before | 0.318 | 0.079 | 49% |
| 1 day before | 0.318 | 0.095 | 49% |
| KEV date (day 0) | 0.319 | 0.095 | 49% |
| 1 day after | 0.493 | 0.506 | 84% |
| 7 days after | 0.468 | 0.465 | 77% |
| 15 days after | 0.454 | 0.465 | 74% |
| 30 days after | 0.447 | 0.465 | 74% |
| 60 days after | 0.449 | 0.414 | 67% |

Flat for 60 days, then a one-day step. Median EPSS goes 0.095 to 0.506 between
day 0 and day 1, a five-fold jump overnight, and the share at or above 0.10 goes
49% to 84%. Nothing in the 60 days before the listing comes close to that: the
whole pre-window moves the median by about 0.05 and the at-or-above-0.10 share by
five points. After the step the scores decay slowly, and by 60 days out the
at-or-above-0.10 share has drifted back to 67%.

Comparing the day before the listing to 60 days after: 33 of 61 rose by more than
0.05, 24 were flat, 4 fell. 12 crossed 0.10 upward. 19 were still under 0.10 two
months after CISA said they were being exploited, which is its own finding.

Caveats to carry:
- **The mechanism claim needs verifying before it is published.** EPSS's feature
  set includes exploitation evidence, and KEV membership belongs to that family,
  which would make this step the model ingesting CISA's decision. The timing
  supports that reading: a one-day discontinuity synchronized to CISA's
  publication calendar is not how real-world exploitation evidence arrives.
  **But confirm the current v5 feature list against FIRST's own model
  documentation before asserting the mechanism in copy.** The chart's own claim
  is only that the step exists, is sized as shown, and shows the score reacting
  rather than anticipating; the *why* is the part that can be wrong. Do not write
  "EPSS uses KEV as an input" without a citation. The on-image footnote was
  deliberately narrowed to the reaction claim for exactly this reason.
- **This is not evidence that EPSS is broken or circular.** A model that updates
  on new public evidence is supposed to update when strong new public evidence
  lands, and a CISA listing is exactly that. The honest framing is about what the
  score can and cannot do for a defender: it cannot warn you before the listing
  (the earlier charts) and it agrees with the listing afterwards.
- **Different cohort from the before-only charts.** 61 here versus 62 there, and
  they overlap without matching: this one needs only 60 days of pre-history but
  also 60 days of post-history. Never present the two counts as the same set.
- **The cohort is the first five months of the year by construction.** The +60
  requirement excludes every recent addition, so any seasonal or
  campaign-specific quirk in early-2026 KEV additions is baked in. This chart
  cannot be refreshed to "today" without the cohort shifting.
- **Day 0 is the KEV date scored that morning.** The snapshot predates the
  listing's effect on the model, which is why the step appears at +1 rather than
  at 0. Say "the next daily run", not "the same day".
- **Small sample, and one CVE is 1.6 points.** The post-step decay from 84% to
  67% is about ten CVEs. Directional only.
- **Say "added to KEV", never a blanket "exploited".** KEV is a curated subset;
  not-on-KEV does not mean not-exploited.
- Snapshot resolution walks BACK only, never forward, so no reading can borrow
  post-dated information.

## LinkedIn / Mastodon (v4, FINAL pending calendar gate)
Attach: `epss_kev_window_pct_square_<postdate>.png`. **Do not post before the
calendar gate below is cleared.**

**Why v4 replaced the v3 hook.** v3 opened "EPSS is not a bad early warning
system. It is a badly scaled one." Two problems. First, Jerry works at Empirical
Security, so a public verdict that EPSS is badly scaled is a criticism of a
product his own employer is tied to, and it reads as either disloyal or as
conceding a design flaw. Second, it is not what the data shows: nothing here says
EPSS chose the wrong scale, only that the informative field is the one most
people do not triage on. The fault sits with reading practice, and the hook now
says so. "Most of us" rather than "you" also fixes the strawman-lecture tone the
review flagged in v1.

The hook keeps its opinion-first flip and its nine-word length, so the
shareability property survives the softening.
```
EPSS is not failing as an early warning system. Most of us are reading the wrong number.

Of the 182 CVEs CISA added to KEV this year, 61 have 60 days of EPSS history on both sides of the listing, which puts them between January and early June. Sixty days before CISA acted, the median one had an EPSS score of 0.041. I read a number like that as "4%, ignore it." That same CVE was sitting at the 88th percentile of everything EPSS scored that day. Thirty of the 61 were already ranked inside the top 10% two months out, and all 30 were still there at every checkpoint I sampled, including the day before the listing. That is not a warning that fired. It is a ranking that was already correct, and had been for at least two months.

The two scales are easy to run together, not least because both of them involve the number ten. The score is a probability. The percentile is a rank. An EPSS score of 0.10 is not the top 10% of CVEs; on today's data it is the top 5%. Cutting at a score of 0.10 would have flagged 27 of these 61 going in. Cutting at the top 10% by rank flags 30, out of twice as much corpus. So rank does not catch you more of them. It tells you the truth about the ones you already had, because a score of 0.041 in a queue reads as noise and the 88th percentile reads as a decision.

None of which makes rank a net. 28 of the 61 never reached the top 10% before their listing, and the step at day +1 is EPSS tracking the listing rather than predicting it. But the percentile ships in the same API response as the score, and most triage rules I have written or reviewed throw it away.

What is your EPSS cutoff, and did you pick that number or inherit it from a vendor default?

#vulnerabilitymanagement #cybersecurity #CVE #EPSS
```

## X / Bluesky (v4, FINAL pending calendar gate)
Attach: `epss_kev_window_pct_wide_<postdate>.png`.
```
EPSS is not failing as an early warning system. Most of us are reading the wrong number.

61 of 2026's KEV additions have 60 days of scores either side of the listing. Sixty days out, the median had an EPSS score of 0.041, which sounds like nothing. It was the 88th percentile that day. 30 of the 61 were already ranked in the top 10%, and all 30 were still there the day before.

Two scales, both involving the number ten: an EPSS score of 0.10 is not the top 10% of CVEs, it is the top 5%.

Not a net: 28 never reached the top 10%. And the jump at +1 is EPSS tracking the listing, not predicting it.

What is your cutoff, and is it a score or a rank?
```

**Affiliation disclosure, decide before posting.** This post now DEFENDS EPSS,
and Jerry's employer is tied to it. A "well of course he says that" reply is
cheap and predictable. Options, in order of preference: (a) name the affiliation
in the first comment rather than the body, which keeps the hook clean and is the
usual convention; (b) add a short clause to the closing paragraph; (c) post as
is, on the grounds that the @jgamblin handle and Empirical Security are already
public and the post concedes two limits against itself. Jerry's call, but it
should be a call and not an oversight, and it matters MORE here than it did on
the critical posts.

**What the review changed and why (keep for the next EPSS post).**
- The v1 hook "that is a scale problem, not a model problem" was cut. It cannot be
  asserted from a cohort selected entirely on KEV membership, and it contradicts
  `epss_report_card`, same lane and same week, which shows CVSS beating EPSS at
  every budget on fresh additions. The replacement keeps the flip and drops the
  claim about the model.
- v1 said 0.041 is "exactly the 90th percentile." The chart plots the
  contemporaneous published percentile, which was the 88th that day. The 90th is
  the mapping onto the 2026-08-17 corpus. Both are now stated as the two
  different things they are.
- v1's payoff argued recall ("you will miss half of this group"). The arithmetic
  goes the other way: 0.10 flags 27 of 61, the top decile flags 30, for roughly
  double the corpus. Three CVEs is not a recall argument. The payoff is now
  legibility, which is unattackable: 0.041 reads as noise, the 90th percentile
  reads as a decision.
- v1 misstated the cohort as "public at least 60 days" (that set is 70). Both
  filters and the 182 denominator are now in the first sentence.
- v1 opened two of four paragraphs on a concession. Now three paragraphs, one
  caveat line each.
- Cut: "and I am not going to dress that up" (announcing candor weakens it),
  "most of these" (49% is not most), "every CVE in your environment" (percentile
  is global rank, not local), "any score, EPSS included" (untested, and about the
  population this cohort excludes).

## Alt text
```
Line chart titled "What the KEV Listing Does to EPSS". The x axis runs from 60
days before the KEV listing date, through day 0, to 60 days after, with points at
60, 30, 15, 7 and 1 day before, the listing day itself, and 1, 7, 15, 30 and 60
days after. The right half of the plot, from day 0 onward, sits on a faint grey
panel labelled "After the KEV listing". The y axis is EPSS score on a log scale
from 0.0001 to 1.0. Each of the 61 CVEs added to KEV in 2026 that has 60 days of
history either side of its listing draws its own faint grey line. Across the
whole left half the grey lines run flat, spread between 0.0001 and 0.9. At day 0
a dense bundle of grey lines turns sharply upward, many climbing two or three
orders of magnitude in a single step, and then stays roughly level or drifts
slowly down over the following 60 days. A thick dark navy line marks the cohort
average, flat at 0.32 through the entire pre-listing window and stepping to 0.49
one day after the listing. A dashed mid-blue line marks the cohort median, which
sits near 0.09 before the listing and jumps to about 0.51 the day after. The
footnote records that the median goes 0.09 to 0.51 and the share at or above 0.10
goes 49% to 84% between day 0 and day 1, and notes that a one-day step
synchronized to CISA's publication calendar means the score is reacting to the
listing rather than anticipating it, while whether KEV feeds the model directly
is a separate question.
```

## Notes (comment ammunition, do not put in the body)
- **The three-chart arc is the real story, and this is the payoff panel.** Chart
  one: EPSS is flat for 90 days before a listing. Chart two: every individual
  path is flat, it is not an averaging artifact. Chart three: the score moves
  the day after CISA publishes. Together they say EPSS is a lagging indicator of
  the KEV list on this cohort, not a leading one.
- **The strongest counter, and it is a good one:** the pre-listing flatness plus
  the post-listing step is also what you would see if CISA were simply faster
  than the public evidence EPSS reads. Under that reading EPSS is not copying
  KEV, it is just slower to the same signal. Distinguishing the two needs the
  feature list, which is why the mechanism caveat exists. Do not claim to have
  ruled this out.
- **The 19 still under 0.10 sixty days after listing** are the most quotable
  number for a "do not key SLAs on a single threshold" argument, and they cut
  against the circularity reading too: if KEV membership drove the score
  mechanically and completely, none of these would stay low.
- **The decay after the step** (84% down to 67% at 60 days) is EPSS behaving like
  a probability that decays without fresh signal, the same effect behind the Vite
  CVE-2025-31125 cautionary tale in the report card caption. A threshold policy
  reads the score on the day you act, not the high-water mark.
- **Why the mean moves less than the median** (0.32 to 0.49 versus 0.09 to 0.51):
  the mean was already carried by the roughly 20 CVEs sitting above 0.50 before
  the listing, so it had less room. The median was sitting in the sparse middle
  and the step pushed the whole middle of the distribution across it. Quote the
  median for the size of the jump, the mean for the cohort total.
- KEV `dateAdded` is date-only, so offsets are calendar-day arithmetic from that
  date; that is also why day 0 can be read as a pre-listing snapshot.

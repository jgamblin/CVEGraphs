---
chart: camp_week
posted: 2026-08-04
platforms: LI
migrated: 2026-10-11
---
# Caption — Strip plot: CVE volume in Black Hat / DEF CON week vs nearby weeks (`camp_week`)

Image: `graphs/camp_week_<ratio>_<date>.png`. House style: no em dashes; no "n="; factual
Title-Case heading; post-date stamp. Measurement lane (Tuesday), posted during camp week
itself. Copy is opinion-first (line one is an arguable claim). See content/planning/INSIGHTS.md.

Finding (CVE List V5 `date_published`, non-rejected, published records; conference week =
the Monday-Sunday week containing DEF CON): the folklore slowdown is not there. Conference
week falls below its local median (the median of the twelve weeks within six either side, same
year) in 6 of 10 years and above it in 4. Median gap **-10.4%**. Mean rank **6.3 of 13**
where a random week averages 7.0 (permutation p = 0.59; sign test on 6/10 p = 0.75; Wilcoxon
on the percent deltas p = 0.92). Per-year: 2016 +261%, 2017 -23%, 2018 -45%, 2019 -13%,
2020 -49%, 2021 +32%, 2022 +23%, 2023 +64%, 2024 -8%, 2025 -20%.

Secondary test (the intuitive mechanism, fewer humans at desks): distinct CNAs publishing
per day during camp week is also flat. Mon-Sun median -6.1%, mean rank 5.9 of 13; Mon-Fri
median -4.9%, mean rank 6.5 of 13.

Also null: severity mix (critical+high share camp vs baseline moves both directions, no
pattern; mean CVSS v3 within 0.1-0.5 either way) and KEV additions during camp week
(2022 4 vs nearby median 1.5; 2023 2 vs 3.5; 2024 3 vs 3.5; 2025 3 vs 3.5). None of these
made the copy; they are pocket answers.

## Conference dates used (verified)
DEF CON is the anchor because the Mon-Sun week containing it also contains the Black Hat USA
briefings (Wed-Thu) and BSidesLV (Tue-Wed) in all ten years. Verified against defcon.org
archives and the DEF CON Wikipedia table; BSidesLV cross-checked against bsideslv.org
archives.

| Year | DEF CON | Conference week (Mon-Sun) |
|------|---------|---------------------------|
| 2016 | Aug 4-7 (DC 24) | Aug 1-7 |
| 2017 | Jul 27-30 (DC 25) | Jul 24-30 |
| 2018 | Aug 9-12 (DC 26) | Aug 6-12 |
| 2019 | Aug 8-11 (DC 27) | Aug 5-11 |
| 2020 | Aug 6-9 (DC 28, virtual) | Aug 3-9 |
| 2021 | Aug 5-8 (DC 29) | Aug 2-8 |
| 2022 | Aug 11-14 (DC 30) | Aug 8-14 |
| 2023 | Aug 10-13 (DC 31) | Aug 7-13 |
| 2024 | Aug 8-11 (DC 32) | Aug 5-11 |
| 2025 | Aug 7-10 (DC 33) | Aug 4-10 |

2026 (DEF CON 34, Aug 6-9; conference week Aug 3-9) is the week this posts and is deliberately
NOT in the chart: the week has not finished.

## CLOCK CHOICE (do not switch this back)
Uses CVE List V5 `date_published` (the CNA's own publication timestamp), NOT NVD `published`.
NVD's field records NVD ingestion and carries hard multi-day zero gaps, including
**Aug 9-11, 2024 (zero CVEs, spanning a Friday)**, which sits squarely inside DEF CON 32
week. On the NVD clock that gap reads as a dramatic conference-week shutdown that never
happened. NVD also has 40 zero-publication weekdays in 2016 and 22 in 2015. If anyone asks
"doesn't NVD show a big dip?", this is the answer.

## LinkedIn / Mastodon
Attach: `camp_week_square_<date>.png` (or portrait/wide).
```
Everyone says the security world stops for Vegas. Your CVE queue never got the memo.

Camp week starts today, so I pulled the last ten completed Black Hat and DEF CON weeks and measured each against the twelve weeks around it in the same year. The median year lands 10% below its typical week, which sounds like something until you see the spread: half the years fall between 22% below and 30% above. Conference week averages rank 6.3 out of 13 nearby weeks, where a week picked at random averages 7.0. Ten years cannot rule out a small dip, but nothing resembling the quiet week people describe shows up.

No spike either, which is the version I expected. Severity mix and KEV additions during camp week run in line with the surrounding weeks. Two accidents of the calendar also kill the travel explanation: 2017's conference was in July, and the window moves with it and stays flat; 2020, when nobody travelled at all, is one of the deepest dips in the set.

So the intake rate does not thin out during the one week your team is thinnest. Who is actually on the vuln queue at your shop this week, and was that a plan or a default?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
Everyone says the security world stops for Vegas. Your CVE queue never got the memo.

Ten years of Black Hat and DEF CON weeks, each against the twelve weeks around it: the median year lands 10% below its typical week, but half the years fall between 22% below and 30% above. Average rank 6.3 of 13, where a random week averages 7.0. No dip, and no spike either.

Who is actually on the vuln queue at your shop this week?
```

## Bluesky (300-char limit; the X copy above does not fit)
```
Everyone says the security world stops for Vegas. Your CVE queue never got the memo. Ten years of Black Hat and DEF CON weeks against the twelve weeks around each: conference week averages rank 6.3 of 13, where a random week averages 7.0. No dip, no spike. Who is on your vuln queue this week?
```

## Alt text
```
Strip plot with one row per year from 2016 to 2025. Each row shows thirteen marks, one per week: the Black Hat and DEF CON conference week as a large red triangle, and the six weeks before and six after it as smaller pale blue dots. The horizontal axis is each week's CVE count as a multiple of that year's typical nearby week, on a log scale marked 0.5x, 1x, 2x and 4x, with a dashed vertical reference line at 1x labelled typical week. In every year the red triangle sits inside the spread of pale dots rather than at either edge, landing left of the 1x line in six years and right of it in four, with no consistent direction. The 2016 row has the widest spread, its triangle reaching past 3.5x. A summary row at the bottom, labelled ten-year median, shows a red triangle just left of the 1x line at 10% below typical, with a horizontal bar behind it marking the middle half of the ten years, spanning roughly 22% below to 30% above. A note below reads that conference week averages rank 6.3 of 13 nearby weeks against 7.0 for a random week. Source: CVE List V5.
```

## CORRECTIONS from the review panel — do not reintroduce
1. **The chart was a 130-bar small-multiples grid and it could not draw its own finding.** At
   the rendered size every row max was 27px, so the effects it argued from (2024 = -8%, a 2px
   gap; 2019 = -13%, 4px) were invisible and the annotations did all the work. Replaced with
   this strip plot: each week is a dot at its ratio to the year's typical week, conference week
   in navy. The null is now the visual (navy dot sits inside the pale swarm), not a caption.
2. **Never colour the deltas by sign.** The old chart rendered below-median years in navy
   #1f3a5f (11.5:1) and above-median years in neutral #8da0b5 (2.68:1, fails WCAG AA). That
   faded exactly the four years that contradict the folklore, so a null-result chart was
   typographically arguing FOR a slowdown. The delta column is now gone entirely; if it ever
   returns, one ink for all ten rows.
3. **The dashed reference line was invisible inside the dark conference bar** (#525559 on
   #1f3a5f = 1.5:1), and only in the four up-years. Another version of the same tilt.
4. **The chart was over-explained** (Jerry, pre-publish): title + two-line subtitle + two
   labelled columns + column headers + axis label + two-line bold verdict + a six-line method
   footnote. If the graph needs a paragraph, the encoding is wrong. Now: one subtitle line, one
   reference label, one axis label, one verdict line, two footnote lines. Keep it there.
5. **Do not label the 1x reference line "CONFERENCE WEEK".** An intermediate version did; the
   dashed line is the TYPICAL nearby week and the navy dots are conference week, so that label
   inverted the whole encoding.
6. **The old copy cited a "45% below to 64% above" range while the chart showed +261% for
   2016.** The visible outlier must never be the one the prose omits. The delta column is gone,
   so the copy no longer cites a range at all; if one returns, name 2016 and its 68-CVE base in
   the same clause.
7. **Cut the automation causal claim** ("which makes sense once you accept that most of it is
   automation now"). Nothing here measures automation, it was the only unsupported claim in an
   otherwise numeric post, and "once you accept" lectures the reader. The distinct-CNA result
   arguably points the other way: the number of distinct ORGANISATIONS publishing does not drop
   either, which is not the same story as "bots are carrying it."
8. **Hedge the null, once.** Ten observations with permutation p = 0.59 cannot support a flat
   "the pipeline does not notice." The copy now says "ten years cannot rule out a small dip",
   which pre-empts the top comment instead of conceding it later.
9. **"Coin flip" was cut.** It was the third use in four weeks (ridgeline_severity Jul 8,
   cvss_v4_adoption Jul 21). Use the chart's own number: less than one rank in thirteen.
10. **Answer the myth that is actually held.** One reviewer's SOC believes camp week is when
    the scary stuff DROPS, not when publishing pauses. The copy now closes both directions
    ("no spike either") using the severity and KEV nulls.
11. **The closing question was "publishing or reading", which excluded most readers** (almost
    none of them publish CVEs) and led the answer. It now asks about queue coverage, which is
    also the real operational takeaway: flat intake plus a team in Vegas equals a backlog.
12. Chart labels must be Title Case (an earlier version had sentence-case axis labels).
13. **Red is a deliberate exception to the palette** (Jerry's call, pre-publish). A reviewer
    praised withholding `alert` red on a null-result chart, but pale-navy-on-navy did not
    survive a thumbnail. Conference week is now a RED TRIANGLE, which reads as a tent and gives
    shape plus colour, so the highlight survives downscaling and colour-vision deficiency.
    Do not revert to a navy circle. The one thing to watch: red carries an alarm connotation,
    so never pair it with alarmed copy, the finding is that nothing happens.
14. **The chart shows the pooled answer** (Jerry's call): a "10-year median" summary row with
    the median at 0.90x (−10%) and a bar spanning the middle half of the years, 0.78x to 1.30x.
    Because −10% is now the most prominent number on the image, the copy names it in the same
    breath as the spread. Never let the chart show −10% while the copy only talks about ranks.

## Notes / caveats
- Baseline is deliberately WITHIN-YEAR (the twelve weeks within six either side, same year).
  CVE volume grew from about 6,500 a year in 2016 to 48,000 in 2025, so any cross-year
  comparison would measure growth, not Vegas.
- x is a RATIO to each year's own typical week, so the 7x growth in volume never enters the
  comparison. Log scale, because 2016's weeks run 0.34x to 4.27x off a 68-CVE median and a
  linear axis would flatten the other nine years.
- 2016 is kept but is the weakest row: MITRE-era batch publishing left 38 zero-publication
  weekdays that year, so its weekly counts are lumpy and its +261% is a small-denominator
  artifact (typical week only 67.5 CVEs). Excluding 2016 moves the median to -13.3% and leaves
  the verdict unchanged (6 of 9 below). The rank measure, which the headline stat uses, is
  immune to this. On the chart 2016 is visibly the widest row, which is the honest tell.
- ROBUSTNESS (ran after the first draft, all hold): excluding MITRE entirely gives median
  -12.9%, 5 of 10 below, mean rank 6.5; baseline widths of +/-4, +/-6, +/-8 and +/-10 weeks
  give mean ranks 4.4/9, 6.3/13, 8.3/17, 10.2/21 against random expectations of 5.0, 7.0, 9.0
  and 11.0. Note the mean rank sits slightly BELOW centre in every window, a consistent lean of
  roughly 0.7 ranks. It never approaches significance on ten years, but "a faint lean toward
  quieter that does not clear the noise" is the honest description, not "exactly random."
- 2020 ran virtually (DEF CON Safe Mode) and BSidesLV was cancelled. Its -49% is one of the
  two deepest dips, which if anything argues AGAINST the travel explanation: nobody travelled
  that year. Do not present 2020 as evidence for the slowdown.
- 2017 is the only July conference (DEF CON 25, Jul 27-30). Useful natural experiment: the
  window moves with the conference and the result stays null, so this is not just "early
  August is quiet".
- Patch Tuesday falls inside conference week in 2022 and 2023, the two clearest up-years.
  That is the main confound and the copy names it. Excluding Patch Tuesday and matching
  weekday-by-weekday still gives a null (median +5.1%, 4 of 10 below).
- POCKET ANSWERS for the comments (do not put in the body):
  - "But NVD clearly goes quiet." NVD's `published` is ingestion, not publishing, and it has
    a hard zero from Aug 9-11 2024 inside DEF CON week plus 40 zero weekdays in 2016. The
    CNA-side clock does not show it. See CLOCK CHOICE above.
  - "Researchers hold 0-days for their talks, so expect a spike." Directionally that is what
    recent years lean toward (2021 +32%, 2022 +23%, 2023 +64%), but 2024 and 2025 are down,
    so there is no reliable spike either. The honest claim is "no effect", in both directions.
  - "Did it used to slow down before automation?" Tempting: 2016-2020 median is -23% and
    2021-2025 is +23%. Do NOT claim this. It is five noisy years per side, and the
    weekday-matched measure shows no such flip (+2.9% vs +7.3%). Offer it as a question, not
    a finding.
  - "What about severity, or KEV?" Also null. Critical+high share moves both directions with
    no pattern, and KEV additions during camp week run 4, 2, 3, 3 against nearby-week medians
    of 1.5, 3.5, 3.5, 3.5.
  - Statistical honesty: this is a null result on ten observations, so it is "no detectable
    effect", not "proof of no effect". A slowdown smaller than roughly 20% could hide in this
    much noise. Say that plainly if pressed.
  - KEV LANGUAGE (house rule): "added to KEV" / "on the KEV list", never blanket "exploited".
- Factual Title-Case heading; the opinion lives in the copy.

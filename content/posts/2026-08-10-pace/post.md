---
chart: pace + earliest_overtake
posted: 2026-08-10
platforms: LI
migrated: 2026-10-11
---
# Caption — Pace Tracker (`pace`)

Two images: `graphs/pace_<ratio>_<date>.png` and `graphs/earliest_overtake_<ratio>_<date>.png`.
House style: no em dashes; no "n="; factual Title-Case heading + labels; post-date stamp.
Volume lane, off-cadence milestone. Angle: anti-vulnpocalypse (fast, not fastest, not bad).

Finding (verified, CVE List V5, published and non-rejected, by publication date):
**On Aug 10, 2026, the 2026 CVE count passed the entire 2025 total.** 2026 year-to-date
is 48,271; all of 2025 was 48,163, a margin of 108 CVEs, about eight hours of publishing
at the current 334/day. Day 222 of the year.

Every prior year since 2018 made the same crossing between late September and
mid-December: 2018 Nov 12, 2019 Dec 18, 2020 Dec 11, 2021 Dec 6, 2022 Oct 24, 2023 Nov
14, 2024 Sep 30, 2025 Nov 4. 2026 beat the earliest of those by 51 days. Separately, 2026
passed all of 2024 on Jul 15, so it absorbed the entire 2024-to-2025 gap in 26 days.

**It is NOT the earliest crossing on record, and the post says so on purpose.** Ranked
across every crossing since 2001, 2026 is **4th earliest**, behind 2005 (Apr 12, cleared
1,612), 2017 (Jun 13, cleared 6,457) and 2002 (Jul 26, cleared 1,323). 2026 is the only
one that had to clear a five-figure total. The ten earliest of the 18 crossings since 2001: 2005
Apr 12, 2017 Jun 13, 2002 Jul 26, 2026 Aug 10, 2004 Sep 24, 2014 Sep 26, 2024 Sep 30,
2012 Oct 6, 2022 Oct 24, 2025 Nov 4.

**Nothing is excluded except pre-2001**, and the chart footnote says so. The series starts
at 2001 because 2000's baseline is 1999, the program's founding stub: all 320 of its CVEs
carry a single publication date. Early years ARE dated coarsely (2002 has 60 distinct
publishing days against 246 in 2005, and 2004 has 88), but that is **disclosed in the
footnote rather than used to remove them**. This was a deliberate reversal of an earlier
draft that filtered them out: including them makes 2026 look less exceptional, which is
the post's actual argument, and it removes any cherry-picking attack surface.

Defensible claims: "4th earliest since 2001", "the only one that had to clear more than
48,000", "years have been lapping the one before them since 2002". Never "earliest ever".

The growth is concentrated, not broad. Publishing is up 71% over the same Jan 1 to Aug 10
window last year (28,272 -> 48,271, +19,999). Five CNAs account for 74.8% of that growth:
GitHub_M +6,807 (1,579 -> 8,386), VulnCheck +3,961 (245 -> 4,206), Chrome +2,023 (90 ->
2,113), Oracle +1,317 (235 -> 1,552), Linux +847 (2,945 -> 3,792). Outside those five the
rest of the CVE world grew 21.8% (23,178 -> 28,222).

**Backfill: aggregate-true, composition-false. Do NOT say "this is not catch-up" in the
post body.** Publications carrying a pre-year CVE ID did fall on the same window, 7,243 to
7,070 (26% of publishing down to 15%), but the composition inverted: Linux went 1,663 ->
256 while **VulnCheck went 98 -> 1,833, which is 43.6% of its own 4,206**. The post credits
VulnCheck as a growth driver, so a blanket "not catch-up" is refuted by the post's own
example in one query. GitHub_M 105 -> 251 (3.0%), Chrome 0, Oracle 0. The aggregate number
belongs in the first comment WITH the VulnCheck disclosure, never as a standalone defense.

## LinkedIn / Mastodon
Attach two images, in this order: `pace_wide_<date>.png` (the milestone), then
`earliest_overtake_wide_<date>.png` (the ranking that keeps it honest).
```
2026 passed the entire 2025 CVE total today, and that is not the bad news it sounds like.

It happened on day 222 of the year, with 48,271 published against the 48,163 that all of 2025 produced. That is fast, but it is not the record and it is not new. Years have been lapping the one before them since 2002, and three crossed earlier than this: 2005 in April, 2017 in June, 2002 in July. What changed is the size of what gets cleared. Those years passed totals between 1,300 and 6,500. This one passed 48,163.

The growth has names on it. Publishing is up 71% over the same window last year, +19,999 CVEs, and five CNAs are three quarters of that increase: GitHub's advisory database up 6,807, VulnCheck up 3,961, Chrome up 2,023, Oracle up 1,317, the Linux kernel up 847. Outside those five, the rest of the CVE world grew 21.8%. Some of that is new ground. A lot of it is re-identification, GitHub minting CVE IDs for advisories that already lived in GHSA, Chrome and Oracle putting numbers on fixes they have shipped publicly for years. Both make the count go up. Neither means more software broke this year than last.

Go look at your own 2026 intake: how much of the increase carries those five names?

#vulnerabilitymanagement #cybersecurity #CVE
```

First comment (sourcing):
```
Counts from CVE List V5, published and non-rejected, by publication date. NVD runs about 50 records behind today, so the margin there is closer to 57, still past the line.

Not a backlog flush either: publications carrying a pre-2026 CVE ID fell year over year, 7,243 to 7,070, so backfill's share of publishing dropped from roughly 26% to 15%. That test only catches old IDs, though. VulnCheck's own pre-2026-ID publications went 98 to 1,833, so a chunk of its 4,206 is genuinely old bugs finally getting published.

The ranking covers every crossing since 2001. 2002 and 2004 were dated in batches rather than daily, so their crossing dates are coarse. They are kept in anyway, because dropping them would move 2026 up.
```

## X / Bluesky
```
2026 passed the entire 2025 CVE total today, and that is not the bad news it sounds like.

Day 222 of the year, 48,271 against 48,163. Fast, but not the record and not new: 2005 crossed in April, 2017 in June, 2002 in July. Those years cleared under 6,500. This one cleared 48,163.

Five CNAs are three quarters of the growth. That is coverage arriving, not software falling apart.
```

## Alt text

Image 1 (`pace`):
```
Bar chart of CVEs published year-to-date by year, 2016 through 2026, every year measured
over the same January 1 to August 10 window. The bars rise steadily from about 4,000 in
2016 to 28,272 in 2025, then jump to 48,271 in 2026, highlighted in red. A dashed navy
line across the chart marks the full-year 2025 total of 48,163; the 2026 bar clears it by
108 CVEs, a margin too small to see at this scale, so the bar is labeled 48,271 +108. Source: CVE List V5, published and non-rejected, by publication date.
```

Image 2 (`earliest_overtake`):
```
Horizontal lollipop chart ranking the ten earliest times a year passed the previous
year's full CVE total, earliest at the top, each row labeled with its crossing date.
The top four rows carry the total each year cleared: 2005 on April 12 cleared 1,612, 2017
on June 13 cleared 6,457, 2002 on July 26 cleared 1,323, and 2026, highlighted in red, is
fourth on August 10 having cleared 48,163. The remaining six rows are date-only and run
from September 24 to November 4. Footnotes note these are the ten earliest of eighteen
crossings since 2001, that the other eight landed in November and December, and that the
2002 and 2004 dates are approximate because those years were published in batches rather
than daily. Source: CVE List V5.
```

## Notes / caveats
- **Margin is thin and live.** 108 CVEs is 0.2% of the total and it crossed the day of
  posting. The copy discloses it ("by a margin of 108 CVEs, about eight hours of
  publishing") rather than letting a reader find it. Re-run `refresh_data.py` and
  re-render if the post slips more than a day; the margin grows about 334/day.
- **Posting after 7pm Central lands on the next UTC day.** `today_utc()` now honors
  `CVEGRAPHS_POST_DATE=YYYY-MM-DD`, which drives both the corner stamp and the output
  filename so they cannot drift apart. Both images for this post were rendered with
  `CVEGRAPHS_POST_DATE=2026-08-10`. Use it on any evening render.
- **Copy says "today", so it expires at midnight local.** If this does not go out tonight,
  change "today" to "on August 10" in both the LinkedIn and X copy, and re-render with the
  new post date. Do NOT re-run `refresh_data.py` first unless you also update every number:
  the current snapshot ends Aug 10 19:14 UTC, which is what makes 48,271 and "today" agree.
- **Never claim "earliest ever".** See the Finding section; 2026 is 4th earliest since
  2001. The `earliest_overtake` image is attached specifically so the post makes that
  concession visually instead of getting corrected in the comments.
- **The post is deliberately pro-CVE-program.** This is the anti-vulnpocalypse lane, a
  continuation of the Jul 30 AI Summit carousel. If a reviewer flags the framing as
  "apologia for CVE volume growth", that is the intended reading, not a defect. The
  guardrail is that every favorable claim stays numerically true; the argument is
  editorial, the numbers are not.
- **Chrome's 90 to 2,113 is the weakest link in the "coverage" story.** It is stated as
  counts only, with no causal claim. If someone argues it is Google inflating numbers
  rather than expanding coverage, that is a fair reading this data cannot settle, and
  conceding it costs the post nothing.
- **Source is CVE List V5, not NVD.** The per-CNA decomposition needs `assigner_short_name`,
  which NVD does not carry, so the whole post and the chart read from one table. NVD's
  totals run about 50 lower today, which would put the margin near 57. Disclosed in the
  first comment.
- **The Jul 15 vs Jul 16 wrinkle.** The Jul 16 `two_year_overtake` post said 2026 passed all
  of 2024 on Jul 16; that was NVD. On V5 the same crossing is Jul 15. The current copy no
  longer references that crossing at all, so nothing visibly conflicts. Only relevant if
  someone cross-checks the two posts; the answer is the source difference.
- **Chart carries two different 2025 numbers on purpose.** The 2025 *bar* is year-to-date
  (28,272); the dashed *line* is all of 2025 (48,163). The line label and the footnote both
  say so. This is the one thing a fast reader can misread.
- **Growth figures are net, not gross.** 74.8% is the top five CNAs' share of *net* growth.
  Some CNAs shrank. If challenged, gross share is lower; net decomposition is the standard
  treatment and the honest one for "what changed".
- Lane: volume. This is the fifth volume item in 27 days and it consumes the off-cadence
  milestone exemption. Rest the lane about three weeks after this.

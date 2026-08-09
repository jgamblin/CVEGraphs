# Caption — Ranked bars: largest verifiable single-second CVE bursts (`second_burst`)

Image: `graphs/second_burst_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. **End-of-month oddity / curio lane**, not a
scheduled slot. Copy is opinion-first (line one is an arguable claim, number line two).

Finding (verified, CVE List V5, data as of 2026-07-31): on 2026-07-13 at 08:41:24 UTC,
Patchstack published **66 CVEs in a single second**, with 22 in the second before and 61 in the second after.
That is the largest verifiable single second in CVE history; the previous record was
Google Android at 31 (2019-09-27 18:05:17). The full burst was 149 CVEs in a three second
window (08:41:23 = 22, :24 = 66, :25 = 61) covering **136 distinct products**.
Context: July 2026 averaged 313 CVEs/day, or 0.0036/second, so that one second ran about
**18,000x the July average rate** and contained roughly **5 hours** of average output.
Patchstack published 481 CVEs in July and 3,185 in 2026 to date.

## LinkedIn / Mastodon
Attach: `second_burst_wide_<date>.png` (or square/portrait).
```
The largest publishing burst in CVE history landed on a completely unremarkable Tuesday, and not one daily chart noticed.

On July 13 at 08:41:24 UTC, Patchstack published 66 CVEs in a single second. That is the largest verifiable single second in the record, double the old high of 31. The full push was 149 CVEs in three seconds, across 136 distinct products, in one bulk API submission for research that took weeks.

Then look at the day it happened on. July 13 closed at 336 CVEs against a July average of 313. Dead average. The biggest burst anyone has recorded left no mark at all on the daily count, because a daily count cannot see it.

The days that did move were calendar artifacts. July's low was 15 CVEs on a Sunday. Its high was 1,474 on the 21st, and 1,097 of those were Oracle's quarterly bundle. Strip Oracle out and the 21st was a 377-CVE day.

So a CVEs-per-day chart is mostly a chart of who uploaded when. What do you put on the slide instead?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
The largest publishing burst in CVE history landed on an unremarkable Tuesday and no daily chart noticed.

July 13, 08:41:24 UTC: Patchstack published 66 CVEs in one second, double the old high of 31. 149 in three seconds, one bulk API submission.

That day closed at 336 CVEs against a July average of 313. Dead average. A daily count cannot see a three-second event, which tells you what a daily count is actually measuring.
```

## Alt text
```
Horizontal bar chart of the eight largest verifiable single-second CVE publishing bursts,
one row per publishing event. A single dark navy bar at the top is Patchstack with 66 CVEs
at 08:41:24 UTC on Jul 13, 2026, more than double every other bar. The seven pale blue bars
below are Google Android (31 in 2019 and 30 in 2020), Apple 29, Chrome 28, Jenkins 27,
Cisco Talos 26 and Microsoft 25. Source: CVE List V5.
```

## Notes / caveats
- Metric: unique CVEs sharing one assigner_short_name and one calendar second of CVE.org
  publication timestamp.
- TWO EXCLUSIONS, both about comparability (stated in the chart footnote):
  1. **MITRE dropped entirely.** MITRE publishes direct to the CVE List instead of
     submitting via the API, so its timestamps measure a different mechanism. Left in, it
     also produces fake records (480 "in one second" at 2004-09-01 04:00:00) because its
     date-only records default to midnight. 74.5% of MITRE rows sit exactly on the hour.
  2. **Only `second != 0` records are eligible** (76% of the remainder). Filtering just
     on-the-hour is NOT enough: Oracle and Apple have minute-truncated rows that fake a
     234-in-one-second. Both date-only and minute-truncated records pile at :00.
- So the honest claim is "largest **verifiable** single second", not "largest ever". A
  bigger real burst could hide inside the 24% with truncated timestamps. The chart says
  "verifiable" and the footnote explains why.
- This measures PUBLISHING, not discovery. The copy concedes this outright and then turns
  it into the point (dashboards counting CVEs/day are measuring automation speed). Do not
  imply 149 vulnerabilities were found in three seconds.
- Patchstack is a WordPress-ecosystem CNA, hence 136 distinct products in one batch. This
  is not a knock on them: bulk submission is the correct way to publish a backlog.
- **Say "136 distinct products", NOT "136 WordPress plugins".** A review persona asserted a
  "114 plugins and 22 themes" split; that is NOT supported by our data and was rejected. All
  149 raw CVE records were checked: 1 carries a plugin signal, 0 carry a theme signal, 148
  carry neither, and the parquet has no reference URLs. Do not publish a plugin/theme split
  we cannot verify.
- **Why the thesis was rewritten (the review's best catch):** an earlier draft claimed
  "every dashboard that counts CVEs per day is measuring how fast someone's automation
  posts." Its own day disproves it. Jul 13 closed at 336 CVEs against a July mean of 313.2,
  only 23 above average, so a 149-CVE three-second burst is INVISIBLE at daily resolution.
  The defensible version is variance across the month: July ran from 15 CVEs (Jul 26) to
  1,474 (Jul 21). Both verified. Real daily outliers were Jul 21 (1,474), Jul 14 (1,007),
  Jul 30 (662), none of them the burst day.
- Chart title says "Largest Verifiable Single-Second CVE Bursts", not "Ever". An earlier
  version said "Ever" directly above a footnote that excludes MITRE and 24% of records,
  which is a self-contradiction on an artifact that travels without its author.
- CADENCE (do not skip this): the week of Jul 27-31 already used both slots
  (cvss_epss_scatter Tue Jul 28, AI Summit carousel Thu Jul 30). This would be a third.
  The off-cadence exemption requires "genuinely newsworthy" and the burst is 18 days old, so
  the gate fails, exactly as cna_burst refused the same exemption on Jul 22. **Hold for
  Tue Aug 4 as that week's slot.** It is a curio in tone, but it still consumes a slot.
- **The claim is ONE SECOND only, and that matters.** Widen the window and Patchstack loses:
  Google Android pushed 258 CVEs in ten seconds on 2019-09-27, against Patchstack's 149.
  Verified. Never juxtapose the 149 three-second total against the 31 one-second high, which
  invites a false comparison. Keep 66-vs-31 and 149-in-three-seconds as separate statements.
  Pocket answer if challenged: "Android holds the ten-second record at 258. Patchstack holds
  the one-second record. Both are upload mechanics, which is the point."
- Endpoint mechanisms, all verified, and naming them makes the argument stronger rather than
  weaker: July's five lowest days were ALL weekends (Jul 26 Sun = 15, Jul 12 Sun = 63,
  Jul 4 Sat = 72, Jul 11 Sat = 79, Jul 18 Sat = 81). July's high of 1,474 on Jul 21 was 74%
  Oracle (1,097); without Oracle that day was 377, near the 313 average.
- Chart ranks ONE ROW PER PUBLISHING EVENT (biggest second per CNA per day), not per clock
  second. Ranking raw seconds put five consecutive seconds of a single Android upload
  (18:05:14 to 18:05:18) in five rows, which read as five separate competitors and inflated
  Patchstack's apparent dominance. One-per-event shows the record against eight distinct
  organisations clustered at 25-31, which is a truer and stronger picture.
- Timestamp sublabels are #556A82 (~5:1 on white). An earlier pass moved them to
  COLORS["neutral"] (#8DA0B5, 2.68:1) which fails WCAG AA. The timestamp is the whole point
  of this chart, so it cannot be low-contrast chrome.
- Related prior post: cna_burst (2026-07-22) covered the biggest single-DAY batch (Oracle
  1,097). This is the same family at second granularity; mention it in comments if asked,
  and do not reuse the "mega-batch" hook wording. NOTE: this is now the THIRD airing of the
  "counts measure publishing, not risk" thesis in ten days (cna_burst Jul 22, AI Summit
  carousel Jul 30, this). The new hook leads on "the record hid in plain sight" instead, but
  if the lane feels saturated, that is a real reason to shelve this rather than post it.

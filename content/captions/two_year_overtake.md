# Caption — Line: the calendar day each year passes the CVE total from two years earlier (`two_year_overtake`)

Image: `graphs/two_year_overtake_<ratio>_<date>.png`. House style: no em dashes; no
"n="; factual Title-Case heading + labels; post-date stamp. Volume/velocity lane.

Finding (verified, NVD publication date, non-rejected): 2026 passed the FULL 2024 CVE
total on July 16, 2026 (day 197 of the year). 2026 year-to-date is 40,116; all of 2024
was 39,952. The date each year overtakes the total from two years earlier has marched
steadily earlier: 2022 on Sep 23, 2023 on Sep 19, 2024 on Aug 17, 2025 on Aug 13, and
2026 on Jul 16. That is 28 days earlier than 2025 reached the same milestone and 32 days
earlier than 2024. It is the earliest crossing in the modern series (2019 onward). 2018
is excluded: its two-years-earlier baseline is 2016, an anomalously small year (~6,400
CVEs, a data-reboot artifact), so 2018 clears it in May for the wrong reason.

## LinkedIn / Mastodon
Attach: `two_year_overtake_wide_<date>.png` (or square/portrait).
```
As of July 16, the 2026 CVE count has passed a marker it took all of 2024 to reach: 39,952 CVEs. We are just past the halfway point of the year and already even with a full recent year, the total from two years ago.

Look at how fast that gap is closing. The year used to overtake the total from two years earlier in the fall: mid-November in 2020, late September in 2022, mid-August in 2025. This year it happened on July 16, about a month earlier than last year and the earliest in this series.

The two-years-ago total is no longer a year-end finish line, it is a summer checkpoint. If you size intake capacity against a recent full year, the volume has already moved past your plan. What are you using as your yardstick for a year that laps two-years-ago before August?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
By July 16, the 2026 CVE count hit 39,952, the entire 2024 total, with the year barely half over.

Each year now clears the two-years-earlier total sooner: mid-November in 2020, mid-August in 2025, mid-July in 2026. The earliest in this series.

The two-years-ago total is a summer checkpoint now, not a year-end line.
```

## Alt text
```
Line chart, one point per year from 2019 to 2026, showing the calendar date each year's
running CVE count passed the full-year total from two years earlier. The date moves
steadily earlier: mid-November in 2019 and 2020, mid-November 2021, late September 2022
and 2023, mid-August 2024 and 2025, and July 16 in 2026 (highlighted in red), the
earliest crossing shown. Source: NVD.
```

## Notes / caveats
- Metric: for each year Y, the first calendar day Y's cumulative non-rejected CVE count
  reaches year (Y-2)'s full-year total. The baseline changes each year, so this measures
  growth relative to two years prior, not against a fixed number.
- Series starts at 2019 so every baseline (2017 onward) is a normal modern year. 2018 is
  omitted because its 2016 baseline is anomalously small; including it would show a
  May crossing that is an artifact, not acceleration. Footnoted on the chart.
- 2020 is a small wobble (Nov 19, slightly later than 2019's Nov 13); kept honest rather
  than smoothed. The overall march is still clearly earlier.
- Y-axis is inverted so earlier dates sit higher and the record 2026 point is at the top.
- Numbers are as of the July 16, 2026 data refresh; 2024 full-year total is 39,952.
- Stamp is the post date (today_utc); the "earlier is faster growth" reading lives in the
  copy, not the chart title (factual Title-Case heading).

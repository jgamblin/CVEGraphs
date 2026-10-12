---
chart: daily_rate
posted: 2026-07-15
platforms: LI
migrated: 2026-10-11
---
# Caption — Line: CVEs published per day in 2026, 7-day rolling average (`daily_rate`)

Image: `graphs/daily_rate_<ratio>_<date>.png`. House style: no em dashes; factual
Title-Case heading + labels; post-date stamp. Volume/velocity lane.

Finding (verified, NVD publication date, non-rejected, seven-day rolling average): the 2026
daily CVE rate climbs within the year. Monthly means per day: Jan 139, Feb 165, Mar 201,
Apr 194, May 224, Jun 265, Jul 256. The 7-day rolling average runs ~100/day in the early-January
lull to a peak of ~354/day on July 14; it crosses its own ~200 average in late February; latest
~305 (last data day is the current partial day), last-30-day ~267. First crossed 200/day on
Feb 24. 2026 YTD mean ~203/day vs the 2025 full-year average of 132/day (about +54%). H1 2026
mean 198/day.

## LinkedIn / Mastodon
Attach: `daily_rate_wide_<date>.png`.
```
In 2026, CVEs are being published at about 200 a day, up from 132 a day in 2025. And the pace is still climbing inside the year: January averaged about 139 a day, June about 265, nearly double.

This is the seven-day rolling average of new CVEs, so daily spikes and weekend lulls wash out and the trend shows. The rate opened the year below the annual average, crossed it in late February, and the second half has run well above, reaching about 270 a day over the last month.

So the firehose is not just bigger than last year, it is accelerating within this one. Whatever your triage capacity was sized for, the intake has already outgrown it. What are you doing differently to keep up?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
In 2026, CVEs are published at about 200 a day, up from 132 in 2025.

And the pace is still climbing inside the year: January averaged about 139 a day, June about 265. The seven-day rolling average opened below the year's average, and the second half has run well above it.

The firehose is not just bigger than last year, it is accelerating within this one.
```

## Alt text
```
Line chart of the seven-day rolling average of non-rejected CVEs published per day in 2026,
January to mid-July. The line rises from about 100 per day in early January and surges to a peak
near 354 in mid-July, ending near 300. A dashed reference line marks the 2026 average of about
200 per day; the rolling line runs below it early in the year and well above it by the second
half. Source: NVD.
```

## Notes / caveats
- Seven-day rolling average by NVD publication date, non-rejected, to smooth the Patch-Tuesday
  spike and weekend lull. Reference line is the 2026 YTD daily average (~200/day, 203 at this refresh); the copy
  still cites the 2025 average (132/day) as the year-over-year comparison, not shown as a line.
- The last data day is the current (partial) day, so the final rolling point is provisional
  (1 of 7 in the window, so a small effect). As of this refresh July is near the year's peak
  (monthly mean 256, rolling peak 354 on Jul 14), not a dip.
- "Accelerating" is a within-year claim (Jan 139 -> Jun 265) plus a YoY one (132 -> ~203), both
  supported. Keep it to publication volume; it is not a claim about severity or exploitation.
- Stamp is the post date (today_utc); the data as-of lives in the footnote / Source line.
- Factual Title-Case heading; the growth story is in the post copy.

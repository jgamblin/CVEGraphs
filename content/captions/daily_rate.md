# Caption — Line: CVEs published per day in 2026, 7-day rolling average (`daily_rate`)

Image: `graphs/daily_rate_<ratio>_<date>.png`. House style: no em dashes; factual
Title-Case heading + labels; post-date stamp. Volume/velocity lane.

Finding (verified, NVD publication date, non-rejected, seven-day rolling average): the 2026
daily CVE rate climbs within the year. Monthly means per day: Jan 139, Feb 165, Mar 201,
Apr 194, May 224, Jun 265, Jul (partial) 205. The 7-day rolling average runs ~100/day in the
early-January lull to a peak of ~327/day on June 30 (June monthly mean 265); it crosses the 132
line in mid-February; latest ~219, last-30-day ~248. First crossed 200/day on Feb 24 (88 of 189
days above 200). 2026 YTD mean ~199/day vs the 2025 full-year average of 132/day (about +50%).
H1 2026 mean 198/day.

## LinkedIn / Mastodon
Attach: `daily_rate_wide_<date>.png`.
```
The CVE firehose is not just big this year, it is accelerating. In January 2026, published CVEs averaged about 139 a day. In June it was 265, nearly double.

This is the seven-day rolling average of new CVEs, so daily spikes and weekend lulls wash out and the trend shows. After a slow January that bottomed near 100 a day, the line climbed above the 2025 average of 132 by mid-February and has stayed there since, still climbing. The rate first crossed 200 a day in late February, and the last month has averaged about 248.

Half a year in, 2026 is running roughly 50% ahead of 2025 on a per-day basis. Whatever your triage capacity was last year, the intake it was sized for is already gone. What are you doing differently to keep up?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
The CVE firehose is not just big in 2026, it is accelerating.

January averaged about 139 new CVEs a day. June hit 265, nearly double. The seven-day rolling average climbed above 2025's 132 a day by mid-February and has stayed there since.

Whatever your triage was sized for last year, that intake is already gone.
```

## Alt text
```
Line chart of the seven-day rolling average of non-rejected CVEs published per day in 2026,
January to mid-July. The line rises from about 100 per day in early January to a peak near 327
in late June (May and July top out near 310), ending near 219. A dashed reference line marks the
2025 daily average of 132; the line crosses above it in mid-February and trends upward. Source: NVD.
```

## Notes / caveats
- Seven-day rolling average by NVD publication date, non-rejected, to smooth the Patch-Tuesday
  spike and weekend lull. Reference line is the 2025 FULL-YEAR daily average (~132/day).
- Be honest about the July dip (205/day vs June's 265): it is partly a partial month and a
  possible summer slowdown. The rolling line shows it rather than hiding it; do not crop it out.
- "Accelerating" is a within-year claim (Jan 139 -> Jun 265) plus a YoY one (132 -> ~199), both
  supported. Keep it to publication volume; it is not a claim about severity or exploitation.
- Stamp is the post date (today_utc); the data as-of lives in the footnote / Source line.
- Factual Title-Case heading; the growth story is in the post copy.

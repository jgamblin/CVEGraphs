# Caption — Ranked bars: biggest year-over-year jumps in monthly CVE volume (`yoy_month_growth`)

Image: `graphs/yoy_month_growth_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Volume lane. Built 2026-08-01 in answer to
"did July 2026 have the largest YoY growth ever?"

Finding (verified, NVD publication date, non-rejected, complete months only, data as of
2026-08-01): July 2026 published 9,775 CVEs against 3,776 in July 2025, an increase of
5,999 CVEs or 158.9%. That is the largest year-over-year increase of any month on record
by ABSOLUTE volume: rank 1 of 401 month-pairs. The prior record was June 2026 (+4,265), so
July beat it by 41%. By RAW percentage July 2026 ranks only 54th of 401, because the
program's early years had tiny bases (August 2001 went 3 to 205, +6,733%). Restricted to
months whose prior-year total was at least 1,000 CVEs (106 qualifying months), July 2026
ranks 1st. Top of that modern list: Jul 2026 +158.9%, Jun 2026 +115.9%, May 2024 +106.7%,
Aug 2019 +97.5%, Aug 2021 +80.5%, May 2026 +74.4%, Jun 2018 +72.6%, Sep 2025 +71.8%.
Three of the top six are 2026 months.

CONCENTRATION (the caveat that belongs in any copy): 68% of July's increase came from six
assigners. Oracle 77 to 1,108 (+1,031, its record 1,097-CVE CPU day on Jul 21), GitHub 271
to 1,294 (+1,023), VulnCheck 119 to 702 (+583), Microsoft 140 to 648 (+508), Chrome 6 to
487 (+481), Linux 401 to 837 (+436). Total increase on the CVE List basis +5,990.

## LinkedIn / Mastodon
Attach: `yoy_month_growth_wide_<date>.png` (or square/portrait).
```
The biggest growth record in CVE history was set by six organizations changing how they publish, not by software getting worse.

July 2026 published 9,775 CVEs against 3,776 in July 2025. Up 5,999, the largest year-over-year increase in volume any month has ever posted, and the previous record was June 2026. In percentage terms it is 159 percent, the highest for any month that had a real base to grow from.

Two thirds of the increase came from six assigners: Oracle, GitHub, VulnCheck, Microsoft, Google Chrome, and the Linux kernel. Oracle went from 77 to 1,108, and 1,097 of those landed on one scheduled day, its July 21 quarterly patch update. GitHub added another 1,023. Strip all six out and the rest of the ecosystem still grew 70 percent, which is a real increase, just not a record.

If your 2027 headcount case is built on a CVE growth curve, July is the month that curve started measuring Oracle's release calendar. The next batch lands in October: does your queue absorb a day like that, or does everything else in it just get older?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
The biggest growth record in CVE history is a publishing story, not a software story.

July 2026: 3,776 CVEs to 9,775, up 5,999. No month has ever added more year over year.

Two thirds of that came from six assigners. Oracle went 77 to 1,108, with 1,097 of them on one scheduled day.
```

## Alt text
```
Horizontal bar chart of the twelve largest year-over-year increases in monthly CVE
publishing. July 2026 leads at plus 159 percent, 3,776 CVEs rising to 9,775, shown in red
and clearly ahead of June 2026 at plus 116 percent and May 2024 at plus 107 percent. The
remaining bars run from plus 98 percent down to plus 60 percent. Each bar is labelled with
the month and the two counts. Only months whose prior-year total was at least 1,000 CVEs
are included. Source: NVD.
```

## Notes / caveats
- Metric: CVEs published in a calendar month (NVD publication date, non-rejected) against
  the same calendar month one year earlier. COMPLETE months only; the current partial month
  is excluded in code, so a re-render cannot compare a half month to a full one.
- THE 1,000 FLOOR IS A CHOSEN THRESHOLD and is disclosed on the chart with its reason.
  Without it the ranking is meaningless: Aug 2001 (3 to 205, +6,733%) and similar
  micro-base months occupy the top. State the floor whenever quoting the "number one"
  claim; do not say "largest percentage growth ever" unqualified, because on raw percentage
  July 2026 is 54th.
- The unqualified, defensible superlative is the ABSOLUTE one: largest year-over-year
  increase of any month on record (+5,999). Lead with that if only one claim fits.
- Concentration caveat is not optional. 68% of the increase is six assigners and the single
  largest contributor is one Oracle quarterly batch. Publishing this as "software is
  breaking 159% faster" would be wrong. Frame it as a publishing-behaviour story.
- Consistent with, and corroborated by, the 2026-07-30 carousel finding (same window year
  over year: CVEs +64%, active CNAs +13%) and cna_burst (Oracle's record 1,097-CVE day).
  This is the monthly-resolution view of the same regime change; it is not a new claim.
- Factual Title-Case heading; the argument lives in the post copy.

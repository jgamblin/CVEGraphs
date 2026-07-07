# Caption — Ridgeline: CVSS severity by year (`ridgeline_severity`)

Image: `graphs/ridgeline_severity_<ratio>_<date>.png`. House style: no em dashes.
Verified: mean CVSS 7.30 (2018) -> 6.59 (2025); 2026 partial at 6.89. The dashed
line on each ridge marks that year's average.

## LinkedIn / Mastodon
```
Are CVEs getting more severe every year? The data says no.

This is the distribution of CVSS scores for every year since 2018, one ridge per
year, with a dashed line at each year's average. Two things jump out:

The shape barely moves. The same clusters near 5, 7, and 9 repeat year after
year. CVSS scoring is remarkably stable.

The average has drifted down, not up: from about 7.3 in 2018 to the mid 6s in
recent years. As we catalog more and more vulnerabilities, a larger share land in
the medium range.

So the CVE explosion is not a severity explosion. We are recording far more
vulnerabilities, but on average they are not getting scarier. Volume is the
story, severity is not.

And the number that should drive your queue was never CVSS anyway, it is
exploitability. But that is another chart.

Does your team still prioritize primarily by CVSS?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
Are CVEs getting more severe every year? No.

CVSS score distribution by year, 2018 to 2026, one ridge each. The average has
drifted DOWN, from ~7.3 to the mid 6s. The shape barely changes.

More CVEs, not scarier ones. Volume is the story, not severity.
```

## Alt text
```
Ridgeline chart: nine stacked density curves, one per year 2018 to 2026, showing
the distribution of CVSS base scores. The shapes are similar across years with
peaks near 5, 7, and 9. A dashed vertical line marks each year's average, drifting
slightly left (lower) over time, from about 7.3 in 2018 to the mid 6s recently.
Source: NVD.
```

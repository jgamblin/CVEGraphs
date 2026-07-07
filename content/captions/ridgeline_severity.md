# Caption — Ridgeline: CVSS severity by year (`ridgeline_severity`)

Image: `graphs/ridgeline_severity_<ratio>_<date>.png`. House style: no em dashes.
Uses best-available CVSS base score (v4 when assigned, else v3) for ~99% coverage
every year. Verified means: 7.30 (2018) -> 6.44 (2025), 6.65 (2026 partial).
Critical share 15.4% (2018) -> ~9-10% now; Low (<4) 1.4% -> 8.9%; Medium is now
the biggest band. Paragraphs are single lines for clean LinkedIn paste.

## LinkedIn / Mastodon
```
Are CVEs getting more severe every year? The data says the opposite.

This is the distribution of CVSS scores for every year since 2018, one ridge per year, with a dashed line at each year's average. The averages have drifted left: from about 7.3 in 2018 to the mid 6s in recent years.

The mix shifted underneath that. Critical's share has fallen by about a third, from 15% of scored CVEs in 2018 to roughly 10% now. The single biggest bucket is now Medium, and a low-severity cluster that barely existed in 2018 (about 1%) has grown to roughly 9%.

So the record CVE volume is not a wave of ever-scarier bugs. We are cataloging far more vulnerabilities, and on average they are getting less severe, not more. Volume is the story; severity is drifting the other way.

One method note, because it matters: about a third of 2026 CVEs are now scored with CVSS v4 instead of v3, so this uses whichever base score was assigned. Drop v4 and you would be ignoring a third of the year.

And severity was never the number that should drive your queue anyway. CVSS is potential impact, not the odds anyone exploits it. That is a different chart.

Are you seeing severity drift down in your own data?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
Are CVEs getting more severe every year? No. The opposite.

CVSS score distribution by year, 2018 to 2026. The average drifts down, from ~7.3 to the mid 6s. Critical's share fell by a third (15% to ~10%); Medium is now the biggest bucket.

More CVEs, milder on average. (Uses CVSS v3/v4 for full coverage.)
```

## Alt text
```
Ridgeline chart: nine stacked density curves, one per year 2018 to 2026, of CVE
CVSS base scores (v3 or v4). A dashed vertical line marks each year's average; it
moves steadily left over time, from about 7.3 in 2018 to the mid 6s by 2026.
Recent years show more mass at the low and medium end, including a new cluster
near a score of 2. Source: NVD.
```

## Have ready in the comments (verified ammo)
- **"You dropped CVSS v4."** No, this uses v4 when assigned, else v3, ~99% coverage
  every year. v3-only would drop 35% of 2026 and bias the trend down further.
- **Band shift 2018 -> 2026:** Critical 15.4% -> 10.3%; High 45% -> 39%; Medium
  38% -> 41% (peaked ~52% in 2024-25); Low (<4) 1.4% -> 8.9%.
- **Why milder?** More ecosystem/mass-assigned CVEs (web plugins, libraries) that
  skew medium, plus v4 scoring a bit lower. It is a mix shift, not a scale change.
- **Not a severity-inflation story:** the "CVE explosion" is volume, not rising
  severity; exploitation (EPSS/KEV) is the real risk signal.

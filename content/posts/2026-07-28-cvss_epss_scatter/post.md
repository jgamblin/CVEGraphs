---
chart: cvss_epss_scatter
posted: 2026-07-28
platforms: LI
migrated: 2026-10-11
---
# Caption — Scatter: 2026 critical (9.0+) CVEs, CVSS vs EPSS, KEV highlighted (`cvss_epss_scatter`)

Image: `graphs/cvss_epss_scatter_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Scoring/measurement lane (Tuesday). Copy is
opinion-first (line one is an arguable claim). KEV LANGUAGE: say "added to KEV" / "on the
KEV list", never a blanket "exploited" (KEV is a curated subset; not-on-KEV is not
proof-of-not-exploited). See content/planning/INSIGHTS.md.

Finding (verified twice, NVD CVSS v3 + EPSS percentile + CISA KEV, published-in-2026 cohort,
data as of 2026-07-28): 4,719 CVEs carry a CVSS **v3** score of 9.0+; 2,493 of them (52.8%)
land on the identical 9.8. Only NINE distinct scores exist in the whole 9.0-10.0 band (no
9.5, no 9.7). EPSS percentile for the cohort: min 1.2, median 37.1, max 99.97. 54 are on
CISA KEV: median percentile 99.6, lowest 59. Cut at the 90th percentile and 211 CVEs contain
49 of the 54 (90.7% recall, 23.2% precision). Non-KEV criticals: median 37.1, only 3.5% at
the 90th+. On the chart, x = CVSS, y = EPSS PERCENTILE (0-100), red = added to CISA KEV; no
threshold line.
CORRECTIONS caught in review, do not reintroduce: (1) it is NOT "median 100th percentile" or
"up to the 100th" (real: 99.6 and 99.97); percentile is a rank fraction so nothing reaches a
true 100. (2) Say "CVSS v3": there are 318 more v4-only criticals (5,037 total), and this
audience was told on 2026-07-21 that v4 covers 34.5% of 2026. (3) 15.8% of the cohort are
not CVE-2026-* ids; the cohort is publication-date based, so say "published in 2026", not
"2026 CVEs". (4) The KEV/EPSS agreement is NOT prediction: all 54 were KEV-listed a median
59 days BEFORE these EPSS scores were computed (range 5-182 days), and EPSS ingests
exploitation signal. The copy states this caveat outright.
RESTRICTION OF RANGE (why the hook is scoped): CVSS does correlate with KEV across the full
range (KEV rate by band: 0.00% / 0.07% / 0.24% / 1.13%), so a 9.8 is ~15x likelier to reach
KEV than a 5.0. Never say CVSS "tells you nothing about exploitation" (that also contradicts
kev_severity, 2026-07-11, and the guardrail in cwe_kev.md). The honest, punchier claim is
WITHIN-band: it cannot tell you which 9.8 to do first.

## LinkedIn / Mastodon
Attach: `cvss_epss_scatter_wide_<date>.png` (or square/portrait).
```
CVSS is a severity label the industry treats like a priority list. A 9.8 tells you how bad a bug could be. It cannot tell you which 9.8 to do first.

This year 4,719 CVEs carry a CVSS v3 score of 9.0 or higher. Half of them, 2,493, land on the identical 9.8, the arithmetic result of a remote, unauthenticated, full-impact vector. Nine distinct scores exist in the entire critical band. There is no 9.5 and no 9.7. That is the resolution you are triaging with.

Rank the same 4,719 by EPSS percentile and the median lands at the 37th, so half the drop-everything tier ranks below 63% of all CVEs. Cut at the 90th percentile and 211 CVEs hold 49 of the 54 now on CISA's KEV list. One caveat: EPSS reads exploitation signal, and all 54 were listed before these scores were computed, so that is two sources agreeing, not a prediction. It still gives you an order. 9.8 does not.

2,493 CVEs this year share one score. If your tooling had to put them in a fix order tomorrow morning, what field would it sort on, and who would argue with you about it?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
CVSS is a severity label the industry treats like a priority list. A 9.8 tells you how bad a bug could be, not which 9.8 to do first.

This year 4,719 CVEs carry a CVSS v3 score of 9.0+. Half, 2,493, land on the identical 9.8. In the whole critical band only nine distinct scores exist: no 9.5, no 9.7. Rank the same set by EPSS and the median is the 37th percentile; the top decile holds 49 of the 54 now on CISA's KEV list.

One score, 2,493 CVEs. What would your tooling sort them on?
```

## Bluesky (300-char limit; the X copy above does not fit)
```
CVSS is a severity label the industry treats like a priority list. This year 4,719 CVEs scored CVSS v3 9.0+, and half carry the identical 9.8. Only nine distinct scores exist in that band: no 9.5, no 9.7. What would your tooling sort them on?
```

## Alt text
```
Scatter plot of 4,719 CVEs published in 2026 with a CVSS v3 base score of 9.0 to 10.0. The
x axis is the CVSS score, the y axis is EPSS percentile, the exploitation rank versus all
CVEs, from 0 to 100. Points form narrow columns at the nine scores that exist in this band,
with nothing at 9.5 or 9.7 and a dominant column at 9.8 holding 2,493 CVEs. The columns
spread across the full height of the percentile axis. Red points, 54 of them, mark CVEs
added to CISA KEV and sit near the top of the ranking. Sources: NVD, EPSS, CISA KEV.
```

## Notes / caveats
- Metric: 2026 CVEs (published-in-year) with a CVSS v3 base score and an EPSS score,
  filtered to CVSS >= 9.0. x = CVSS, y = EPSS PERCENTILE (0-100), red = on CISA KEV. No
  threshold line.
- PERCENTILE IS RANK, NOT LIKELIHOOD (keep copy honest): a 90th-percentile CVE is more
  likely to be exploited than 90% of all CVEs, which can still be a small absolute
  probability. Never pair this chart with a raw-probability claim ("a 0.45% chance"); the
  current copy talks only about ranking/spread, which is the correct frame for a triage post.
- Why percentile (Jay's feedback, 2026-07-27): the original used raw EPSS with a "danger
  band" at 0.5. That read as ANTI-EPSS (an arbitrary cutoff making it look like EPSS finds
  almost nothing) and invited "why is 50% the line?". A log axis fixed the crushing but felt
  abstract. Percentile drops the threshold entirely and shows EPSS doing useful work: the
  criticals spread 1st-100th, KEV clusters at the top. Frame stays pro-EPSS, anti-"CVSS as
  a priority list".
- KEV LANGUAGE (house rule, content/planning/INSIGHTS.md): "added to KEV" / "on the KEV list", never
  blanket "exploited". KEV is a curated subset; a CVE absent from KEV is NOT proven
  un-exploited. The copy says "added to CISA's KEV list" and explicitly notes "KEV is only
  the documented set" so it cannot be read as "these 54 are the only exploited ones."
- Why red = KEV (not a threshold): KEV is a variable the axes do not show, so the color
  earns its place, and "added to KEV" (documented) is a more concrete referent than a
  prediction cutoff.
- EPSS/KEV circularity (do not reintroduce): the KEV criticals sit at a median 99.6th
  percentile, but this is NOT evidence EPSS "predicted" or "flagged them in advance." All 54
  were KEV-listed a median of 59 days BEFORE the EPSS scores plotted here were computed
  (range 5-182 days; 39 of 54 over 30 days), and EPSS ingests exploitation signal, so the two
  are entangled. The copy states this outright ("two sources agreeing, not a prediction"),
  which is stronger than hiding it: it still gives you an order, which 9.8 does not.
- EPSS is a rolling 30-day forecast (percentile is that score's rank); KEV is
  documented-so-far. Both are point-in-time (EPSS model v2026.06.15 at this refresh); the
  54 count and the percentiles drift.
- Bonus story kept as one line: half of all criticals are the identical 9.8 (score
  compression). "Rubber stamp" was cut in review: 9.8 is the deterministic formula output
  for a remote, unauthenticated, full-impact bug, so it blames scorers for the scale's own
  lack of resolution. Say "the formula runs out of resolution", not "rubber stamp".
- Deconflicts with the Aug 1 monthly review (which shows the CVSS distribution); this shows
  CVSS vs EPSS vs KEV, a different and sharper point.
- POCKET ANSWERS for the comments (do not put in the body):
  - Right-censoring: these CVEs have had months, not years, of exposure, so the 54 on KEV are
    the fast-exploited tail. The KEV count for this cohort only rises from here; it is a
    floor, not a final rate.
  - Why 9.8 is so common: it is the deterministic CVSS output for a remote, unauthenticated,
    full-impact vector, and NVD serves whichever v3 metric set is listed first (often
    CNA-supplied), so the pileup is largely a CNA scoring habit, not negligence.
  - "Isn't this anti-EPSS?": the opposite. EPSS is what gives you an order; the target is
    using CVSS as a priority list.
  - "CVSS does correlate with exploitation": agreed, across the full range (KEV rate by band
    0.00 / 0.07 / 0.24 / 1.13%). The claim is scoped WITHIN the critical band.
- Factual Title-Case heading; the opinion lives in the copy.

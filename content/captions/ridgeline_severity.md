# Caption — Ridgeline: CVSS severity by year, v3 vs v4 (`ridgeline_severity`)

Image: `graphs/ridgeline_severity_<ratio>_<date>.png`. House style: no em dashes.
From 2024 the chart splits CVSS v3 (dark) and v4 (light) into their own ridges.

## ⚠️ CORRECTION (2026-07-08) — the "v4 scores lower" claim was wrong

The original post claimed a "clean proof": on ~18K CVEs scored with both v3 and v4
by the SAME org, v4 was ~0.76 lower 2/3 of the time. **That is largely a data
artifact in our own pipeline, not a version effect.** Re-verified against raw data:

- **The v4 numbers we charted are pulled low.** `refresh_data.py:254` extracts
  `metrics["cvssMetricV40"][0]` (the first v4 entry, no source/type selection). On
  the 25K CVEs with both, NVD-feed v4 averages **5.99 vs the CNAs' own CVE-List v4
  of 6.61** (mean −0.62). NVD v3 and CNA v3, by contrast, agree (mean diff 0.00).
  So v3 is fine; only v4 is systematically ~0.6 too low. That gap, not the version,
  produced most of the "v4 is lower" result.
- **True like-for-like** (same CNA's own v3 and v4 vectors on its own CVE, both from
  CVE-List, ~18,270 CVEs): mean v4 - v3 = **+0.10** (v4 a hair *higher*), strictly
  lower only **57%** (coin flip). Caveat: this pool is ~80% two bulk scorers (VulDB
  ~11.2K, VulnCheck ~3.4K), so it is not CNA-weighted; treat as directional.
- **No scorer-invariant per-CWE re-ranking.** VulDB and VulnCheck disagree on the
  *sign* for the headline classes: SQLi (CWE-89) VulDB -0.60 vs VulnCheck +0.43;
  XSS (CWE-79) VulDB +1.78 vs VulnCheck -0.86. A few classes agree (buffer down,
  SSRF down, info-leak up, path-traversal up), but "SQLi down / XSS up" is a VulDB
  artifact. **Do not publish it.**

**What survives:** year-over-year CVSS blends multiple scorers and two versions, and
*who* scores a CVE (and which feed you pull it from) moves the number more than which
version they used. The chart's shape by year is fine; the causal "v4 is a lower
ruler" claim was wrong, and the v4 ridges should be regenerated off CVE-List v4.

**✅ FIXED (2026-07-08):** root cause was the NVD JSON mirror carrying stale/low v4
base scores (6,978 CVEs), not our selection logic. `refresh_data.py` now reconciles
`cvss_v4` from the authoritative CVE-List CNA vector (`reconcile_nvd_v4`). Ridgeline
regenerated: 2025 v4 6.59 (= v3 6.59), 2026 v4 6.78 (vs v3 6.89); the both-scored
gap fell from −0.68 to −0.06. The "v4 scores lower" effect was ~90% the data bug.

## Update post (Jul 9) — the correction, with fixed data
Attach: corrected `ridgeline_severity_wide_<date>.png` + `scorer_divergence_wide_<date>.png`.
```
Follow-up to my CVSS v3-vs-v4 post. I said v4 scores about 0.7 points lower than v3, a commenter pushed back, and I promised new data. Here it is, and I was wrong.

The gap was almost entirely a data problem on my end. The v4 scores in the feed I was charting were running about 0.6 points low versus what the scoring organizations actually published. Once I pull v4 from the authoritative CNA records, the "v4 is lower" effect basically disappears. On the same bugs, v3 and v4 land within a rounding error: 2025 was v3 6.59 and v4 6.59, 2026 is v3 6.89 and v4 6.78.

So the clean version of the chart looks like this. v4 is not a lower ruler. It scores about the same, it just spreads a little differently.

The more interesting thing I found while digging: the number depends far more on WHO scores the CVE than on which version they use. Take the same weakness classes scored by two different big CNAs and they move v4 vs v3 in opposite directions. One marks XSS up, the other marks it down, same story for SQL injection.

And it is not noise. On the same bug classes, these two scorers sit about 1.4 CVSS points apart whether they use v3 or v4. Switching versions does not close that gap.

That is the real takeaway, and it is bigger than v3 vs v4. CVSS is not one ruler, it is a lot of rulers held by different hands. Comparing scores across years or vendors quietly compares scorers as much as severity.

Thanks to everyone who pushed on the first version. This is why I post the data and not just the conclusion.

How much do you trust CVSS base scores when they come from mixed sources?

#vulnerabilitymanagement #cybersecurity #CVE
```

## Reply to the pushback (posted correction)
```
Really good catch, and it's the right thing to push on. I went back to the raw data to check you, and you're right.

Correction first, and I've pinned this on the original post so it isn't just buried down here: my "v4 reads about 0.7 lower" figure was a data artifact, not a real version effect. The v4 scores in the feed I charted come out about 0.6 lower than the CNAs' own published v4 vectors (the v3 numbers match fine, it's only v4 that's pulled low), so I was partly charting a data-quality gap. Comparing like for like, the same CNA's own v3 and v4 on the same CVE, they land within a rounding error, basically a coin flip on which is lower. That one's on me.

One honest caveat so I don't just replace one bad number with another: that like-for-like pool leans heavily on a couple of bulk scorers, so I'm treating "no real gap" as directional rather than precise.

What still holds is the part worth taking into a steering meeting: year-over-year CVSS blends multiple scorers and two versions, so comparing 2026 severity to 2022 isn't apples to apples. If anything the deeper story is that who scores a CVE, and which feed you pull it from, moves the number more than which version they used.

How are you handling the v3/v4 mix in your own triage right now?
```

## LinkedIn / Mastodon (AS POSTED — contains the retracted v4-lower claim)
```
Are CVEs getting more severe every year? No. And a big part of the reason is a measurement change hiding in plain sight.

This is the CVSS score distribution for every year since 2018. From 2024 I split each year into CVSS v3 (dark) and CVSS v4 (light), because v4 went from a rounding error to a third of all scores in two years.

The light v4 ridges sit lower. And this is not a quirk of which CVEs happen to get v4. Look at the 18,000 vulnerabilities where the same organization scored the same bug with both v3 and v4: the v4 score comes out about 0.76 points lower, two-thirds of the time. Same bug, same scorer, different system, lower number.

That is not a flaw in v4, it is the point of it. v4 was built to be more discriminating than v3, which had a habit of pushing almost everything into High and Critical. So "average CVE severity is falling" is partly real (more medium-grade ecosystem CVEs) and partly just this: a fast-growing slice of CVEs is now scored with a ruler that reads lower.

Two takeaways. Comparing CVSS trends across, say, 2023 and 2026 now means partly comparing two different rulers, so be careful. And severity was never the number that should drive your queue anyway. Exploitability is. Different chart.

What share of your CVEs are scored with v4 yet?

#vulnerabilitymanagement #cybersecurity #CVE
```

## Alt text
```
Ridgeline chart of CVE CVSS base scores by year, 2018 to 2026. Years 2018 to 2023
are single dark ridges (CVSS v3). From 2024 each year has two ridges: dark for v3
and light for v4. NOTE: the v4 ridges use NVD-feed v4 scores that run about 0.6
points below the CNAs' published v4, so the apparent v4-lower shift is largely a
data artifact rather than a real v3-to-v4 difference. Source: NVD.
```

## Verified ammo (corrected)
- **The headline claim was a data artifact.** Our `cvss_v4` is pulled from
  `cvssMetricV40[0]` and runs ~0.6 below the CNAs' authoritative CVE-List v4 (NVD
  5.99 vs 6.61); v3 matches. Like-for-like (CNA's own v3 and v4, ~18,270 CVEs) shows
  v4 +0.10, lower 57% (coin flip).
- **Backfiller caveat:** the like-for-like pool is ~80% VulDB + VulnCheck, not
  CNA-representative; report "no real gap" as directional.
- **Per-CWE re-ranking is scorer-dependent.** VulDB vs VulnCheck disagree on the sign
  for SQLi and XSS, so any per-CWE v4/v3 chart must hold the scorer fixed and is that
  scorer's convention, not a v4 property.
- **What holds:** cross-year CVSS mixes scorers, versions, and feeds; who/where you
  score dominates which version; exploitation (EPSS/KEV), not CVSS, is the triage signal.
- **Action:** fix the v4 extraction (select CNA/primary v4 or read CVE-List v4), then
  regenerate the ridgeline before making any v4-magnitude claim.
```

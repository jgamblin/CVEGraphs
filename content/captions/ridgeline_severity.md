# Caption — Ridgeline: CVSS severity by year, v3 vs v4 (`ridgeline_severity`)

Image: `graphs/ridgeline_severity_<ratio>_<date>.png`. House style: no em dashes.
From 2024 the chart splits CVSS v3 (dark) and v4 (light) into their own ridges.
Verified: on 25,154 CVEs scored BOTH ways, v4 is 0.68 lower on average and lower
65% of the time. v4 share: ~0% pre-2024 -> 8.9% (2024) -> 25.8% (2025) -> 35% (2026).
Population means 2025: v3 6.59 / v4 5.94; 2026: v3 6.89 / v4 6.22. Single lines
for clean LinkedIn paste.

## LinkedIn / Mastodon
```
Are CVEs getting more severe every year? No. And a big part of the reason is a measurement change hiding in plain sight.

This is the CVSS score distribution for every year since 2018. From 2024 I split each year into CVSS v3 (dark) and CVSS v4 (light), because v4 went from a rounding error to a third of all scores in two years.

The light ridges sit lower. CVSS v4 scores vulnerabilities below what v3 would have. And this is not a quirk of which CVEs get v4: on the 25,000 vulnerabilities that carry both a v3 and a v4 score, v4 comes out 0.68 points lower on average, and lower about two-thirds of the time. Same vulnerability, lower number, because the ruler changed.

So "average CVE severity is falling" is partly real (more medium-grade ecosystem CVEs) and partly just this: a fast-growing slice of CVEs is now measured with a system that scores lower.

Two takeaways. Comparing CVSS trends across, say, 2023 and 2026 now means partly comparing two different rulers, so be careful. And severity was never the number that should drive your queue anyway. Exploitability is. Different chart.

What share of your CVEs are scored with v4 yet?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
Are CVEs getting more severe? No, and there is a twist.

CVSS v4 is now a third of all scores, and it rates the same bugs lower than v3. On 25,000 CVEs scored both ways, v4 came out 0.68 points lower on average.

"Average severity is falling" is partly just a change of ruler.
```

## Alt text
```
Ridgeline chart of CVE CVSS base scores by year, 2018 to 2026. Years 2018 to 2023
are single dark ridges (CVSS v3). From 2024 each year has two ridges: dark for v3
and light for v4. The light v4 ridges sit lower and wider than the dark v3 ones,
with a distinct low cluster near a score of 2, showing v4 scores vulnerabilities
lower than v3. Source: NVD.
```

## Have ready in the comments (verified ammo)
- **The clean proof:** 25,154 CVEs have both a v3 and a v4 score; v4 averages 0.68
  lower (median 6.0 vs 6.5) and is lower on 65% of them. So it is the scoring
  system, not just which CVEs get v4.
- **v4 adoption:** ~0% through 2023, 8.9% (2024), 25.8% (2025), 35.0% (2026).
- **Population means:** 2025 v3 6.59 / v4 5.94; 2026 v3 6.89 / v4 6.22.
- **"v4 is supposed to score differently."** Correct, by design (reworked metrics).
  The point is not that v4 is wrong, it is that CVSS trend lines now mix two rulers.
- **Not a severity-inflation story:** the CVE explosion is volume; exploitation
  (EPSS/KEV) is the real risk signal.

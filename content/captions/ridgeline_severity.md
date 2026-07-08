# Caption — Ridgeline: CVSS severity by year, v3 vs v4 (`ridgeline_severity`)

Image: `graphs/ridgeline_severity_<ratio>_<date>.png`. House style: no em dashes.
From 2024 the chart splits CVSS v3 (dark) and v4 (light) into their own ridges.
Verified (same-source control, isolates the system from the scorer): on 18,247
CVEs where the SAME org scored the bug with both v3 and v4, v4 is 0.76 lower,
67% of the time. Across all 25,154 both-scored (any scorer): 0.68 lower, 65%.
v4 share: ~0% pre-2024 -> 8.9% (2024) -> 25.8% (2025) -> 35% (2026). Population
means 2025: v3 6.59 / v4 5.94; 2026: v3 6.89 / v4 6.22. Single lines for paste.

## LinkedIn / Mastodon
```
Are CVEs getting more severe every year? No. And a big part of the reason is a measurement change hiding in plain sight.

This is the CVSS score distribution for every year since 2018. From 2024 I split each year into CVSS v3 (dark) and CVSS v4 (light), because v4 went from a rounding error to a third of all scores in two years.

The light v4 ridges sit lower. And this is not a quirk of which CVEs happen to get v4. Look at the 18,000 vulnerabilities where the same organization scored the same bug with both v3 and v4: the v4 score comes out about 0.76 points lower, two-thirds of the time. Same bug, same scorer, different system, lower number.

That is not a flaw in v4, it is the point of it. v4 was built to be more discriminating than v3, which had a habit of pushing almost everything into High and Critical. So "average CVE severity is falling" is partly real (more medium-grade ecosystem CVEs) and partly just this: a fast-growing slice of CVEs is now scored with a ruler that reads lower.

Two takeaways. Comparing CVSS trends across, say, 2023 and 2026 now means partly comparing two different rulers, so be careful. And severity was never the number that should drive your queue anyway. Exploitability is. Different chart.

What share of your CVEs are scored with v4 yet?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
Are CVEs getting more severe? No, and there is a twist.

CVSS v4 is now a third of all scores, and it rates the same bugs lower than v3. On 18,000 CVEs where the same org scored a bug with both, v4 came out ~0.76 points lower, two-thirds of the time.

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
- **The clean proof (kills "different scorers"):** 18,247 CVEs were scored with
  both v3 and v4 by the SAME organization; v4 averages 0.76 lower and is lower on
  67% of them. Same scorer, so it is the scoring system, not who scored it.
  Across all 25,154 both-scored (any scorer): 0.68 lower, 65%.
- **v4 adoption:** ~0% through 2023, 8.9% (2024), 25.8% (2025), 35.0% (2026).
- **Population means:** 2025 v3 6.59 / v4 5.94; 2026 v3 6.89 / v4 6.22.
- **"v4 is supposed to score differently."** Correct, by design (reworked metrics).
  The point is not that v4 is wrong, it is that CVSS trend lines now mix two rulers.
- **Not a severity-inflation story:** the CVE explosion is volume; exploitation
  (EPSS/KEV) is the real risk signal.

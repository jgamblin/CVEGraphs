---
chart: cvss_v4_adoption
posted: 2026-07-21
platforms: LI
migrated: 2026-10-11
---
# Caption — Stacked bars: CVSS v4 adoption by year, 3 heavy-adopter CNAs vs the rest (`cvss_v4_adoption`)

Image: `graphs/cvss_v4_adoption_<ratio>_<date>.png`. House style: no em dashes; no
"n="; factual Title-Case heading + labels; post-date stamp. Scoring/measurement lane
(Tuesday slot).

Finding (verified, CVE List V5 CNA vectors, non-rejected, by publication year, data as
of 2026-07-21): CVSS v4 shipped November 2023, so 2024 was its first full year. The share
of CVEs carrying a v4 base score has climbed from 8.9% (2024) to 25.8% (2025) to 34.5%
(2026 YTD); 2023 itself was ~0.2% and is not charted. But the growth is concentrated:
three CNAs (VulnCheck, VulDB, GitHub) account for 71% of all 2026 v4 scores, and they are
24.6 of the 34.5 points. The other 200+ CNAs that have used v4 land at ~10% of all CVEs in
2026, up from ~4% in 2024: real growth, but a fraction of what the three added. Holding the
scorer fixed (same CVE List record scored in both versions, 8,472 CVEs in 2026, of which
~86% are VulDB + VulnCheck), the v4-v3 shift is a wash: mean +0.09, median -0.10, v4 higher
46% / lower 52%. So among the CNAs that dual-score, the version is not harsher or softer. v4
is read from CVE List (the CNA's own vector), not the NVD feed.

## LinkedIn / Mastodon
Attach: `cvss_v4_adoption_wide_<date>.png` (or square/portrait).
```
A third of 2026 CVEs so far carry a CVSS v4 score, up from under 9% in 2024. Fast climb for a scoring system that only shipped in late 2023, and on paper v4 looks like it is catching on.

Then you split it by who did the scoring. Three CNAs, VulnCheck, VulDB, and GitHub, account for 71% of every v4 score this year. Strip them out and the other 200-plus CNAs land around 10% of all CVEs, up from about 4% in 2024. Real growth, but a fraction of what those three added. Most of the rise of v4 is three organizations, not the whole ecosystem.

And when the same scorer rates a bug both ways, it is close to a coin flip: v4 higher 46% of the time, lower 52%, a net shift of essentially zero (mean +0.09). The two versions rarely land on the same number, but it washes out in aggregate. Worth noting this set is mostly VulDB and VulnCheck, aggregators who dual-score in bulk, and it is only the base score. v4's added metrics like Automatable and Provider Urgency are a separate question this does not touch.

Are you seeing v4 scores show up in your tooling yet, or is it still v3 in practice?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
A third of 2026 CVEs so far carry a CVSS v4 score, up from under 9% in 2024. Fast climb for a version that only shipped in late 2023.

Then you see who did it: VulnCheck, VulDB, and GitHub are 71% of all v4 scores. The other 200+ CNAs went from ~4% to ~10%, real growth but nowhere near those three. Most of the rise of v4 is three organizations.

And when the same scorer rates a bug both ways, it is close to a coin flip, higher about as often as lower, net shift near zero. Are you seeing v4 in your tooling yet?
```

## Alt text
```
Stacked bar chart of the share of each year's CVEs that carry a CVSS v4 base score, 2024
to 2026, split by who assigned it. Total rises from 8.9% in 2024 to 25.8% and 34.5%. In
every year the dark segment (three CNAs: VulnCheck, VulDB, GitHub) is the majority; the
light segment (all other CNAs) rises from about 4% in 2024 to about 10% in 2026. Source:
CVE List V5.
```

## Notes / caveats
- v4 presence is read from the CVE List record (the CNA's own CVSS vector), not the NVD
  feed. NVD's v4 pass-through now roughly matches CVE List (~14.2k for 2026), so the two
  agree, but CVE List is the correct source for "which CNA chose v4."
- "Adoption" here means a v4 score is present, usually in ADDITION to a v3 score. Nearly
  every CVE still gets a v3 (NVD scores ~94% of 2026 CVEs in v3), so v4 is a supplement,
  not a replacement. Say "carry a v4 score," not "switched to v4."
- The v4-v3 shift is measured on the SAME record (scorer held fixed) to isolate the
  version, not the scorer. This is the honest comparison and it nets to ~0. See the
  scorer_divergence chart: the gap is a property of the scorer, not the version. Do not
  claim "v4 scores lower" from a naive NVD-v3-vs-CNA-v4 comparison (scorer confound).
- GitHub_M is GitHub's CNA short name; labelled "GitHub" on the chart.
- Factual Title-Case heading; the "three CNAs drive it" and "barely moves the number"
  reads live in the post copy.

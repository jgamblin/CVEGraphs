# Insight brief — as of Jul 07, 2026

Ranked share-worthiness candidates from the current data. Curate the top
few into posts (pair each with `suggested_chart`). Scores are heuristic:
records/flips and exploitation rank highest, routine stats lower.

## 1. [92] Of 37,136 CVEs published in 2026, only 90 (0.24%) are on CISA's KEV list so far
- **why**: A floor that rises as the cohort ages, not a final rate. Confirmed exploitation stays rare while volume climbs, the whole triage story.
- **category**: exploitation  ·  **chart**: `epss_funnel`

## 2. [90] 2026 year-to-date (37,136) already exceeds every full year before 2024
- **why**: Six-plus months of 2026 outrank all of 2023 (28,817) and every year prior.
- **category**: record  ·  **chart**: `pace`

## 3. [88] June 2026 was the busiest CVE month ever: 7,950
- **why**: No calendar month in the program's history published more CVEs.
- **category**: record  ·  **chart**: `pace`

## 4. [87] Only 47 of 2026's 37,136 CVEs (0.13%) score EPSS >= 0.5
- **why**: 223 (0.6%) clear EPSS 0.1. Predicted exploitation is as rare as confirmed: model v2026.06.15.
- **category**: exploitation  ·  **chart**: `epss_funnel`

## 5. [83] Newest CISA KEV entry: CVE-2026-48908 (JoomShaper SP Page Builder), added Jul 07
- **why**: The most recent confirmed-exploited CVE. Timely by definition.
- **category**: recent  ·  **chart**: `kev`

## 6. [80] CVE-2026-43284 has the highest EPSS of 2026 not on KEV: 0.932
- **why**: linux / linux_kernel. High predicted risk the confirmed list hasn't caught up to.
- **category**: exploitation  ·  **chart**: `epss_funnel`

## 7. [78] CISA added 23 CVEs to KEV in the last 30 days, 2 ransomware-linked
- **why**: Exploitation news travels; a fresh KEV batch is always timely.
- **category**: kev  ·  **chart**: `kev`

## 8. [78] chrome disclosed 52 CVEs in one day (2026-07-01)
- **why**: A single-day mass disclosure. Verify against the vendor's release notes before posting.
- **category**: recent  ·  **chart**: `kev`

## 9. [76] GitHub_M is 2026's top CVE issuer with 6,978 (19% of all published)
- **why**: The CNA mix reflects who has scope, not who ships the worst code.
- **category**: mover  ·  **chart**: `cna`

## 10. [74] The busiest CVE weekday in 2026 is Wednesday (not Tuesday)
- **why**: Wednesday: 8,314 vs Tuesday: 7,816. The 'Patch Tuesday' mental model does not match the data.
- **category**: curio  ·  **chart**: `rhythm`

## 11. [74] Highest-EPSS new CVE since Jul 01: CVE-2026-27771 at 0.407
- **why**: The most likely-to-be-exploited of the freshly published set.
- **category**: recent  ·  **chart**: `kev`

## 12. [72] 37,136 CVEs published so far in 2026, one every 7.3 minutes
- **why**: 198/day, +52% vs 2025 at the same point. Straight-line run-rate lands near 72,100 for the full year.
- **category**: pace  ·  **chart**: `pace`

## 13. [68] The CVE catalog is at 346,029, 3,971 short of 350,000
- **why**: At the current rate it crosses 350,000 in about 20 days.
- **category**: record  ·  **chart**: `pace`

## 14. [66] The single biggest CVE day of 2026: 2026-06-09 with 747
- **why**: Batch publishing by high-volume CNAs drives these spikes.
- **category**: curio  ·  **chart**: `rhythm`

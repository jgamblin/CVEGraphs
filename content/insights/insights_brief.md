# Insight brief — as of Sep 08, 2026

Ranked share-worthiness candidates from the current data. Curate the top
few into posts (pair each with `suggested_chart`). Scores are heuristic:
records/flips and exploitation rank highest, routine stats lower.

## 1. [92] Of 60,142 CVEs published in 2026, only 146 (0.24%) are on CISA's KEV list so far
- **why**: A floor that rises as the cohort ages, not a final rate. Confirmed exploitation stays rare while volume climbs, the whole triage story.
- **category**: exploitation  ·  **chart**: `epss_funnel`

## 2. [90] 2026 year-to-date (60,142) already exceeds every full year before 2026
- **why**: Six-plus months of 2026 outrank all of 2025 (48,153) and every year prior.
- **category**: record  ·  **chart**: `pace`

## 3. [88] August 2026 was the busiest CVE month ever: 12,269
- **why**: No calendar month in the program's history published more CVEs.
- **category**: record  ·  **chart**: `pace`

## 4. [87] Only 75 of 2026's 60,142 CVEs (0.12%) score EPSS >= 0.5
- **why**: 308 (0.5%) clear EPSS 0.1. Predicted exploitation is as rare as confirmed: model v2026.06.15.
- **category**: exploitation  ·  **chart**: `epss_funnel`

## 5. [83] Newest CISA KEV entry: CVE-2026-19490 (Citrix NetScaler), added Sep 09
- **why**: The most recent confirmed-exploited CVE. Timely by definition.
- **category**: recent  ·  **chart**: `kev`

## 6. [80] CVE-2026-43284 has the highest EPSS of 2026 not on KEV: 0.932
- **why**: linux / linux_kernel. High predicted risk the confirmed list hasn't caught up to.
- **category**: exploitation  ·  **chart**: `epss_funnel`

## 7. [80] microsoft published 492 more CVEs this month than last
- **why**: A sharp month-over-month surge worth a closer look.
- **category**: mover  ·  **chart**: `cna`

## 8. [78] CISA added 41 CVEs to KEV in the last 30 days, 0 ransomware-linked
- **why**: Exploitation news travels; a fresh KEV batch is always timely.
- **category**: kev  ·  **chart**: `kev`

## 9. [78] chrome disclosed 21 CVEs in one day (2026-09-02)
- **why**: A single-day mass disclosure. Verify against the vendor's release notes before posting.
- **category**: recent  ·  **chart**: `kev`

## 10. [76] GitHub_M is 2026's top CVE issuer with 9,602 (16% of all published)
- **why**: The CNA mix reflects who has scope, not who ships the worst code.
- **category**: mover  ·  **chart**: `cna`

## 11. [72] 60,142 CVEs published so far in 2026, one every 6.0 minutes
- **why**: 240/day, +87% vs 2025 at the same point. Straight-line run-rate lands near 87,500 for the full year.
- **category**: pace  ·  **chart**: `pace`

## 12. [68] The CVE catalog is at 369,015, 985 short of 370,000
- **why**: At the current rate it crosses 370,000 in about 4 days.
- **category**: record  ·  **chart**: `pace`

## 13. [66] The single biggest CVE day of 2026: 2026-07-21 with 1,474
- **why**: Batch publishing by high-volume CNAs drives these spikes.
- **category**: curio  ·  **chart**: `rhythm`

## 14. [60] The busiest CVE weekday in 2026 is Tuesday
- **why**: Tuesday: 14,503 vs Wednesday: 11,676. The 'Patch Tuesday' mental model does not match the data.
- **category**: curio  ·  **chart**: `rhythm`

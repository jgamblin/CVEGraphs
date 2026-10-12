# Caption — Lines: who attaches a CVE's weakness class, by CNA over time (`cwe_provenance`)

Image: `graphs/cwe_provenance_<ratio>_<date>.png`. House style: no em dashes.
**Status: built and rendered, NOT the chart that shipped.** Lost the Thu Aug 13 2026
slot to its companion `cwe_cna_rank`, which shows the same finding in one glance.
Keep it: it is the only chart that carries the switch-flip trajectories, and it is
the natural follow-up if the ranked version lands.

Data: CVE List V5, published and non-rejected, by publication date.

## What it shows

Share of each CNA's CVEs carrying a CNA-supplied CWE, by publication year, 2019 to
2026 YTD. All 36 CNAs with 250+ CVEs in a year are drawn as faint grey lines so the
bimodal shape is visible, over the all-CVE baseline and two named exemplars:

| Series | 2019 | 2020 | 2021 | 2022 | 2023 | 2024 | 2025 | 2026 |
|--------|------|------|------|------|------|------|------|------|
| All published CVEs | 12.7 | 19.2 | 34.4 | 42.6 | 61.5 | 66.9 | 74.2 | 80.1 |
| Microsoft | 0 | 0 | 0 | 0 | 82 | 100 | 100 | 99.7 |
| Oracle | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

Two exemplars only: turned it on (Microsoft), never turned it on (Oracle).

**The "turned it off" exemplar was removed as false.** An earlier build drew WPScan
falling from 99% in 2021 to 0% from 2023. That was an artifact of the CWE parser
reading only the optional `cweId` key, which WPScan does not set. Corrected, WPScan
runs 100, 99, 100, 100, 100, 100 across 2021-2026. No CNA with volume moved down by 25
points or more in the last two years; all eight movers of that size went up. See the
parser section in `content/posts/2026-08-13-cwe_cna_rank/post.md`.

Decomposition of the 2019 to 2026 aggregate rise, recomputed after the 2026-08-13
parser fix (+67.4 points total): within-CNA improvement 32.3 points (48%), CNA mix
shift 9.2 points (14%), interaction from new high-coverage entrants 25.9 points (38%).
So roughly half is existing CNAs changing behaviour and half is the arrival and growth
of CNAs that always did it. Note both endpoints here are full-year 2019 against YTD
2026; YTD-matched 2019 is 13.6%, so quote the decomposition as approximate.

## Why the KEV version was killed

The first build of this chart plotted the **KEV cohort** against all CVEs and made
the 2020-2023 crossover its sharpest claim: that the CVEs which later landed on KEV
were documented worse than average. Two independent problems:

1. **KEV is far too small for the job.** 1,665 CVEs against 376,000+, with per-year
   cohorts of only 118 to 213.
2. **The gap was a CNA-composition artifact.** KEV over-indexes on MITRE, Microsoft,
   Apple and Chrome, which supplied a CWE on 0.0% of *everything* they published in
   2021, not just their KEV entries. Those four were 50-63% of the early KEV cohorts
   against 27-55% of all CVEs. Mix-adjust the baseline to the KEV cohort's CNA
   composition and the gap vanishes: the 2021 gap falls from 12.8 points to 2.3, and
   2022 flips sign.

Comparing CNAs directly, as this version does, removes the confound because the CNA
becomes the unit of analysis instead of a lurking variable. See the memory note
`kev-cohort-cna-composition-confound`.

## Notes / caveats
- Copy for the shipped post lives in `content/posts/2026-08-13-cwe_cna_rank/post.md`. If this
  chart is ever posted, the standing guards there apply verbatim: no timing claim, no
  "read the CNA instead of NVD" recommendation, scope held to the weakness class and
  never "enrichment".
- A CNA-year is plotted only at 250+ CVEs, so a grey line starts when that CNA
  reaches real volume rather than at an arbitrary date.
- Measured on the current record, which a CNA can update after publication.
- 2026 is a partial year; the axis labels it "2026 YTD".
- Legend sits above the axes on purpose. Inside the axes it covered the dense 100%
  cluster of grey lines, which is the evidence the chart exists to show.
- **Data current as of 2026-08-13** (376,628 CVEs).

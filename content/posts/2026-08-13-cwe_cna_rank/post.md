---
chart: cwe_cna_rank
posted: 2026-08-13
platforms: LI
migrated: 2026-10-11
---
# Caption: Ranked bars, CWE coverage by CNA (`cwe_cna_rank`)

Image: `graphs/cwe_cna_rank_<ratio>_<date>.png`. House style: no em dashes.
Data-quality lane, in the `cna_spread` family (named-CNA accountability, the
best-performing chart lane at 3,686 impressions and 17 comments).
Data: CVE List V5, published and non-rejected, current year to date.

**STATUS: cleared to post today, Thu Aug 13 2026.** The review's ship-date hold was
withdrawn because its premise was wrong: it read a `cwe_provenance` row in the CALENDAR
Log dated 2026-08-13 as a published post, but that row was a placeholder written while
planning and has since been deleted. Verified against LinkedIn creator analytics on
Aug 13: nothing posted that day or the day before, newest was the Tue pace post at 1,570
impressions. This is the second chart post of the Aug 10-16 week, inside the two-post cap.

Thursday is nominally the exploitation slot and this is a data-quality chart, so it takes
the Thu slot off-lane. Exploitation has now been dark since Jul 14. Worth noting for next
week's planning, not a reason to hold.

Images are stamped **Aug 13** via `CVEGRAPHS_POST_DATE=2026-08-13`. If the post slips a
day, re-render or the stamp lies:
`CVEGRAPHS_POST_DATE=2026-08-14 cvegraphs render cwe_cna_rank`

**Attach the PORTRAIT to LinkedIn, not the wide.** Nineteen rows of CNA names do not
survive the wide aspect at phone width, and the names are the entire payload.

## Finding (verified on data reprocessed 2026-08-13, after the CWE parser fix below)

Share of each CNA's 2026 CVEs carrying a **CNA-supplied** CWE. 19 CNAs published
250+ CVEs this year: 39,112 of 49,793, or **79% of all volume**. All-CVE average
**80.09%**, shown as 80%.

| CNA | Coverage | 2026 CVEs |  | CNA | Coverage | 2026 CVEs |
|-----|---------|-----------|--|-----|---------|-----------|
| GitHub | 100.0% | 8,577 | | Apache | 98.1% | 635 |
| VulDB | 100.0% | 3,994 | | IBM | 96.5% | 545 |
| Patchstack | 100.0% | 3,285 | | Red Hat | 96.4% | 671 |
| Wordfence | 100.0% | 2,538 | | **Chrome** | **66.8%** | 2,118 |
| WPScan | 100.0% | 697 | | **MITRE** | **14.0%** | 2,417 |
| Adobe | 100.0% | 565 | | Linux | **0.0%** | 3,810 |
| GitLab | 100.0% | 262 | | Oracle | **0.0%** | 1,552 |
| Microsoft | 99.7% | 1,926 | | Apple | **0.0%** | 519 |
| ICS-CERT | 99.7% | 322 | | Mozilla | **0.0%** | 341 |
| VulnCheck | 99.7% | 4,338 | | | | |

**The distribution is a switch, not a gradient.** Thirteen CNAs at 96% or better,
four at exactly 0.0%, and only Chrome and MITRE anywhere in between. The four
zero-coverage CNAs account for **6,222 CVEs**. The 80% average lands in the empty gap
between Red Hat (96.4%) and Chrome (66.8%), so it describes no CNA on the chart.

Supporting facts used in the copy, all recomputed after the parser fix:
- **Microsoft flipped and stayed:** 0.00% every year through 2022 (845, 1,262, 871,
  931 CVEs), then 82.29% in 2023, 100.00% in 2024 and 2025, 99.74% in 2026.
- **The movement is one-directional.** Among CNAs with 50+ CVEs in 2024 and 100+ in
  2026, eight moved by 25 points or more and **all eight moved up**, none down:
  HackerOne 0.0 to 73.7, jpcert 34.2 to 100.0, HCL 26.7 to 92.0, canonical 39.2 to
  100.0, VMware 27.8 to 86.6, AMD 43.1 to 93.8, MediaTek 53.6 to 100.0, Chrome 28.0
  to 66.8.
- **NVD covers most of what the four never name, except Linux.** NVD has a CWE on
  65.0% of the four zeros' 6,222 records: Mozilla 99.1%, Oracle 97.5%, Apple 96.9%,
  but Linux only **44.3%**.

## THE PARSER BUG THIS POST ALMOST SHIPPED

The first build printed a red **0.0% next to WPScan**. That was wrong, and it was the
one number a named vendor could have refuted with a link to its own JSON.

`refresh_data.py` extracted a CWE only from the optional `cweId` key in
`problemTypes.descriptions[]`. WPScan never sets it. It writes the class into
`description` as `"CWE-79 Cross-Site Scripting (XSS)"` with `"type": "CWE"`. Verified
against `data/cvelistV5`: **all 697 of WPScan's 2026 published records carry a
`CWE-<n>` in description text and exactly zero have `cweId`.** WPScan's real figure is
100.0%.

Fixed at `refresh_data.py` (`CWE_IN_TEXT`): count a CWE when `cweId` is set **or** the
description matches `\bCWE-\d+`. What moved: WPScan 0.0 to 100.0, Apache 97.95 to
98.11, and below the 250 floor CERT/CC 1.3 to 100.0 and Samsung Mobile 0.9 to 100.0.
Corpus-wide the metric moved 39.59% to 40.90%. All-CVE 2026 average 77.79% to 80.09%.

**The other four zeros are airtight, checked the same way:** Linux and Mozilla emit no
`problemTypes` block at all; Apple (519/519) and Oracle (1,552/1,552) emit untyped
impact prose with no CWE ID and no `CWE-<n>` anywhere in the text.

**There is no reversal in this data.** The killed draft claimed "WPScan was at 99% in
2021 and has sat at zero since 2023". Corrected, WPScan runs 100.0, 99.0, 100.0,
100.0, 100.0, 100.0 across 2021 to 2026. They never stopped classifying, they stopped
emitting `cweId`. Do not reintroduce a "some CNAs went backwards" line: no CNA with
volume moved down by 25 points or more in the last two years.

## LinkedIn / Mastodon
Attach: `cwe_cna_rank_portrait_<date>.png`.
```
No CNA is mediocre at attaching a weakness class. They either always do it or they never do.

Of the nineteen CNAs that published 250 or more CVEs this year, thirteen sit at 96% or better and four sit at exactly zero. Not low, zero: Linux 3,810 CVEs, Oracle 1,552, Apple 519, Mozilla 341. Chrome at 67% and MITRE at 14% are the only two of the nineteen anywhere in between, so the 80% average describes nobody on the chart.

It flips fast when a CNA decides it should, and it only flips one way. Microsoft published nothing through 2022, hit 82% in 2023, and has been at 100% or a rounding error from it since. Every CNA with volume that moved on this field in the last two years moved up: HackerOne from zero to 74%, Chrome from 28% to 67%.

NVD and CISA classify most of what those four never name, though only about 44% of the Linux records, so union the sources rather than swapping one for the other.

Would you rather a CNA attach a weakness class it is only mostly sure of, or leave it off?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
279 characters, verified against the 280 limit.
```
No CNA is mediocre at attaching a weakness class. They always do, or they never do.

Of 19 CNAs with 250+ CVEs in 2026, thirteen are at 96%+, four at exactly zero:

Linux 3,810 / Oracle 1,552 / Apple 519 / Mozilla 341

NVD fills most of it. Should a CNA guess, or leave it blank?
```

## Alt text
```
Horizontal bar chart ranking 19 CVE Numbering Authorities by the share of their 2026 CVEs that carry a CNA-supplied CWE weakness class, best at the top. Thirteen sit at 96 percent or higher, led by GitHub, VulDB, Patchstack, Wordfence, WPScan, Adobe and GitLab at 100 percent. Chrome is at 66.8 percent and MITRE at 14 percent. Four sit at exactly zero, marked with a red cap at the baseline: Linux, Oracle, Apple and Mozilla. A dashed vertical reference line marks the 80 percent average across all 2026 CVEs, and it falls in the empty gap between Red Hat at 96.4 percent and Chrome. A right-hand column gives each CNA's 2026 CVE count. Source: CVE List V5.
```

## Notes / caveats
- **Do not advise reading CWE from the CNA record instead of NVD.** Strictly lossy: on
  the KEV catalog there are 0 CVEs where the CNA supplied a CWE and NVD did not,
  against 849 the other way. Linux at 44.3% NVD coverage is the one place the CNA
  record is nearly the only source, which is why the copy names it.
- **No timing claim.** This measures the current record, not who attached a CWE first.
- **Scope is the weakness class only, never "enrichment"** (that sweeps in CPE, where
  the Jul 13 `product_id` post argued the opposite in public).
- **Do not say these CNAs "leave the field blank".** Apple and Oracle populate
  `problemTypes` on 100% of their 2026 records, with impact prose rather than a class.
  Only Linux and Mozilla actually omit the block. Say "never name a weakness class".
- **Cut for good reason, do not reinstate:** "This is a configuration decision, not a
  capability gap." It is an intent claim a coverage column cannot support, and it reads
  to an Apple or Oracle engineer as a competence dig.
- `MIN_CVES = 250` is the inclusion floor. Sensitivity, recomputed post-fix:

  | Floor | CNAs | at 96%+ | in between | at exactly 0% | Volume covered |
  |-------|------|---------|-----------|---------------|----------------|
  | 100 | 52 | 39 | 9 | 4 | 89% |
  | 250 | 19 | 13 | 2 | 4 | 79% |
  | 500 | 16 | 11 | 2 | 3 | 77% |
  | 1,000 | 10 | 6 | 2 | 2 | 69% |

  **"Only two in between" is floor-specific**, so the copy must stay scoped to "the
  nineteen". At a floor of 100 the middle holds nine CNAs.
- **Volume-weighted defence if challenged:** among CNAs with 100+ 2026 CVEs, 96-100%
  coverage is 73.4% of volume, 0-25% is 19.9%, and the 25-96% middle band is only
  6.8%. State the denominator: that is 93.3% of the 100-plus subset (44,214 CVEs), and
  **82.8% of all 49,793** 2026 CVEs. Do not say "93% of CVE volume" unqualified.
- **Do not quote a 2019 to 2026 trend as "13% to 80%".** 12.7% is full-year 2019
  against a YTD 2026 figure. YTD-matched 2019 is **13.6%**, which is what
  `rolling_config.ytd_mask` exists to enforce.
- No duplicate `cve_id` rows inflate any denominator (49,793 rows, 49,793 unique).
- Zeros are absolute, not rounded: `max(cwe_count) == 0` across every 2026 record for
  Linux, Oracle, Apple and Mozilla.
- **Prepared replies.** MITRE's 14.0% is by publication date: 1,022 of its 2,417 2026
  publications (42.3%) carry pre-2026 IDs and run 3.1%, against 22.0% on 2026-vintage
  IDs. Mozilla's zero is 2026-only (1.49% in 2024, 0.96% in 2025); Oracle, Apple and
  Linux are multi-year.
- Zero rows draw a red cap at the baseline. Without it, four blank rows read as missing
  data rather than a measured zero. Red for zero is a deliberate palette break, same
  reasoning as `camp_week`'s red tents.
- Tie sort is `["rate", "n"]` descending. Sorting on rate alone was not stable across
  refreshes (quicksort headed the 100% block with Adobe, mergesort with GitHub).
- **Data reprocessed 2026-08-13** after the parser fix (376,628 CVEs, KEV 1,665).
- `/post-review` 2026-08-13: COPY rework, GRAPH fix-first, SHIP DATE hold. All applied.
  Declined: recolour red to navy (red carries meaning here), relabel the metric
  "machine-readable CWE ID" and keep the strict count (weaker post, still invites the
  WPScan reply), drop "and CISA" from the footnote (CISA-ADP coverage is real and
  measurable), clip the x-limit at 100 (cosmetic).

## Spin-off queued
The WPScan free-text finding is a better standalone post than the line it replaced: a
CNA that classifies 100% of its advisories in a form no parser reads, alongside
CERT/CC, Samsung Mobile, Go and curl doing the same. That is a data-plumbing story
with a named cast and a fix. Log it in `content/planning/BACKLOG.md` before it evaporates.

---
chart: product_id
posted: 2026-07-13
platforms: LI · X
migrated: 2026-10-11
---
# Caption: How CVEs identify affected products, CPE vs PURL vs free text (`product_id`)

Image: `graphs/product_id_<ratio>_<date>.png`. House style: no em dashes, no "n=", compact.
Data: per-year scan of the CVE List V5 clone (`src/cvegraphs/precompute/product_id.py` ->
`processed/product_id_coverage.parquet`) + NVD for enriched CPE coverage.

Finding (verified, same-cohort join of CVE List CNA-authored flags to NVD enriched CPE,
38,355 non-rejected CVEs PUBLISHED in 2026 and present in both; matches cve.icu's ~38.4k):
As authored, 75% of CVEs carry neither CPE nor PURL. NVD/CISA enrichment cuts that to ~40%
(displayed 41% for sum-to-100 rounding), entirely by backfilling CPE. The chart uses an
EXCLUSIVE partition (each CVE counted once, priority PURL > CPE > neither) so each column
sums to 100: No CPE or PURL 75->41, CPE 23->57, PURL 2 flat. Total CPE coverage (has a CPE,
incl. those that also carry a PURL) is ~25->59; the CPE bar shows 23->57 because the ~2.4%
with both are counted under PURL. PURL stays ~2.4% because NVD is CPE-only and the CISA ADP
container carries 0.0% PURL. Of the PURL records, ~9 in 10 also carry a CPE.

COHORT (important): "2026 CVEs" = CVEs PUBLISHED in 2026 (38,355), NOT CVE-2026-* IDs
(~31.5k). Counting by ID year undercounts the real year by ~18% because ~6.8k CVEs published
in 2026 carry older IDs (mostly 2025 backlog). cve.icu and common usage mean published-in-year.

## LinkedIn / Mastodon
Attach: `product_id_wide_<date>.png`.
```
PURL was supposed to be the upgrade. A package-native identifier built to describe the open-source packages CPE never handled well. Here is where it actually landed in the CVE feed: about 2% of 2026 CVEs, and most of that from a single third-party CNA.

As CNAs write them, 75% of CVEs carry neither CPE nor PURL. Then NVD and CISA go to work: they backfill CPEs and cut that no-ID pile to 41%. Every point of that improvement is CPE. They add zero PURLs, and not by choice. NVD has no PURL field to fill.

Here is the strange part. PURL is alive and well outside this pipeline, in OSV, GitHub Security Advisories, and every SBOM and SCA tool. It just never made it into the CVE and NVD pipeline that most of the industry still triages from. The problem is not PURL. It is that the feed everyone relies on structurally cannot see it. How long do we keep matching CVEs to assets through a format that cannot name a package?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
PURL was built to identify open-source packages, the thing CPE never did well.

Where it landed in the CVE feed: about 2% of 2026 CVEs. NVD and CISA backfill missing CPEs, cutting the no-ID pile from 75% to 41%, but they add zero PURLs, because NVD has no PURL field.

PURL is thriving in OSV, GitHub advisories, and SBOM tools. It just never made it into the pipeline everyone triages from.
```

## Alt text
```
Horizontal grouped bar chart of how every 2026 CVE (published in 2026) is identified, as the
CNA writes it versus after NVD/CISA enrichment, on the same set of CVEs, in three exclusive
groups that each sum to 100%. "No CPE or PURL" falls from 75% to 41% after enrichment. CPE (the
incumbent standard) rises from 23% to 57%. PURL (the proposed replacement) is 2% in both bars:
enrichment adds nothing, because NVD is CPE-only and the CISA ADP container carries no PURLs.
Source: CVE List V5 and NVD.
```

## Notes / caveats
- Detection: a record counts as CPE if its CNA container has an `affected[].cpes` entry
  or a `cpeApplicability` block; PURL if a `pkg:` package-URL string appears; "bare" if
  neither CPE nor any package-style field (purl / packageName / collectionURL) is present.
  Bare records still name vendor/product in free text; they just lack a standard ID.
- Chart is a plain horizontal grouped bar chart: three EXCLUSIVE groups (No CPE or PURL / CPE
  / PURL) x before/after enrichment, so each state (column) sums to 100. Bars: no-ID 75->41,
  CPE 23->57, PURL 2->2. Priority PURL > CPE > neither, so the ~2.4% with both count under
  PURL (this is why CPE shows 23/57 here, vs ~25/59 total has-CPE coverage). Display uses
  largest-remainder rounding to force each column to 100, so a value can be +/-1 off its own
  natural round (enriched no-ID is 40.4%, displayed 41 to make the column total 100). Keep it
  a normal bar graph (earlier versions accreted stacked partitions, ghost extensions, banners).
- SAME-COHORT numbers: computed on the 38,355 CVEs PUBLISHED in 2026 that appear in BOTH the
  CVE List clone and NVD (flags in product_id_cve_flags.parquet, keyed by publication year,
  joined to NVD has_cpe), so "as authored" and "after enrichment" are the same CVEs and the
  denominator matches cve.icu (~38.4k). src/cvegraphs/precompute/product_id.py builds the flags by
  publication date, NOT by CVE-ID-year directory (the old bug that read ~31.5k).
- "No CPE or PURL" (75%) is broader than "no product ID at all / free text only": it includes
  the ~10% of records that carry only a bare package name (WordPress/npm/Maven), which is
  neither a CPE nor a PURL.
- The zero-PURL-backfill finding: scanning the `containers.adp` (CISA ADP / Vulnrichment)
  for `pkg:` strings gives 0.0%; NVD's data model is CPE-only. So no enricher adds PURL.
  ADP adds a few points of CPE; NVD's database is where CPE reaches ~59%.
- SCOPE GUARDRAIL (post-review blocker): do NOT claim PURL is dead / "never launched" /
  "nobody uses it". PURL is the native identifier of OSV, GitHub Security Advisories,
  deps.dev, and SBOM/SCA tooling (SPDX, CycloneDX). The finding is scoped to the CVE/NVD
  pipeline: PURL is a rounding error THERE, and NVD structurally can't add it (no PURL field).
- Of the 812 2026 CVEs with a PURL in the CNA container, 622 (77%) come from one CNA
  (VulnCheck); GitHub does not emit PURL in its CVE records. Copy says "most from a single
  third-party CNA" without naming it (avoids a company callout); swap in the name if desired.
- Denominator note (RESOLVED): before/after are now the same 38,355-CVE cohort, so the
  26->59 "different denominators" caveat no longer applies. Cohort matches cve.icu.
- An earlier version was a 100% partition (no ID 64% / CPE 26% / package-or-plugin 10%);
  the 10% bucket was WordPress plugins + Maven/PyPI/Go. Kept for reference in git history;
  the backfill-contrast framing is the current, stronger story.
- Two provenance layers: the CNA-authored container (CPE 26%) vs NVD enrichment (CPE 59%).
  The chart shows CNA-as-authored, with the NVD lift as a callout. Same provenance theme
  as `exploited_cwe` (CNA feed sparse, NVD/CISA backfill).
- PURL "first year" uses the first year its share reaches >=0.1% (2025), not a stray
  record; a handful of `pkg:` strings appear earlier and round to 0.0%.
- The local CVE List clone can lag the NVD mirror slightly (2026 record counts differ:
  ~31.1k in the clone vs ~37.9k in NVD), so treat shares, not raw counts, as the story.
- Refresh: re-run `cvegraphs precompute product_id` after a data refresh to
  rebuild `processed/product_id_coverage.parquet`; the chart reads that parquet.
- Stamped with the NVD data-refresh date (evergreen), like the other volume charts.
```

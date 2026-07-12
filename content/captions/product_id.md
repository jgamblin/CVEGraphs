# Caption: How CVEs identify affected products, CPE vs PURL vs free text (`product_id`)

Image: `graphs/product_id_<ratio>_<date>.png`. House style: no em dashes, no "n=", compact.
Data: per-year scan of the CVE List V5 clone (`scripts_precompute_product_id.py` ->
`processed/product_id_coverage.parquet`) + NVD for enriched CPE coverage.

Finding (verified, same-cohort join of CVE List CNA-authored flags to NVD enriched CPE,
31,076 non-rejected 2026 CVEs present in both):
As authored, 74% of CVEs carry neither CPE nor PURL. NVD/CISA enrichment cuts that to 38%,
entirely by backfilling CPE. The chart uses an EXCLUSIVE partition (each CVE counted once,
priority PURL > CPE > neither) so each column sums to 100: No CPE or PURL 74->38, CPE 23->59,
PURL 3 (2.6% precisely) flat. Total CPE coverage (has a CPE, incl. those that also carry a
PURL) is 26->61; it shows as 23->59 here because the ~2.3% with both are counted under PURL.
PURL stays 2.6% because NVD is CPE-only and the CISA ADP container carries 0.0% PURL. Of the
2.6% with a PURL, ~9 in 10 also carry a CPE (only ~0.3% are PURL-without-CPE). PURL first
appeared in 2025 (0.3%), 0.0% before. "Neither CPE nor PURL" (74%) is broader than "no
product ID at all / free text only" (~64%, which also excludes bare package names). Trend of the "bare" share: 84% (2022) -> 77 -> 73 ->
65 -> 64% (2026). CPE-in-CNA: 12 -> 11 -> 15 -> 17 -> 26%. CPE and PURL are counted
independently (a record can carry both), so they do not sum with "bare" to 100.

## LinkedIn / Mastodon
Attach: `product_id_wide_<date>.png`.
```
PURL was supposed to be the upgrade. A package-native identifier built to describe the open-source packages CPE never handled well. Here is where it actually landed in the CVE feed: 2.6% of 2026 CVEs, and most of that from a single third-party CNA.

As CNAs write them, 74% of CVEs carry neither CPE nor PURL. Then NVD and CISA go to work: they backfill CPEs and cut that no-ID pile to 38%. Every point of that improvement is CPE. They add zero PURLs, and not by choice. NVD has no PURL field to fill.

Here is the strange part. PURL is alive and well outside this pipeline, in OSV, GitHub Security Advisories, and every SBOM and SCA tool. It just never made it into the CVE and NVD pipeline that most of the industry still triages from. The problem is not PURL. It is that the feed everyone relies on structurally cannot see it. How long do we keep matching CVEs to assets through a format that cannot name a package?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
PURL was built to identify open-source packages, the thing CPE never did well.

Where it landed in the CVE feed: 2.6% of 2026 CVEs. NVD and CISA backfill missing CPEs, cutting the no-ID pile from 74% to 38%, but they add zero PURLs, because NVD has no PURL field.

PURL is thriving in OSV, GitHub advisories, and SBOM tools. It just never made it into the pipeline everyone triages from.
```

## Alt text
```
Horizontal grouped bar chart of how every 2026 CVE is identified, as the CNA writes it versus
after NVD/CISA enrichment, on the same set of CVEs, in three exclusive groups that each sum to
100%. "No CPE or PURL" falls from 74% to 38% after enrichment. CPE (the incumbent standard)
rises from 23% to 59%. PURL (the proposed replacement) is 3% in both bars: enrichment adds
nothing, because NVD is CPE-only and the CISA ADP container carries no PURLs. Source: CVE List V5 and NVD.
```

## Notes / caveats
- Detection: a record counts as CPE if its CNA container has an `affected[].cpes` entry
  or a `cpeApplicability` block; PURL if a `pkg:` package-URL string appears; "bare" if
  neither CPE nor any package-style field (purl / packageName / collectionURL) is present.
  Bare records still name vendor/product in free text; they just lack a standard ID.
- Chart is a plain horizontal grouped bar chart: three EXCLUSIVE groups (No CPE or PURL / CPE
  / PURL) x before/after enrichment, so each state (column) sums to 100. Bars: no-ID 74->38,
  CPE 23->59, PURL 3->3. Priority PURL > CPE > neither, so the ~2.3% with both count under
  PURL (this is why CPE shows 23/59 here, vs 26/61 total has-CPE coverage). Keep it a normal
  bar graph (earlier versions accreted stacked partitions, ghost extensions, and banners).
- SAME-COHORT numbers: computed on the 31,076 CVEs present in BOTH the CVE List clone and NVD
  (join in processed/product_id_cve_flags.parquet + NVD has_cpe), so "as authored" and "after
  enrichment" are the same CVEs. This is why enriched CPE is 61% here, not the ~59% quoted
  earlier from NVD's larger standalone set.
- "No CPE or PURL" (74%) is broader than "no product ID at all / free text only" (~64%): the
  74% includes ~10% of records that carry only a bare package name (WordPress/npm/Maven), which
  is neither a CPE nor a PURL. Do not conflate the two numbers.
- The zero-PURL-backfill finding: scanning the `containers.adp` (CISA ADP / Vulnrichment)
  for `pkg:` strings gives 0.0%; NVD's data model is CPE-only. So no enricher adds PURL.
  ADP adds ~3.5 pts of CPE; NVD's database is where CPE reaches 59%.
- SCOPE GUARDRAIL (post-review blocker): do NOT claim PURL is dead / "never launched" /
  "nobody uses it". PURL is the native identifier of OSV, GitHub Security Advisories,
  deps.dev, and SBOM/SCA tooling (SPDX, CycloneDX). The finding is scoped to the CVE/NVD
  pipeline: PURL is a rounding error THERE, and NVD structurally can't add it (no PURL field).
- Of the 812 2026 CVEs with a PURL in the CNA container, 622 (77%) come from one CNA
  (VulnCheck); GitHub does not emit PURL in its CVE records. Copy says "most from a single
  third-party CNA" without naming it (avoids a company callout); swap in the name if desired.
- Denominator caveat: CNA-authored shares are over the 31,102 CVE List clone records; the
  59% enriched CPE is NVD's database figure (37.9k records). The clone can lag NVD, so
  treat the 26%->59% as "roughly doubles," not an exact same-cohort delta.
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
- Refresh: re-run `python scripts_precompute_product_id.py` after a data refresh to
  rebuild `processed/product_id_coverage.parquet`; the chart reads that parquet.
- Stamped with the NVD data-refresh date (evergreen), like the other volume charts.
```

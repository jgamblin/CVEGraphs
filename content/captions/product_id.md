# Caption: How CVEs identify affected products, CPE vs PURL vs free text (`product_id`)

Image: `graphs/product_id_<ratio>_<date>.png`. House style: no em dashes, no "n=", compact.
Data: per-year scan of the CVE List V5 clone (`scripts_precompute_product_id.py` ->
`processed/product_id_coverage.parquet`) + NVD for enriched CPE coverage.

Finding (verified, same-cohort join of CVE List CNA-authored flags to NVD enriched CPE,
31,076 non-rejected 2026 CVEs present in both):
As authored, 74% of CVEs carry neither CPE nor PURL. NVD/CISA enrichment cuts that to 38%,
entirely by backfilling CPE, which rises from 25.6% to 61%. PURL is on 2.6% as authored and
STAYS 2.6% after enrichment: the CISA ADP container carries 0.0% PURL, and NVD is CPE-only,
so no enricher adds a PURL. Of the 2.6% with a PURL, ~9 in 10 also carry a CPE (only ~0.3%
are PURL-without-CPE). PURL first appeared in 2025 (0.3%), 0.0% before. Note: "neither CPE
nor PURL" (74%) is broader than "no product ID at all / free text only" (~64%, which also
excludes bare package names). Trend of the "bare" share: 84% (2022) -> 77 -> 73 ->
65 -> 64% (2026). CPE-in-CNA: 12 -> 11 -> 15 -> 17 -> 26%. CPE and PURL are counted
independently (a record can carry both), so they do not sum with "bare" to 100.

## LinkedIn / Mastodon
Attach: `product_id_wide_<date>.png`.
```
PURL was supposed to be the upgrade. A package-native identifier built for the open-source world that CPE never described well, and long pitched as the modern replacement. Here is where it actually landed: 2.6% of 2026 CVEs.

And nothing is coming to save it. As CNAs write them, 74% of CVEs carry neither CPE nor PURL. Then NVD and CISA go to work: they backfill CPEs and cut that no-ID pile to 38%, more than doubling CPE coverage from 26% to 61%. They add zero PURLs, because the whole enrichment pipeline is built around CPE.

So the format meant to modernize product matching is barely used by the people who write CVEs, and untouched by the machine that fixes everything else. If PURL is the answer, why is nobody, human or automated, reaching for it?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
PURL was pitched as the modern replacement for CPE, built for open source. It is on 2.6% of 2026 CVEs.

And nothing is coming to save it. NVD and CISA backfill missing CPEs, cutting the no-ID pile from 74% to 38%, but they add zero PURLs. No CNA uses it, no enricher adds it.

The new hotness never launched.
```

## Alt text
```
Horizontal grouped bar chart comparing product-identifier coverage in 2026 CVEs, as the CNA
writes it versus after NVD/CISA enrichment, on the same set of CVEs. "No CPE or PURL" falls
from 74% to 38% after enrichment. CPE (the incumbent standard) rises from 26% to 61%. PURL
(the proposed replacement) is 2.6% in both bars: enrichment adds nothing, because NVD is
CPE-only and the CISA ADP container carries no PURLs. Source: CVE List V5 and NVD.
```

## Notes / caveats
- Detection: a record counts as CPE if its CNA container has an `affected[].cpes` entry
  or a `cpeApplicability` block; PURL if a `pkg:` package-URL string appears; "bare" if
  neither CPE nor any package-style field (purl / packageName / collectionURL) is present.
  Bare records still name vendor/product in free text; they just lack a standard ID.
- Chart is a plain horizontal grouped bar chart: three groups (No CPE or PURL / CPE / PURL)
  x before/after enrichment. Bars: no-ID 74->38, CPE 26->61, PURL 2.6->2.6. Keep it a normal
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

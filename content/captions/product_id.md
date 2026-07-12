# Caption: How CVEs identify affected products, CPE vs PURL vs free text (`product_id`)

Image: `graphs/product_id_<ratio>_<date>.png`. House style: no em dashes, no "n=", compact.
Data: per-year scan of the CVE List V5 clone (`scripts_precompute_product_id.py` ->
`processed/product_id_coverage.parquet`) + NVD for enriched CPE coverage.

Finding (verified from CVE List V5 + NVD, non-rejected, 2026, 31,102 CVEs):
CPE is on 25.6% of CVEs as the CNA writes it, rising to ~59% after NVD backfills it (the
CISA ADP container adds only ~3.5 points of CPE; NVD's database is the big lift). PURL is on
2.6% as authored and STAYS 2.6% after enrichment: the CISA ADP container carries 0.0% PURL,
and NVD is CPE-only, so backfill adds no PURLs at all. As authored, 64% carry neither CPE nor
PURL. Of the 2.6% with a PURL, ~9 in 10 also carry a CPE (only ~0.3% are PURL-without-CPE).
PURL first appeared in 2025 (0.3%) and was 0.0% before. Trend of the "bare" share: 84% (2022) -> 77 -> 73 ->
65 -> 64% (2026). CPE-in-CNA: 12 -> 11 -> 15 -> 17 -> 26%. CPE and PURL are counted
independently (a record can carry both), so they do not sum with "bare" to 100.

## LinkedIn / Mastodon
Attach: `product_id_wide_<date>.png`.
```
PURL was supposed to be the upgrade. A package-native identifier built for the open-source world that CPE never described well, and long pitched as the modern replacement. Here is where it actually landed: 2.6% of 2026 CVEs.

And nothing is coming to save it. When a CNA leaves out a CPE, NVD and CISA backfill it later, taking CPE coverage from 26% to 59%. That same enrichment machine adds zero PURLs, because the whole pipeline is built around CPE. PURL gets no safety net, and 64% of CVEs still carry neither identifier as written.

So the format meant to modernize product matching is barely used by the people who write CVEs, and ignored by the people who enrich them. If PURL is the answer, why is nobody, human or automated, reaching for it?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
PURL was pitched as the modern replacement for CPE, built for open source. It is on 2.6% of 2026 CVEs.

And nothing is coming to save it. NVD and CISA backfill missing CPEs, from 26% to 59%, but they add zero PURLs. No CNA uses it, no enricher adds it.

The new hotness never launched.
```

## Alt text
```
Grouped vertical bar chart comparing product-identifier coverage in 2026 CVEs, before and
after NVD/CISA enrichment. For CPE (the incumbent standard), the as-authored bar is 26% and
the after-enrichment bar jumps to 59%. For PURL (the proposed replacement), both bars are
2.6%: enrichment adds nothing, because NVD is CPE-only and the CISA ADP container carries no
PURLs. The subtitle notes that 64% of 2026 CVEs carry neither identifier. Source: CVE List V5 and NVD.
```

## Notes / caveats
- Detection: a record counts as CPE if its CNA container has an `affected[].cpes` entry
  or a `cpeApplicability` block; PURL if a `pkg:` package-URL string appears; "bare" if
  neither CPE nor any package-style field (purl / packageName / collectionURL) is present.
  Bare records still name vendor/product in free text; they just lack a standard ID.
- Chart is a plain grouped bar chart (two identifiers x before/after enrichment), NOT a
  partition. Bars: CPE 26% -> 59%, PURL 2.6% -> 2.6%. Rebuilt from scratch after earlier
  versions accreted too many custom elements (stacked partition, ghost extensions, banners);
  keep it a normal bar graph.
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

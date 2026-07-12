# Caption: How CVEs identify affected products, CPE vs PURL vs free text (`product_id`)

Image: `graphs/product_id_<ratio>_<date>.png`. House style: no em dashes, no "n=", compact.
Data: per-year scan of the CVE List V5 clone (`scripts_precompute_product_id.py` ->
`processed/product_id_coverage.parquet`) + NVD for enriched CPE coverage.

Finding (verified from the CVE List V5 CNA container, non-rejected, 2026):
of 31,102 CVEs, ~64% carry no standardized product identifier (CPE or PURL) as authored,
only free-text vendor/product fields. CPE appears in 25.6% as the CNA writes it, rising to
~59% after NVD backfills it downstream. PURL (package URL) appears in 2.6%, its first
material year: it first appeared in 2025 at 0.3% and was 0.0% before that. Trend of the "bare" share: 84% (2022) -> 77 -> 73 ->
65 -> 64% (2026). CPE-in-CNA: 12 -> 11 -> 15 -> 17 -> 26%. CPE and PURL are counted
independently (a record can carry both), so they do not sum with "bare" to 100.

## LinkedIn / Mastodon
Attach: `product_id_wide_<date>.png`.
```
How does a CVE tell you what software it affects, in a form a scanner can match? In 2026, mostly it doesn't.

About 64% of this year's CVEs carry no standardized identifier a scanner can match against your inventory, just a free-text vendor and product name. CPE, the identifier scanners have leaned on for nearly two decades, is in 26% as the CNA authors it, and NVD backfills more later, to around 59%. PURL, the package-native identifier meant to fix this for open source, first appeared last year and reaches 2.6% now.

If nearly two-thirds of advisories arrive with no standardized ID to match against your inventory, only vendor and product text, what closes that gap in your pipeline?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
How does a CVE say what software it affects? In 2026, mostly it doesn't.

About 64% carry no standardized ID (CPE or PURL) to match against your inventory, just vendor and product text. CPE, nearly 20 years old, is in 26% as written. PURL, the modern fix for open source, first appeared last year and reaches 2.6%.

The link between a CVE and your asset inventory is missing from most of them.
```

## Alt text
```
Horizontal bar chart of how 2026 CVEs identify the affected product, as the assigning CNA
writes it, in three mutually-exclusive groups that sum to 100%: "No product ID" (free-text
vendor and product only) 64%, "CPE" (the incumbent standard) 26%, and "Package or plugin
name" (WordPress, npm, Maven, no CPE) 10%. Two notes below: PURL, the modern package-URL
standard, is on only 2.6% of records and almost always alongside a CPE, not on its own;
NVD later backfills CPE from 26% to about 59% after publication. Source: CVE List V5 and NVD.
```

## Notes / caveats
- Detection: a record counts as CPE if its CNA container has an `affected[].cpes` entry
  or a `cpeApplicability` block; PURL if a `pkg:` package-URL string appears; "bare" if
  neither CPE nor any package-style field (purl / packageName / collectionURL) is present.
  Bare records still name vendor/product in free text; they just lack a standard ID.
- The chart is a mutually-exclusive partition (priority CPE > package > none), so the three
  bars sum to 100: no product ID 64%, has-CPE 26%, package-or-plugin-name-but-no-CPE 10%.
- The 10% bucket is `packageName`/`collectionURL` records with no CPE: dominated by
  WordPress plugins/themes (~half, via wordpress.org/plugins + themeforest), then Maven,
  CPAN, PyPI, Go. Labeled "Package or plugin name" for accuracy.
- PURL (2.6%) is NOT a fourth bar: ~9 of 10 PURL records ALSO carry a CPE (only ~0.3% are
  PURL-without-CPE), so it mostly rides inside the CPE bar. Shown as a callout, and the
  callout says "alongside a CPE" so no one reads it as part of the 10% bucket. Do NOT
  reintroduce independent overlapping bars (they invite a false sum, and confused the author).
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

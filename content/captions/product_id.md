# Caption: How CVEs identify affected products, CPE vs PURL vs free text (`product_id`)

Image: `graphs/product_id_<ratio>_<date>.png`. House style: no em dashes, no "n=", compact.
Data: per-year scan of the CVE List V5 clone (`scripts_precompute_product_id.py` ->
`processed/product_id_coverage.parquet`) + NVD for enriched CPE coverage.

Finding (verified from the CVE List V5 CNA container, non-rejected, 2026):
of 31,102 CVEs, ~64% carry no machine-readable product identifier as authored (free-text
vendor/product only). CPE appears in 25.6% as the CNA writes it, rising to ~59% after NVD
backfills it downstream. PURL (package URL) appears in 2.6%, its first real year: it was
0.0% through 2024 and 0.3% in 2025. Trend of the "bare" share: 84% (2022) -> 77 -> 73 ->
65 -> 64% (2026). CPE-in-CNA: 12 -> 11 -> 15 -> 17 -> 26%. CPE and PURL are counted
independently (a record can carry both), so they do not sum with "bare" to 100.

## LinkedIn / Mastodon
Attach: `product_id_wide_<date>.png`.
```
How does a CVE tell you what software it affects? In 2026, mostly it doesn't.

About 64% of this year's CVEs carry no machine-readable product identifier as written, just a free-text product name. CPE, the identifier scanners have used for 25 years, is in 26% as the CNA authors it, and NVD backfills more later, to around 59%. PURL, the package-native identifier meant to fix this for open source, just appeared: 2.6%, its first real year.

The field that links a CVE to your asset inventory is missing from most of them at publication, and the modern replacement is barely off zero.

If two of three advisories arrive with nothing a scanner can match, what closes that gap in your pipeline?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
How does a CVE say what software it affects? In 2026, mostly it doesn't.

About 64% carry no machine-readable product identifier, just free text. CPE (25 years old) is in 26% as written. PURL, the modern fix for open source, just appeared at 2.6%.

The link between a CVE and your asset inventory is missing from most of them.
```

## Alt text
```
Horizontal bar chart of how 2026 CVEs identify the affected product, as the assigning
CNA writes it. "No machine-readable ID" (free-text product name only) is 64%, down from
84% in 2022. "CPE" is 26%, up from 12% in 2022, with a marker showing it reaches 59%
after NVD backfills it. "PURL", the package-native identifier, is 2.6%, first appearing
in 2025. CPE and PURL are counted independently. Source: CVE List V5 and NVD.
```

## Notes / caveats
- Detection: a record counts as CPE if its CNA container has an `affected[].cpes` entry
  or a `cpeApplicability` block; PURL if a `pkg:` package-URL string appears; "bare" if
  neither CPE nor any package-style field (purl / packageName / collectionURL) is present.
  Bare records still name vendor/product in free text; they just lack a standard ID.
- Two provenance layers: the CNA-authored container (CPE 26%) vs NVD enrichment (CPE 59%).
  The chart shows CNA-as-authored, with the NVD number as a backfill marker. Same
  provenance theme as `exploited_cwe` (CNA feed sparse, NVD/CISA backfill).
- PURL "first year" uses the first year its share reaches >=0.1% (2025), not a stray
  record; a handful of `pkg:` strings appear earlier and round to 0.0%.
- The local CVE List clone can lag the NVD mirror slightly (2026 record counts differ:
  ~31.1k in the clone vs ~37.9k in NVD), so treat shares, not raw counts, as the story.
- Refresh: re-run `python scripts_precompute_product_id.py` after a data refresh to
  rebuild `processed/product_id_coverage.parquet`; the chart reads that parquet.
- Stamped with the NVD data-refresh date (evergreen), like the other volume charts.
```

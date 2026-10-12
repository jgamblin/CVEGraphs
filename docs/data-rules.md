# Data rules

Every one of these has produced a wrong chart or a wrong sentence at least once.
Check the list before building on a field you have not used before.

Most of them are applied inline in the chart that needs them. Only the rolling
window and the NVD Deferred split have unit tests (`tests/test_rolling.py`,
`tests/test_data_rules.py`). The rest depend on whoever writes the next chart
reading this file, plus the `/post-review` fact-checker.

## Dates and timestamps

**KEV `dateAdded` is a date, not a timestamp.** It parses to midnight UTC, while
CVE List `datePublished` and NVD `published` carry a time of day. A raw
`(added - published).dt.days` floors a same-day gap to -1, which invents a
phantom "added to KEV before publication" bucket. Compare calendar dates:
`(added.dt.normalize() - pub.dt.normalize()).dt.days`. This is what the EPSS
precompute steps do.

**MITRE publishes straight to the CVE List**, bypassing the API, so its
`datePublished` values cannot be compared with other CNAs' for anything about
timing (bursts, rate, time of day). Drop `assigner_short_name == "mitre"` from
those analyses and say so in the footnote. Also filter `second != 0`: records
with only a date, or truncated to the minute, all pile up at :00.

**NVD lags the CVE List.** The CVE List gets a CVE when the CNA publishes it, and
NVD ingests it later. The gap ranges from about 100 records to more than a full
day's volume after an Oracle CPU. NVD also has exactly 679 non-rejected records
dated 1988 to 1998. That number is frozen. A pipeline that filters
`year >= 1999` on one side but not the other inherits a permanent 679-record
offset.

**The rolling window.** Year-over-year comparisons cover Jan 1 through the same
month and day in every year (`rolling.ytd_mask`), anchored to the newest record
in the data (`rolling.data_asof`), not the wall clock.

## Scores

**Compare CVSS v3 with v4 from the same scorer.** NVD's mirrored v4 used to run
about 0.6 low against the CNA's own v4. The refresh now reconciles NVD v4 to the
CVE List value (`reconcile_nvd_v4`). Even so, a v3-vs-v4 comparison across
scorers measures the scorer, not the version.

**CISA-ADP scores mostly repeat the CNA's.** When a CVE has both, about 90% match
exactly. Pair CNA scores with NVD (`nvd@nist.gov`), the genuinely independent
second scorer, for any "scorers disagree" analysis.

**NVD Deferred (since April 2026).** NVD marks most 2026 CVEs it will not
enrich as `Deferred`: no CPE, no NVD score. Which CVEs get deferred depends on
the CNA, not on severity. Split by `vuln_status` before reading CPE coverage or
NVD-score coverage, and measure Deferred share only among settled records
(Analyzed, Modified, Deferred).

## KEV and exploitation

**Say "added to KEV", never "exploited".** KEV is a curated subset. A CVE that
is not on KEV is not therefore unexploited.

**KEV-vs-all comparisons measure which CNAs are on KEV.** KEV over-represents
MITRE, Microsoft, Apple and Chrome. Before claiming a gap on a record-quality
field (CWE, CVSS, CPE, credits), adjust the baseline to the KEV cohort's mix
of CNAs.

**The EU (EUVD) exploited list has no source field.** About 99% of it mirrors
CISA KEV. Entries the EU listed "first" track CISA-ADP SSVC ratings, and the
EU-only entries vary in quality. Audit each one before calling any of them
independent evidence.

## Detection rules

**A rule that names a CVE ID measures how the ruleset is indexed, not whether
the bug can be detected.** Endpoint detection is behavioral and deliberately
leaves CVE numbers out (Sigma by design). Never grade a ruleset on CVE coverage.

## Charts people can count

In a unit chart (dots, waffles, isotypes) a reader can count every mark, so every
bin edge and divider label is a factual claim. A divider labelled "Jul 1" must
have exactly the count the copy states on its right. ISO-week bins broke this
once.

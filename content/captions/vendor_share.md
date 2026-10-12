# Caption: share of CVEs published by the product's own vendor (`vendor_share`)

Image: `graphs/vendor_share_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Built 2026-09-24 from a September data scan.
**Volume / CNA lane**, so milestone-only under the calendar rules; it is closer to the
data-quality lane in spirit (who does the publishing) and could take a Tuesday.
`/post-review` not run.

Chart: `charts/vendor_share.py`. Two lines, monthly from Jan 2025: share of CVEs whose
CNA maintains the product, all CNAs (navy) and without Linux, Microsoft and Oracle (grey).

## Finding (CVE List V5, through Sep 28 2026; refreshed for the Sep 29 draft)

| Measure | Value |
|---|---|
| Vendor share, Sep 2026 (partial, through Sep 28) | **55.2%**, highest in the series |
| Vendor share, Mar 2026 (2026 low) | 24.5% |
| Previous high | 51.9% (Jul 2026) |
| Without Linux/Microsoft/Oracle, Sep 2026 | 37.8% |
| Without them, Jan 2026 low | 18.9%; 2025 range about 19% to 30% |
| Vendor-CNA CVEs, Q1 2026 vs Q3 to date | 3,949 vs 18,502 (4.7x) |
| Third-party CVEs, same windows | 10,887 vs 16,749 (+54%) |
| Unclassified volume, worst month | 2.8% |

Biggest vendor growth, Q1 to Q3-to-date: Linux +3,342, Oracle +2,563, Microsoft +1,836,
Chrome +1,103, IBM +697, Red Hat +492, Apache +411, Apple +283, Adobe +282, Dell +238.
114 vendor CNAs outside the big three published in September.

## Accuracy guards

- **Third parties did not shrink.** They grew 54%. The share moved because vendors grew
  4.7x. Any copy that says third parties "retreated" or "pulled back" is wrong.
- **The classification is hand-built** (`THIRD_PARTY` / `VENDOR` in the chart file). The
  rule is whether the CNA maintains the product, so GitHub_M is third party even though
  many GHSA CVEs are requested by the maintainer. If someone pushes on that: moving
  GitHub to "vendor" raises every month, it does not remove the turn. Worth checking
  before posting if the copy leans on the absolute level.
- **Ecosystem CNAs** (Joomla, Drupal, CPANSec, EEF) are third party; foundations that own
  their projects (Apache, OpenJS, PSF, Eclipse) are vendors. Unlisted CNAs are dropped
  from both sides, never defaulted.
- **Feb 2025 spike (46%)** is the Linux kernel CNA's Feb 26 2025 batch (909 that month).
- **Do not reuse the `pace` decomposition.** That post (Aug 10) said five CNAs drove 2026
  growth. This is a different claim: which *kind* of CNA, and that it changed mid-year.
- **Cause is not in the data.** Tempting to say "AI-assisted bug finding hit vendor
  pipelines"; nothing here shows that. Leave it as a question.

## /post-review 2026-09-29 (12 personas): COPY "post with fixes", GRAPH "fix first"

Review recommended holding to Tue Oct 6 for a closed September (2/week cap, and the
Oct 1 MonthlyCVEStats month-close quotes full September). **Jerry chose to post Sep 29
anyway**, then reversed the same day and **held it for Tue Oct 6** to protect the Oct 1
month-close post. The partial-month treatment (dashed last segment, hollow markers, "*")
is now automatic: drawn only when the trailing month is partial, and a trailing month
under 15 days (`MIN_PARTIAL_DAYS`) is dropped, so the Oct 6 render ends on closed September.

Decisive catch: the series starts at the Jan 2025 trough, so "highest since Jan 2025"
oversold a reversal as a record. Same classification over all of CVE List V5: 2016 67.5%,
2017 to 2021 43% to 48% (pooled 46.1%), 2022 40.7%, 2023 38.7%, 2024 38.2%, **2025 36.5%
(lowest since at least 2014)**. Last month above Sep's 55.2%: **Jan 2021 (56.3%)**.
Unclassified volume 2% to 5% in those years, so the comparison holds. Without the big
three, 2025 pooled 25.0%.

Applied: "2017 to 2021 average, 46%" reference line replaces "Half" (computed in the
chart, `BASE_YEARS`); darker grey series (#7F93AD, label #5F7390); legend "Excluding Linux
kernel, Microsoft, Oracle"; one-line subtitle; eyebrow CNA Share. Copy reframed as a
reversal ("again"), turn dated to spring not May, Q1/Q3 counts moved to this caption,
"owning" and "actually maintains" cut, ex-big-three measured from 2025 not the Jan low,
Oracle CSPU credited as the on-record part of the turn (cna_peak_day caption: off-cycle
CSPUs since May 28, between quarterly CPUs, not monthly). Dismissed: stacked volume panel,
Red Hat/Go reclassification rerun (about 490 CVEs, cannot flip it).

## Draft copy (LinkedIn), final 2026-09-29, for Tue Oct 6

tells linter passed. **Refresh every September figure after the Oct 6 re-render**; switch "So far in September it's" to "In September it was" and "38% this month" to "38% in September"; if closed Sep is 56.3% or higher, "since January 2021" becomes "since October 2020".

The best news in this year's CVE data: vendors are publishing their own bugs again.

For years a shrinking share of CVEs came from the CNA that maintains the product, bottoming at 24.5% this March. So far in September it's 55.2%, the highest month since January 2021. Third-party CNAs didn't shrink; vendors just grew faster. And it isn't only Linux, Microsoft and Oracle: pull them out and the vendor share still climbs, from 25% across 2025 to 38% this month.

That changes the job downstream. More of your queue now lands in batches on vendor release days, from the team that shipped the fix.

Part of the spring turn is on the record: in May, Oracle started shipping security patch updates between its quarterly releases. The rest, including the vendors outside the big three, isn't explained anywhere in the records. So a question for vendor PSIRTs, and anyone who watched it happen: what changed for you this spring?

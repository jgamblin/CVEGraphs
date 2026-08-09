# Caption — Ranked bars: biggest single-day CVE batches by one CNA, modern era (`cna_burst`)

Image: `graphs/cna_burst_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading + labels; post-date stamp. Volume/CNA-milestone card,
posted off-cadence as a same-week milestone (triggered by Oracle's record CPU day).

Finding (verified, CVE List V5, non-rejected, de-duplicated by CVE id, grouped by
assigner short name + calendar day UTC of CVE.org publication, data as of 2026-07-22):
on 2026-07-21 Oracle published 1,097 CVEs in a single day, a new all-time single-CNA
record, about 55% above the previous record of 709 (ZDI, 2024-05-03). Verified real:
all 1,097 are fresh CVE-2026 ids, published in one ~8-minute burst (Oracle's July
Critical Patch Update). The chart shows the modern top 10: Oracle 1,097 (2026-07-21),
ZDI 709 (2024-05-03), Linux 706 (2025-02-26), Microsoft 570 (2026-07-14, July Patch
Tuesday), Linux 431 (2026-07-19), Chrome 427 (2026-06-04), Chrome 382 (2026-06-30),
Linux 372 (2024-10-21), MITRE 363 (2018-07-09), Linux 362 (2025-06-18). Five of the
ten are from 2026 (50%); nine of ten are since 2024 (only MITRE, 2018, is older). The
50% share is robust: 5 of the all-time top 10 are also from 2026, so it is not a
window artifact.

## LinkedIn / Mastodon
Attach: `cna_burst_wide_<date>.png` (or square/portrait).
```
On July 21, Oracle published 1,097 CVEs in a single day. That is the most any CNA has ever published at once, about 55% more than the previous record of 709.

For context: this is one quarterly Critical Patch Update, Oracle's scheduled housekeeping across its whole product line, not 1,097 fresh zero-days. And it is the sharpest example yet of a pattern this chart shows. Half of the ten biggest single-day batches since 2017 came in 2026 alone, now spread across many CNAs (Oracle, Microsoft, Linux, Chrome), not the single-assigner bulk uploads of the past.

The mega-batch is the normal shape of CVE publishing now, and it is mostly mechanical: quarterly bundles like Oracle's, monthly Patch Tuesdays, the Linux kernel's per-commit stream, ZDI backlog releases. The signal is not the 1,097 count, it is the two or three that land in your stack. Everything else is publishing mechanics.

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
On July 21, Oracle published 1,097 CVEs in one day. The most any CNA ever has, about 55% over the old record of 709.

For context: it is one quarterly Critical Patch Update, scheduled housekeeping across Oracle's whole product line, not 1,097 new zero-days. Half of the ten biggest single-day batches since 2017 came in 2026 alone, now spread across many CNAs, not the old sole-assigner MITRE dumps.

Mega-batches are the normal shape of CVE publishing now, mostly scheduled bundles. The signal is not the 1,097 count, it is the two or three that land in your stack.
```

## Alt text
```
Horizontal bar chart ranking the 10 largest single-day CVE batches published by one CNA,
2017 to now. Oracle leads by a wide margin with 1,097 on Jul 21, 2026, well above ZDI's
709 (May 3, 2024) and Linux's 706 (Feb 26, 2025), then Microsoft 570, Linux 431, two
Chrome days, and more Linux days down to 362. Only one bar (MITRE, Jul 2018) is pre-2024,
shown in pale blue; the other nine are dark navy. Source: CVE List V5.
```

## Notes / caveats
- Metric: unique CVEs sharing one assigner_short_name and one calendar day (UTC) of
  CVE.org publication. Oracle's 1,097 is a genuine single-day batch: all fresh CVE-2026
  ids in one ~8-minute publish burst on 2026-07-21 (the July Critical Patch Update), not
  a backfill of old CVE ids.
- This landed with a lag: the morning-of-Jul-21 data showed no Oracle batch; the Jul 22
  refresh picked it up. The original trigger for this chart was the Jul 19 Linux burst
  (431, now 5th); Oracle's CPU then took the record two days later.
- The post-2024 surge is mostly mechanical, not a rise in distinct exploitable bugs:
  Oracle/other quarterly bundles, monthly Patch Tuesdays, the Linux kernel's per-commit
  CVE policy (a CNA since Feb 2024), ZDI backlog releases. Keep the "count is not the
  risk" framing; do not imply 1,097 new zero-days.
- Threshold context: only 2 single-CNA days of 300+ CVEs in 2017-2023 (MITRE 363, Mozilla
  318) vs 13 since 2024. Oracle previously topped out at 244/day and had never hit 300;
  the July 2026 CPU (1,097) is its first 300+ day and now the overall record. (Earlier
  drafts said "Oracle never hit 300" - that is now void.)
- Modern-era cut starts 2017 to exclude MITRE's early sole-assigner bulk-loads (2001-2005,
  up to 480/day). Trimmed to top 10; Mozilla's 2018 day (318) and two 2024/2025 Linux days
  sit just below the cut.
- Cadence: posted as this week's 2nd post (with Tue cvss_v4_adoption), at the 2/week cap,
  as a milestone. Replaces the Thursday post; does not add a third chart this week.
- Ends on a statement, not the usual question: the review panel flagged the formulaic
  "how does your pipeline handle a 1,000-CVE day?" as engagement-bait and a near-repeat of
  chrome_day's close. Deliberate deviation from the end-with-a-question house rule.
- Pinned-comment ready for the likely chrome_day challenge ("you said Chrome 427 was the
  record"): "Chrome Day was the vendor-vs-vendor record. 1,097 is the all-CNA single-day
  record. Different scope."
- Factual Title-Case heading; the record + "scheduled housekeeping" read lives in the copy.
  Color = era (navy 2024 to date, pale 2017-2023), stated in the legend.

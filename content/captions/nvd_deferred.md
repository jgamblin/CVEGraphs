# Caption: Ranked bars, NVD Deferred share by CNA (`nvd_deferred`)

Image: `graphs/nvd_deferred_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Data-quality lane, scoring/measurement
family (Tuesday). Same shape and 250 floor as `cwe_cna_rank` (Aug 13) and `patch_tag`
(Sep 4), so the three CNA-practice charts read as a set. Copy drafted against
`~/Documents/Github/Blogs/humanize.md` (adopted for this repo 2026-09-08).

Built 2026-09-08 from item 1 of the "Week of Aug 31 2026 scan" in BACKLOG.md. Data:
`processed/nvd_cves.parquet` (`vuln_status`) joined to `processed/cvelist_v5.parquet` for
the assigning CNA. No precompute step.

**Attach the PORTRAIT to LinkedIn.** Twenty-three CNA names are the payload and the wide
does not survive phone width.

**Data refreshed 2026-09-08 (newest NVD record Sep 8 11:17 UTC); all figures below and
the renders are on that refresh.** If the post slips a day:
`CVEGRAPHS_POST_DATE=2026-09-09 python make.py nvd_deferred`

## What Deferred is
Two NVD announcements, both verified on www.nist.gov/itl/nvd 2026-09-08:
- **Apr 2 2025** (updated Apr 10 2025) introduced the `Deferred` status: *"All CVEs with a
  published date prior to 01/01/2018 that are awaiting further enrichment will be marked
  as Deferred within the NVD dataset."* So the status predates the 2026 policy; it was a
  backlog tool first.
- **Apr 15 2026**, "NIST Updates NVD Operations to Address Record CVE Growth": *"Starting on
  April 15, 2026, we will prioritize the following CVEs for enrichment: CVEs appearing in
  CISA's Known Exploited Vulnerabilities (KEV) Catalog... CVEs for software used within the
  federal government... CVEs for critical software as defined by Executive Order 14028."*
  and *"Those that do not meet the criteria above will be categorized as 'Lowest Priority -
  not scheduled for immediate enrichment.'"* The API value for that tier is `Deferred`.
  The same note carries the line quoted in the first comment: *"Going forward, we will no
  longer routinely provide a separate severity score for those CVEs."*

**NVD's stated test is about the PRODUCT (KEV, federal use, EO 14028), not the CNA.** The
chart shows the outcome of that test sorts by publisher. Say both; never say NVD "decides
by CNA" as if that were the written rule.

**What Deferred means in the data:** no CPE configuration (0 of 20,076, against 100% of
Analyzed and Modified rows) and no NVD-authored CVSS. **The CPE is the discriminator, not
the score:** the review's factcheck found 61% of Analyzed and 54% of Modified 2026 rows
also carry no NVD-authored score (they carry the CNA's or CISA-ADP's), because the same
Apr 15 note ended routine NVD scoring. So the copy says "no CPE, no NVD analysis", not "no
NVD score". 88.7% of Deferred rows (17,808) still show a CVSS v3 from the CNA on the NVD
page; 4,652 show none.

**Deferred is not permanent.** The label is "not scheduled for immediate enrichment", a
KEV listing pulls a record back into analysis, and anyone can request enrichment. Never
write "never".

**Cohort choice, stated once so nobody re-litigates it:** the denominator is CVEs NVD has
SETTLED, meaning `Analyzed`, `Modified` or `Deferred`. Modified rows are Analyzed rows that
were later updated (100% carry a CPE; about 46% carry an NVD-authored score, the rest the
CNA's), so they are enriched and belong in the denominator. The Sep 4 scan quoted 42.5% on Analyzed + Deferred only; including Modified
gives **39.2%**. Use 39%. Received (5,529), Awaiting Analysis (2,750) and Undergoing
Analysis (639) are excluded because their fate is not yet decided: 8,918 CVEs. The CNA
join to CVE List V5 is inner, so 5 records V5 has rejected and NVD has not are dropped.

## Finding (verified 2026-09-08 on the same-day refresh)

**20,076 of the 51,219 CVEs published in 2026 that NVD has settled are Deferred: 39.2%.**
23 CNAs have 250+ settled CVEs (41,840, 82% of settled volume).

| CNA | Deferred | Settled |  | CNA | Deferred | Settled |
|-----|---------|---------|--|-----|---------|---------|
| Patchstack | 99.7% | 3,773 | | Cisco | 6.6% | 274 |
| Wordfence | 99.7% | 2,754 | | Linux | 4.4% | 2,935 |
| WPScan | 99.3% | 966 | | Apache | 3.0% | 702 |
| VulDB | 70.1% | 4,520 | | Dell | 2.8% | 253 |
| Joomla | 65.1% | 261 | | GitLab | 1.4% | 295 |
| CPANSec | 63.6% | 253 | | IBM | 1.1% | 804 |
| VulnCheck | 52.2% | 4,438 | | Oracle | 0.1% | 2,420 |
| ICS-CERT | 49.1% | 265 | | Chrome | 0.0% | 2,486 |
| MITRE | 47.0% | 2,515 | | Microsoft | 0.0% | 1,958 |
| GitHub | 26.6% | 7,957 | | Adobe | 0.0% | 594 |
| Red Hat | 12.4% | 427 | | Apple | 0.0% | 560 |
| | | | | Mozilla | 0.0% | 430 |

- **Severity does not decide it.** Deferred share by the CNA's own CVSS v3 band: Low
  41.5%, Medium 49.7%, High 40.3%, Critical 45.7%. Inside VulDB, Critical is deferred
  MORE often (89.9%) than Low (70.8%). **1,646 Deferred CVEs carry a CNA score of 9.0 or
  higher; 890 are exactly 9.8.** Top sources of Deferred Criticals: Patchstack 490,
  VulnCheck 293, GitHub 214, Wordfence 161, VulDB 160.
- **The KEV side is working as promised.** 141 CVEs published in 2026 are on the CISA KEV
  list: 138 Analyzed, 2 Modified, 1 Undergoing Analysis, **0 Deferred**. Say "140 of 141
  enriched, the last one is being analyzed now"; do not say "all 140 Analyzed" (the Sep 4
  data had 140 Analyzed + 1 Received; the refresh moved records between statuses). Say "on the KEV list", never
  "exploited" (KEV language rule).
- **Share by publication month, settled rows only:** Jan 40.3%, Feb 34.0%, Mar 26.4%,
  Apr 29.0%, May 40.7%, Jun 42.5%, Jul 41.6%, **Aug 50.5%**, Sep (8 days) 65.3%. The
  Aug and Sep figures are on thin settled cohorts (Aug still has 3,879 Received, 873
  Awaiting Analysis and 320 Undergoing) and will fall as the backlog is analyzed. Quote August as "about
  half of what NVD has settled so far", never as a final number. Post-Apr-15
  publications: 43.4% of 33,309 settled.
- **Below the floor, the pattern holds:** TR-CERT 92.2% (243), TuranSec 95.4% (194),
  CERT-PL 67.0% (233), Erlang (EEF) 60.6% (236), HCL 28.2% (195), NVIDIA 12.8% (196),
  VMware 4.1% (218), ZDI 30.7% (179).
- Floor sensitivity: the 0.0% block (Chrome, Microsoft, Adobe, Apple, Mozilla) and the
  99%+ block (three WordPress CNAs) are unchanged at 100+ or 500+.

## LinkedIn / Mastodon
Attach: `nvd_deferred_portrait_<date>.png`.
```
NVD's April policy did not remove the enrichment work. It moved it. This chart is how you find out how much of it moved to you.

The rule, published April 15: NVD enriches CVEs on CISA's KEV list, CVEs in software the federal government uses, and critical software under Executive Order 14028. Everything else is marked "not scheduled for immediate enrichment," which arrives in the API as Deferred and means no CPE. The CNA's own score usually still shows. The record does not look empty.

Of the 51,219 CVEs published in 2026 that NVD has settled, 20,076 are Deferred. That is 39%. The useful part is that it is predictable.

The rule is written about products. The result sorts by publisher. Patchstack, Wordfence and WPScan: 99% of their records Deferred. VulDB 70%, VulnCheck 52%, MITRE 47%, GitHub 27%. Microsoft, Chrome, Apple, Adobe and Mozilla: 0.0%. Take the three WordPress CNAs out and 12,608 Deferred CVEs remain. Severity does not change the answer: by the CNA's own score, Critical is Deferred at 46% and Low at 42%.

So find the CNAs that publish most of your CVEs and read your own number off the chart. If you live on WordPress plugins or open-source packages, most of your CPE matching is now yours to do, and that is a staffing question before it is a tooling one. Run a Microsoft and Chrome estate and almost nothing changed. The KEV half of the rule is holding either way: 140 of the 141 KEV-listed CVEs from 2026 are enriched and none is Deferred.

When NVD says Deferred, where does your CPE come from?

#vulnerabilitymanagement #cybersecurity #CVE #NVD
```

## X / Bluesky
```
NVD's April policy did not remove the enrichment work. It moved it.

39% of settled 2026 CVEs are Deferred: no CPE, no NVD analysis. The rule is written about products, the result sorts by publisher. WordPress CNAs 99%, VulDB 70%, Microsoft 0%.

How much of that moved to you?
```

## Alt text
```
Horizontal bar chart ranking 23 CVE Numbering Authorities by the share of their 2026 CVEs that NVD has marked Deferred, highest at the top. Patchstack 99.7 percent, Wordfence 99.7, WPScan 99.3, VulDB 70.1, Joomla 65.1, CPANSec 63.6, VulnCheck 52.2, ICS-CERT 49.1, MITRE 47.0, GitHub 26.6, Red Hat 12.4, Cisco 6.6, Linux 4.4, Apache 3.0, Dell 2.8, GitLab 1.4, IBM 1.1, Oracle 0.1. Five rows show no bar and read 0.0 percent: Chrome, Microsoft, Adobe, Apple and Mozilla. A dashed vertical line marks the 39 percent share across all settled 2026 CVEs. A right-hand column headed Settled CVEs gives each CNA's count. Footnote: settled means Analyzed, Modified or Deferred, 20,076 Deferred; excludes 8,918 CVEs still in NVD's queue. Source: NVD vulnStatus, CNA from CVE List V5.
```

## First comment (pre-loaded, post it yourself right after the post)
```
Two dates worth separating. The Deferred status itself goes back to April 2, 2025, when NVD applied it to pre-2018 CVEs. The April 15, 2026 note is the one that created the "Lowest Priority" tier for current CVEs, and NVD applied it to this year's records in bulk on June 17. It is also not permanent: a KEV listing pulls a record back into analysis. Another 8,918 CVEs from 2026 are still in the queue, so the monthly shares will keep moving. The split by CNA will not.
```

## Comment ammunition
- Deferred = `vulnStatus: "Deferred"` in the NVD 2.0 API; 0 of 20,076 have a CPE
  configuration; none has an NVD-authored CVSS. 17,808 (88.7%) carry the CNA's v3.
- "So NVD stopped working": 140 of 141 KEV-listed 2026 CVEs are Analyzed or Modified
  (the other is Undergoing Analysis). 27,156 Analyzed plus 3,987 Modified this year. The tiering is real; the
  tier boundary is the CNA.
- "Is it just WordPress plugins?" Three WordPress CNAs are 7,468 of the 20,076 Deferred
  (37%). Take them out and 12,608 of 43,726 settled non-WordPress CVEs are still
  Deferred, 29%, with VulDB, VulnCheck, MITRE and GitHub carrying it.
- "Those are low-value CVEs anyway": 1,646 Deferred carry a CNA score of 9.0+, 890 at
  9.8. Deferred share is 45.7% for CNA-Critical vs 41.5% for CNA-Low.
- Linux at 4.4% and Microsoft at 0.0% are the CNAs NVD has historically fully enriched;
  Red Hat at 12.4% is the surprise on the enterprise side.
- Related shipped posts: `patch_tag` (Sep 4) cited 20,075 Deferred as the reason NVD's
  Patch tag is missing on those records; `nvd_ssvc_deadweight` caption has the SSVC
  side (88.1% of 2026 CVEs carry decision points, 22.2% carry an NVD score).

## Traps (do not ship these)
- **This is a "here is the work left" post, not an anti-NVD post. Jerry set the frame twice
  on 2026-09-08**, rejecting "NVD is not behind anymore" (makes light of it, and they said
  they would do this and are doing it) and then rejecting "harder to plan around than an
  outage" (backwards: the data HELPS you plan, because you can see who is not being
  enriched). The policy is predictable, and predictable is usable. Line one says the work
  moved rather than vanished; the payoff paragraph tells the reader how to read their own
  number off the chart. Never frame a followed policy as a failure, and never claim this
  makes planning harder.
- **Never write "never" or "will never score".** Deferred is "not scheduled for
  immediate enrichment"; a KEV listing or a request pulls a record back. Five of twelve
  reviewers flagged this. Say "will not score" or "not scheduled".
- **Do not say "no NVD score" as the definition of Deferred.** Most Analyzed 2026 rows
  have no NVD-authored score either. The discriminator is the CPE. Say "no CPE, no NVD
  analysis".
- **Do not say "NVD decides by publisher" as the rule.** The written rule is KEV / federal
  use / EO 14028 software. The chart shows the OUTCOME sorts by CNA. State the rule, then
  the outcome, as the copy does.
- **Do not quote August "about half" in the post.** 3,879 Received plus 873 Awaiting plus
  320 Undergoing are still open for August; the settled share can land anywhere from
  29.6% (all pending analyzed) to 50.5%. Caption only, with the range.
- **Do not say "NVD stopped scoring" or "NVD gave up".** It Analyzed 27,156 of this
  year's CVEs and has enriched 140 of the 141 KEV-listed ones. The claim is about WHICH CVEs it defers, not
  whether it works.
- **Do not call it a severity cut or a risk cut.** Deferred share is flat to rising
  across the CNA's own severity bands (Low 41.5%, Critical 45.7%). It tracks the CNA.
- **Do not rank CNAs on quality or effort.** The chart shows NVD's decision about a
  CNA's records, not the CNA's work. Patchstack at 99.7% is a fact about NVD's queue
  policy, not about Patchstack. Same rule as `cwe_cna_rank` and `patch_tag`: a map of
  practice, never a scorecard of intent.
- **Do not quote 42.5%.** That excluded Modified rows. The number is 39.2% (39%).
- **Do not quote a monthly share as final.** August is 50.5% of a settled cohort that
  is still missing 5,072 CVEs in Received, Awaiting or Undergoing Analysis.
- **The bulk flag date is verified, but keep it to comments.** 8,255 of the 20,076
  Deferred rows carry a `lastModified` of 2026-06-17 (next largest days: Jul 23 1,295,
  Aug 26 1,095); earliest is Jun 16. So the Apr 15 policy was applied in bulk two months
  later. Fine as comment ammunition, not in the post, where "since April" is the
  honest framing of the policy.
- **KEV language:** "on the CISA KEV list", never "exploited" as a blanket.
- **Received is not Deferred.** 5,529 Received CVEs have no CPE either, for a different
  reason (nobody has looked yet). Never fold them into the Deferred count.
- **"No CPE" is not "no product".** Every one of these records names its product in the
  CNA container's `affected[]`. What is missing is NVD's CPE match string, which is what
  most scanners key on. Say "no CPE", not "no product data".
- Pre-2026 Deferred counts (25,747 rows on older CVEs) are a backlog-clearing artifact
  and not comparable to the 2026 in-flow share. Keep the chart to 2026 publications.

## Review log
2026-09-08: built and captioned on the Sep 4 data, then data refreshed the same day and
every figure re-derived from the chart's own cohort function (20,076 Deferred unchanged;
settled 51,133 -> 51,219 after switching the CNA join to inner so V5-rejected records drop;
39.3% -> 39.2%; KEV cohort moved from 140 Analyzed + 1 Received to 138 Analyzed + 2 Modified + 1
Undergoing, copy reworded to "140 of 141 enriched"). Severity-independence check run
before drafting the hook (Critical 45.7% vs Low 41.5%; VulDB Critical 89.9% vs Low 70.8%).
Cohort widened from the scan's Analyzed + Deferred to include Modified after confirming
Modified rows are 100% enriched (CPE), 46% NVD-scored.

`/post-review` run 2026-09-08 (12 personas): COPY "post with fixes", GRAPH "fix first".
Blocker: X post 317 chars (replaced, 277). Should-fixes, all applied: "never" cut
(reversible status); "no NVD score" replaced with "no CPE, no NVD analysis" after the
factcheck showed 61% of Analyzed rows also lack an NVD-authored score; "opinion of the
publisher" replaced with NVD's written criteria (KEV, federal use, EO 14028, verified on
nist.gov) followed by the observed outcome; April policy / June bulk-flag timeline made
explicit; August "about half" dropped from the post (range 29.6% to 50.5% with 5,072
pending); "NVD's queue, not the CNAs' work" line added so Patchstack 99.7% is not read as a
CNA quality score; 12,608 non-WordPress Deferred added for the non-WordPress reader; KEV
folded to one line as the rule working; closer kept. Chart: subtitle now says "settled"
and drops "no NVD score"; count column right-aligned with header; reference line moved
under the bars; label "All Settled 2026 CVEs: 39.2%"; footnote and source line reworded.
Panel proposals rejected by the editor and by me: a second severity-band image (Simpson's
risk inside aggregators), replacement closers, keeping "never", a Deferred-count column.
Series note for the calendar: three CNA ranked-bar charts in four weeks; the next
scoring-lane chart should not be CNA bars. Tells linter passed on the reviewed copy (234 words).

**Jerry reset the frame twice after review, 2026-09-08.** First he rejected "NVD is not
behind anymore" (makes light of it; they announced this and are doing it). The replacement
argued a followed policy is "harder to plan around than an outage" and he rejected that too:
the data HELPS you plan, because it shows who is not being enriched, and the post is a "here
is the work left" post, not an anti-NVD post. Final copy: line one is that the policy moved
the enrichment work rather than removing it, the criteria paragraph comes second, and the
payoff tells the reader to find their own CNAs on the chart and read their number, splitting
WordPress and open-source estates (most CPE matching is now theirs) from Microsoft and Chrome
estates (little changed). KEV coverage holding is the reassurance, not the alibi. First
comment carries the two-date history and reversibility. 269 words, tells linter PASSED after
a rhythm fix (first pass flagged uniform sentence length); X post 268 characters.

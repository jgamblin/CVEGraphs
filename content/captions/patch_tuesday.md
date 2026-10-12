# Caption: Patch Tuesday size and composition (`patch_tuesday`)

Image: `graphs/patch_tuesday_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Built 2026-09-08 at Jerry's request, same
day, off the Tue/Thu template as a **news trigger**: Microsoft's September release is the
biggest Patch Tuesday on record. First post of the Mon Sep 7 week, so inside the 2/week
cap.

Chart: `charts/patch_tuesday.py`, stacked bars, 24 trailing Patch Tuesdays (Oct 2024 to
Sep 2026), memory safety on the baseline and everything else on top.

**Text budget (Jerry, 2026-09-08, second time he has said it): one footnote, one line,
source and as-of date only. One-line subtitle.** The first build carried a four-line
footnote with the CWE set, the baseline share and the severity check; that squeezed the
plot and Jerry cut it. **Everything below now lives here and nowhere else, so it has to be
carried into the post copy and the comments by hand.** `charts/patch_tuesday.py:stats()`
prints the derived figures (955, 728, 76.2%, 51.2%, prior high 570, mean 135) so the copy
never has to retype them from the image. See the text-budget table in
`content/INSIGHTS.md`.

Data: `data.load_cvelist()` (CVE List V5), Microsoft-assigned non-rejected CVEs by
publication date, de-duplicated by CVE ID.

## Why one day per bar, not one month
Patch Tuesday is 85% to 99% of Microsoft's month, and a September *month* bar would be
partial while the other 23 were complete. Every bar is one calendar day of the same kind.
Patch Tuesday is derived as the second Tuesday of the month, not hand-listed, and it is
also the busiest Microsoft publishing day in all 24 months plotted, so the derivation is
not quietly picking a slow day.

## Finding (verified 2026-09-08 on data refreshed the same day, snapshot 17:19 UTC)

**Microsoft published 955 CVEs on 2026-09-08, the biggest Patch Tuesday on record.**

| Measure | September 2026 | Comparison |
|---|---|---|
| CVEs in the release | 955 | prior high 570 (Jul 14, 2026); pre-2026 high 167 (Oct 14, 2025) |
| Memory-safety share | 76.2% (728 of 955) | 51% across the previous 23 releases |
| Median CVSS v3 | 7.8 | inside the 7.1 to 8.1 range of all 24 releases |
| Critical share | 4.2% (40 of 955) | 0.0% to 7.2% across the 24 |
| Mean release size, previous 23 | 135 | trailing 12 months 172, calendar 2025 93 |

- **The count is a three-month step change, not a one-off.** Microsoft's releases ran 54
  to 200 CVEs from Oct 2024 through Jun 2026, then 570 (Jul), 402 (Aug), 955 (Sep).
  Whole-month totals tell the same story: 648, 471, 963.
- **Composition moved further than the count.** Three CWEs carry 608 of the 955: heap
  overflow CWE-122 (293), use-after-free CWE-416 (168), out-of-bounds read CWE-125 (147).
  Memory safety is counted as 23 memory-error CWEs (119/120/121/122/124/125/126/127/129/
  131/415/416/476/680/786/787/788/805/822/823/824/843/908). **Integer overflow (CWE-190,
  28 records), underflow (191), truncation (197) and races (CWE-362, 18) are deliberately
  excluded** as causes rather than memory errors; including them would push the share to
  about 80% without being defensible.
- **Severity did not follow the volume.** Median CVSS v3 7.8 and mean 7.43 sit dead centre
  of the 24-release range. Use this against both overclaims: it is not a flood of padding
  and it is not 955 emergencies.
- **NOT the biggest single-day CNA batch ever.** Oracle published 1,097 on 2026-07-21
  (see `cna_burst`, posted Jul 22). September 8 is second all-time. Do not let the copy
  drift into "record batch"; it is a record *Patch Tuesday*.
- **The batch is broad, not one component.** Largest single title cluster is Windows
  Biometric Service elevation of privilege at 63, then SQL Server RCE at 22 and Office
  Word RCE at 21. Long tail across Windows, Office, SQL Server, SharePoint, Exchange,
  Visual Studio Code, .NET.

## Caveats that must survive into the copy
- **No credit data.** All 955 records carry an empty `credits` array; Microsoft does not
  populate it. So the *cause* of the surge (automation, an internal program, a single
  reporter) is not in the file. The hook may infer it as an opinion, but the post has to
  say the data cannot settle it.
- **Same-day snapshot.** The refresh stopped at 17:19 UTC on Sep 8 and Microsoft publishes
  around that window, so 955 is a floor for the day and may rise slightly. Re-check before
  quoting the number anywhere permanent.
- **First-listed product is not meaningful.** 548 of the 955 list "Windows 10 Version 1607"
  first, but median `product_count` is 13, so that is list order, not concentration. Do
  not build a "legacy Windows" angle on it.
- **This counts CVE IDs, not vulnerabilities or patches.** One ID can span 28 products.

## Post copy (LinkedIn, shipped 2026-09-08)

> Nobody hand-audited their way to 955 CVEs in one Patch Tuesday.
>
> Microsoft published 955 CVEs today. Their previous single-day high was 570 in July, and
> before this year they had never crossed 167. The composition moved further than the
> count: 728 of the 955 (76%) are memory-safety bugs, against 51% across the previous 23
> Patch Tuesdays, and heap overflow, use-after-free and out-of-bounds read account for 608
> on their own.
>
> Severity stayed put. Median CVSS v3 is 7.8, inside the 7.1 to 8.1 range of every release
> in the last two years, so this is neither padding nor 955 emergencies. Microsoft is
> finding and disclosing far more of the same class of bug, which is the work going right.
> The bill for it lands on your triage queue. Worth being precise about what the data
> can't tell me: these records carry no credit field, so who or what found them isn't in
> the file. It's also not the biggest single-day batch ever. Oracle put out 1,097 in a day
> this July.
>
> If you review every Microsoft CVE in a release, what do you actually do with one that is
> more than five times a normal release and no more severe than usual?

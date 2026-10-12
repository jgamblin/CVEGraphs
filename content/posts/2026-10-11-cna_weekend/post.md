---
chart: cna_weekend
posted: 2026-10-11
platforms: LI, X
migrated: 2026-10-11
---
# Caption: who publishes CVEs on the weekend (`cna_weekend`)

Image: `graphs/cna_weekend_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Built 2026-10-11 after Saturday Oct 10 drew
412 CVEs (2nd-largest Saturday of 2026 after Aug 15's 921), 92% of them from Patchstack,
VulnCheck and Wordfence. Jerry is posting it the weekend of Oct 10-11 as a weekend post. `/post-review` run 2026-10-11 (COPY "rework", GRAPH "fix first"); graph fixes G1-G4 applied, copy kept funny per Jerry with the factual fixes applied (no "yesterday" peg, no "every weekend", no "patch days", closing question added).

Chart: `charts/cna_weekend.py`. Timesheet grid: 16 largest CNAs by 2026 volume (MITRE
excluded), CVEs per day of week, weekend columns red, 
rows sorted by weekend share. Weekday cells flat grey; weekend cells on one shared navy log scale; zeros print as a muted "0". `stats()` prints every figure below.

## Finding (CVE List V5, Jan 1 to Oct 10, 2026, UTC days)

| Measure | Value |
|---|---|
| CVEs published | 76,765 |
| On a Saturday or Sunday | 7,392 (9.6%) |
| CNAs that published in 2026 | 389 |
| CNAs with at least one weekend CVE | 68 (321 never) |
| Top five weekend publishers | Linux 1,893; VulDB 1,745; VulnCheck 1,504; Wordfence 909; WPScan 383 |
| Top five share of all weekend CVEs | 87% |
| Weekend share, top five | VulDB 32%, Wordfence 27%, Linux 26%, WPScan 24%, VulnCheck 21% |
| Zero weekend CVEs (16-row grid) | Chrome 3,193; Oracle 3,076; IBM 1,356; Apple 812; Mozilla 592 |
| Microsoft / Adobe | 5 of 2,970 / 1 of 830 |
| VulDB weekends with a CVE | 39 of 41 (VulnCheck 36, Wordfence 38, Linux 18, WPScan 18) |
| WPScan weekend CVEs stamped 06:00 UTC | 373 of 383 (all at 06:00 exactly) |

## Accuracy guards

- **UTC days, not local days.** Wordfence's Saturday volume is mostly 01:00 to 08:00 UTC,
  which is Friday night US Eastern. Linux's biggest Saturday slot is 05:00 UTC. On a
  "core weekend" (Sat 12:00 to Sun 12:00 UTC, weekend in every time zone) the count drops
  to 2,922, led by VulDB 1,009, VulnCheck 805, Linux 422. Do not write that a named CNA's
  staff "work Saturdays"; these are mostly automated pipelines and time-zone spill.
- **Volume CNAs, not vendors.** The weekend crew are aggregators and bulk publishers
  (VulDB, VulnCheck, WordPress-ecosystem CNAs, the kernel). Vendor PSIRTs ship on their
  patch day.
- **MITRE excluded** because of date-only timestamps; say so if asked why it is missing.

## Final copy (LinkedIn)

Passed `tells.py`. Funny frame is Jerry's ("we've all worked a weekend"); every number
is from `stats()` or the checks above. Do not reintroduce "catch up" (implies the CNAs are
behind) or Saturday Oct 10's 412 (160 of those were Patchstack, not one of the five).

> Every team has someone who answers Slack on a Saturday. The CVE world has five of them.
>
> The Linux kernel, VulDB, VulnCheck, Wordfence and WPScan published 87% of this year's 7,392 weekend CVEs. VulDB has shown up on 39 of the 41 weekends so far. Chrome, Oracle, IBM, Apple and Mozilla are at a clean zero, because vendors publish CVEs alongside their own releases and those ship on weekdays.
>
> At least one of the five looks like a cron job: 373 of WPScan's 383 weekend CVEs went out at 06:00 UTC on the dot. Most dedicated coworker in security.
>
> When the weekend crew's work hits your queue on Monday, does it get the same first look as a vendor advisory?

**First comment:** Days are UTC, so some "Saturday" CVEs went out Friday night in the US.
Most of Wordfence's do. MITRE is left off the chart because its records carry date-only
timestamps.

## X
Attach: `cna_weekend_wide_<date>.png`. 253 of 280 characters. Passed `tells.py`.
```
Every team has someone who answers Slack on a Saturday. The CVE world has five: the Linux kernel, VulDB, VulnCheck, Wordfence and WPScan, with 87% of 2026's weekend CVEs.

One looks like a cron job: 373 of WPScan's 383 went out at 06:00 UTC on the dot.
```

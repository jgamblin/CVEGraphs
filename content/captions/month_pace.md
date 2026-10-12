# Caption: cumulative CVEs by day of month (`month_pace`)

Image: `graphs/month_pace_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Built 2026-09-24 from a September data scan.
**Volume lane, milestone-only.**

**Scope conflict, read first.** The month-close volume post comes from the
MonthlyCVEStats repo (Sep 1 post: 2,256 impressions, 7 reposts). This chart is the
*mid-month* companion. Two honest uses: (a) post it the day September passes August's
12,261 (**it did, at 18:56 UTC on Sep 24**, with the month's 12,262nd CVE) as a
milestone card, or (b) hand the figure to MonthlyCVEStats for its Oct 1 post and do not
post this at all. Do not do both: that is two volume posts in eight days.

Chart: `charts/month_pace.py`. One cumulative line per 2026 month, September heavy navy,
August mid navy, others pale; dashed rule at the all-time monthly record. `/post-review`
not run.

## Finding (CVE List V5, refreshed 2026-09-25, newest record 07:44 UTC)

| Measure | Value |
|---|---|
| September to date | 12,377 (12,308 through day 24) |
| August at day 24 | 9,653 (Sep ahead by 27.5%) |
| Previous monthly record | 12,261 (Aug 2026) |
| **Record passed** | **Sep 24, 18:56 UTC** (Sep 24 carried 553 CVEs; Linux 234) |
| Margin over the old record | 116, with six days left |
| Run rate, completed days | 512.8 per day |
| Sep 2025, full month | 4,319 |

Drivers (from the scan): Linux 1,507, VulnCheck 1,170, GitHub 1,150, Microsoft 999
(965 on Patch Tuesday), VulDB 693, Oracle 634 (Sep 15 CPU). Eleven CNAs set record months.

## Accuracy guards

- Compare at the last **completed** day. The chart does; the copy must too.
- No projection is drawn. "On pace to" is fine in copy; a projected month-end number is
  not, because Oracle-, Microsoft- and Linux-style batches make the tail lumpy.
- The volume lane is saturated ("counts measure publishing, not risk" has aired five-plus
  times). If this posts, the hook has to be about the calendar, not the count.

## Draft copy (LinkedIn, only if option (a))

> August's all-time CVE record lasted 24 days.
>
> September passed August's 12,261 on Sep 24, with six days still to go.
> At day 24 it was 27.5% ahead of August's pace, which was itself a record. Linux,
> Microsoft and Oracle alone published 3,374 of this month's CVEs.
>
> If your team's planning number came from August, it's already low. What are you
> budgeting for October?

Crossing confirmed in the 2026-09-25 refresh. Re-check the 3,374 and the day-24 lead from `stats()` on the posting day.

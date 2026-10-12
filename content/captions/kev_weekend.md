# Caption: KEV additions by day of the week (`kev_weekend`)

Image: `graphs/kev_weekend_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Built 2026-10-08 from a first-week-of-October
data scan at Jerry's request. **Exploitation lane, Thursday, on-lane.** Angle (Jerry's):
automation and alerting are now a must, because CISA lists on weekends and the deadline
is three days.

Chart: `charts/kev_weekend.py`. One bar per weekday across the whole catalog, weekend bars
in red, with a callout listing all four weekend entries so the reader can count them.
`stats()` prints every figure below. `/post-review` run 2026-10-08; fixes applied.

## Finding (KEV catalog version 2026.10.04, refreshed 2026-10-08)

| Measure | Value |
|---|---|
| KEV entries, Nov 3 2021 to Oct 4 2026 | 1,734 |
| Added on a Saturday | **0** |
| Added on a Sunday | **4** (3 listing days of 482) |
| Sun Jul 20 2025 | CVE-2025-53770, Microsoft SharePoint (due Jul 21) |
| Sun Sep 27 2026 | CVE-2026-88771, CVE-2026-88772, Citrix NetScaler (due Sep 30) |
| Sun Oct 4 2026 | CVE-2026-88779, Citrix NetScaler (due Oct 7) |
| September 2026 additions with a due date 3 days or less after listing | 35 of 43 (Jun 17/23, Jul 22/26, Aug 21/31) |
| Weekday bars | Mon 318, Tue 332, Wed 540, Thu 334, Fri 206 |

All four weekend entries were published to CVE List V5 the same UTC day they were listed
(CVE-2026-88779 at 02:35 UTC Oct 4).

## Accuracy guards

- **KEV language rule.** "Added to KEV", never "exploited".
- **Date-only field.** `dateAdded` is CISA's calendar date; the weekday is read straight off
  it. Do not claim an hour for any listing.
- **Wednesday is inflated by the launch** (Nov 3 2021, a Wednesday, 287 entries; drawn as a pale segment). Irrelevant
  to the weekend claim; if a commenter asks why Wednesday, that is why.
- **The deadline is federal, and it is BOD 26-04, not 22-01.** All three NetScaler entries
  cite BOD 26-04 in `requiredAction` and carry `forensicTriage: Yes`; their three-day due
  date binds FCEB agencies. SharePoint (CVE-2025-53770, Jul 2025) predates it and got a
  one-day due date. Never cite BOD 22-01 for the 2026 entries in replies, and never write
  "each" of the four got three days.
- **Four is a small number.** It is a count, not a trend. Do not write "CISA now lists on
  weekends"; write what happened on which Sundays.
- **Hook rule (credit, then consequence).** CISA did the fast thing; the work moved to the
  reader. No gotcha framing aimed at CISA or Citrix.

## Draft copy (LinkedIn)

Revised 2026-10-08: opening is Jerry's "five years of KEV" line (revised again 2026-10-08); body carries the
`/post-review` fixes (COPY "post with fixes", GRAPH "fix first", all applied). KEV feed
re-pulled 2026-10-08: still version 2026.10.04, no additions since. Passed `tells.py`.

> Five years of KEV taught us that CISA doesn't update it on the weekend. The last two Sundays changed that.
>
> In 1,734 entries since November 2021, CISA has never added one on a Saturday and has added only four on a Sunday. Three of the four are these NetScaler bugs: two on Sep 27 and one on Oct 4. The fourth was SharePoint (ToolShell) in July 2025.
>
> Both NetScaler listings came with a three-day federal deadline, which is now the norm for what CISA lists. A Sunday listing is due Wednesday, so if you track to KEV due dates and find out Monday morning, a third of the window is already gone.
>
> Credit to CISA for not waiting until Monday. The work moves to our side: if your KEV pull only runs on weekdays, a Sunday listing sits until Monday. Make sure it runs every day and alerts when it matches something you run. What tells your team when KEV changes on a Sunday?

**First comment:** All three NetScaler entries carry CISA's forensic-triage flag, so the
job is patch and check for compromise. (Link the kev_triage post if it shipped.)

## X
Attach: `kev_weekend_wide_<date>.png`. 262 of 280 characters. Passed `tells.py`.
```
Five years of KEV taught us that CISA doesn't update it on the weekend. The last two Sundays changed that.

1,734 entries: 0 on a Saturday, 4 on a Sunday. Three are Citrix NetScaler (Sep 27, Oct 4), each due in three days.

Does your KEV alerting run on Sundays?
```

## Mastodon
Attach: `kev_weekend_wide_<date>.png` with the alt text below. 479 of 500 characters.
Passed `tells.py`.
```
Five years of KEV taught us that CISA doesn't update it on the weekend. The last two Sundays changed that.

Of 1,734 KEV entries since Nov 2021, none were added on a Saturday and four on a Sunday. Three are Citrix NetScaler: two on Sep 27, one on Oct 4. Each came with a three-day federal deadline, so a Sunday listing is due Wednesday.

If your KEV pull only runs on weekdays, it sits until Monday. Make it run every day and alert on a match.

#infosec #CVE #KEV #vulnmanagement
```

**Alt text (X and Mastodon):**
```
Bar chart of CISA KEV additions by day of the week, all 1,734 entries from Nov 3, 2021 to Oct 4, 2026. Monday 318, Tuesday 332, Wednesday 540 (287 of them on the catalog's launch day), Thursday 334, Friday 206, Saturday 0, Sunday 4. A table lists the Sunday additions: Jul 20, 2025 Microsoft SharePoint; Sep 27, 2026 Citrix NetScaler (2 CVEs); Oct 4, 2026 Citrix NetScaler.
```

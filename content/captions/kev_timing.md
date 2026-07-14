# Caption — Bars: how old a CVE is when CISA adds it to KEV (`kev_timing`)

Image: `graphs/kev_timing_<ratio>_<date>.png`. House style: no em dashes; factual
Title-Case heading AND labels. Exploitation-timing lane; pairs with `exploited_cwe`.

Finding (verified, KEV dateAdded minus CVE List datePublished on CALENDAR dates, the 153
CVEs CISA added so far in 2026): Same Day 16%, 1-7 days 21%, 8-30 days 16%, 1-12 months 24%,
1-3 years 8%, over 3 years 15%. Median 20 days. Over half (53%) are added within 30 days of
publication, about three-quarters (77%) within a year. Oldest at KEV: Windows CVE-2008-4250
(~17.6 yr), Office CVE-2009-0238 (~17 yr). NO 2026 CVE was added a calendar day before its
CVE.org record. (An earlier draft's "before publication" bucket was a date-flooring bug:
dateAdded is date-only, datePublished carries a time, so a same-day-published-later gap
floored to -1. Fixed by comparing normalized calendar dates.) Robustness: the shape is stable
2023-2026; 2022 is excluded as the KEV-launch bulk-load outlier.

## LinkedIn / Mastodon
Attach: `kev_timing_wide_<date>.png`.
```
When CISA flags a vulnerability as actively exploited, how old is it? So far in 2026, most are fresh, but a stubborn slice are ancient.

I measured the gap from a CVE.org record being published to that CVE landing on CISA's Known Exploited Vulnerabilities list, across the 153 CVEs CISA added this year. Most move fast: over half are added within a month of publication, and about three-quarters within a year. That tracks with how we picture exploitation working, a new bug, a quick confirmation, onto the list.

But 15% break the pattern. They are more than three years old when CISA flags them, including a 2008 Windows bug and a 2009 Office bug, each about 17 years old at listing. Recency catches most of what CISA confirms as exploited, but not the old vulnerability that suddenly comes back. Is your program built to catch that one?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
When CISA flags a CVE as exploited in 2026, how old is it? Mostly fresh, over half are added within a month of publication.

But 15% are more than three years old when they hit the list, including a 2008 Windows bug and a 2009 Office bug, each about 17 years old.

Recency catches most of what gets confirmed exploited, but not the old bug that comes back.
```

## Alt text
```
Vertical bar chart of the number of days from a CVE.org record's publication to its addition
to CISA's Known Exploited Vulnerabilities list, for the 153 CVEs CISA added so far in 2026,
in six buckets that sum to 100%. Same Day 16%, 1 to 7 Days 21%, 8 to 30 Days 16%, 1 to 12
Months 24%, 1 to 3 Years 8%, Over 3 Years 15%. Source: CISA KEV and CVE List V5.
```

## Notes / caveats
- DATE BUG (fixed): compare CALENDAR dates (normalize both), because dateAdded is date-only
  and datePublished carries a time; a raw subtraction floors a same-day-published-later gap
  to -1 and invents a phantom "before publication" bucket. A post-review pass caught this.
- No 2026 CVE was added a calendar day before its CVE.org record; the "Before Publication"
  bar is shown only if that bucket is non-empty (it is 0 for 2026).
- Do NOT claim "freshness is a weak triage signal": it conditions on the outcome (only CVEs
  that reached KEV), and the data in fact shows most flagged CVEs are recent. The honest
  framing is "recency catches most of what CISA confirms, but not the old tail."
- Do NOT resurrect the "flagged a day ahead" vendor examples (Cisco/Microsoft/Fortinet/
  Ivanti) or "both ends at once" framing; all were the date bug.
- "about 17 years", not "nearly two decades" (17 < 18).
- Window is the current calendar year (added since Jan 1), evergreen; year-added split shows
  the shape is stable 2023-2026, so the 153-CVE sample is representative; 2022 excluded.
- Buckets partition the cohort, largest-remainder rounded to sum to 100. Footer darkened to
  the subtitle grey for WCAG AA. Stamped with the KEV catalog dateReleased.

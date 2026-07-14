# Caption — Bars: how old a CVE is when CISA adds it to KEV (`kev_timing`)

Image: `graphs/kev_timing_<ratio>_<date>.png`. House style: no em dashes; factual
Title-Case heading. Exploitation-timing lane; pairs with `exploited_cwe` / `kev_severity`.

Finding (verified, KEV dateAdded minus CVE List datePublished, the 153 CVEs CISA added so
far in 2026): age at KEV listing: before publication (at least a full day ahead, gap <= -1)
16% (24 CVEs), same day to 7 days 24%, 8-30 days 14%, 1-12 months 23%, 1-3 years 8%, over 3
years 15%. Same-day listings (gap 0, ~8%) are grouped with the within-a-week bucket, NOT
counted as "before", because KEV dates have no time so same-day order is unknowable. Every
2026 "before" case is exactly one day ahead (Cisco CVE-2026-20262, Microsoft Office
CVE-2026-21509, Fortinet CVE-2026-24858, Ivanti CVE-2026-1281); no 2026 case leads by more.
Oldest at KEV: Windows CVE-2008-4250 (~17.6 yr), Office CVE-2009-0238 (~17 yr). Median 19 days.
Robustness: the shape is stable every year 2023-2026; 2022 is the KEV-launch bulk-load
outlier (58% over 3 years, median ~4 yr) and is excluded by the current-year window.

## LinkedIn / Mastodon
Attach: `kev_timing_wide_<date>.png`.
```
When CISA flags a vulnerability as actively exploited, how old is it? So far in 2026, the answer lands at both ends at once.

I measured the gap from a CVE.org record being published to that CVE landing on CISA's Known Exploited Vulnerabilities list. About 1 in 6 were on the exploited list at least a full day before their CVE.org record was even published. Recent examples: Cisco, Microsoft, Fortinet, and Ivanti flaws that CISA flagged a day ahead of the record. Another quarter arrive within a week.

But the other end is just as loud. Just as many exploited CVEs are ancient as arrive early: 15% are more than three years old, a couple of them nearly two decades, including a 2008 Windows bug and a 2009 Office bug.

So freshness is a weak triage signal. Some exploited bugs beat their own CVE record onto the list, others sat unpatched for years. Which end is your program weaker at?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
When CISA flags a CVE as exploited, how old is it? In 2026, both ends at once.

About 1 in 6 landed on the exploited list at least a full day before their CVE.org record was published (Cisco, Microsoft, Fortinet, Ivanti). But just as many, 15%, are more than three years old.

Freshness is a weak triage signal.
```

## Alt text
```
Vertical bar chart of how long after its CVE.org record is published a CVE lands on CISA's
Known Exploited Vulnerabilities list, for the 153 CVEs CISA added so far in 2026, in six
buckets that sum to 100%. Before the CVE was published (at least a day ahead) 16%, same day
to 7 days 24%, 8 to 30 days 14%, 1 to 12 months 23%, 1 to 3 years 8%, over 3 years 15%.
Source: CISA KEV and CVE List V5.
```

## Notes / caveats
- Gap uses CVE List `datePublished` (the canonical public date), NOT NVD's, which lags.
- "Before publication" requires gap <= -1 (at least a full day ahead). KEV dateAdded has no
  time component, so a same-day listing (gap 0) is NOT provably before the record and is
  grouped with "same day to 7 days". This was a deliberate rigor call.
- Every 2026 "before" case leads by exactly one day; there is no 2026 equivalent of the old
  dramatic multi-month leads. Those (Firefox 290d, Chromium) were 2022-2023 additions and
  reflect CVE.org publication *lag*, not CISA precognition. Do not resurrect them for a 2026 post.
- Window is the current calendar year (added since Jan 1), evergreen. Not "last 24 months":
  a year-added split shows the distribution is stable 2023-2026, so the smaller current-year
  sample (153) is representative; 2022 is excluded as the KEV-launch bulk-load outlier.
- Buckets are a partition (each CVE one bucket), largest-remainder rounded to sum to 100.
- Stamped with the KEV catalog `dateReleased`. Heading factual + Title Case; story in the copy.

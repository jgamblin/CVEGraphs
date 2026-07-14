# Caption — Bars: how old a CVE is when CISA adds it to KEV (`kev_timing`)

Image: `graphs/kev_timing_<ratio>_<date>.png`. House style: no em dashes; factual
Title-Case heading AND labels. Exploitation-timing lane; pairs with `exploited_cwe`.

Finding (verified, KEV dateAdded minus CVE List datePublished on CALENDAR dates, the 153
CVEs CISA added so far in 2026): Same Day 16%, 1-7 days 21%, 8-30 days 16%, 1-12 months 24%,
1-3 years 8%, over 3 years 15%. Median 20 days. Over half (53%) are added within 30 days of
publication, about three-quarters (~76%) within a year. Oldest at KEV: Windows CVE-2008-4250
(~17.6 yr, "nearly 18"), Office CVE-2009-0238 (~17 yr). NO 2026 CVE was added a calendar day before its
CVE.org record. (An earlier draft's "before publication" bucket was a date-flooring bug:
dateAdded is date-only, datePublished carries a time, so a same-day-published-later gap
floored to -1. Fixed by comparing normalized calendar dates.) Robustness: the shape is stable
2023-2026; 2022 is excluded as the KEV-launch bulk-load outlier.

## LinkedIn / Mastodon
Attach: `kev_timing_wide_<date>.png`.
```
CISA added 153 CVEs to its Known Exploited Vulnerabilities list so far in 2026. Over half landed within a month of publication, but a stubborn 15% were more than three years old at listing.

I measured the gap from a CVE.org record being published to that CVE landing on KEV. Most move fast: about three-quarters are listed within a year of publication. That tracks with how we picture exploitation: a new bug, a quick confirmation, onto the list.

But 15% break the pattern, more than three years old when CISA lists them, including a 2008 Windows bug (nearly 18 years) and a 2009 Office bug (about 17). Listing dates cannot tell us whether that exploitation is new or long-running, only that CISA confirmed it years after disclosure. Is your program built to catch the old one?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
CISA added 153 CVEs to its Known Exploited Vulnerabilities list so far in 2026. Over half landed within a month of publication.

But 15% were more than three years old when they hit the list, including a 2008 Windows bug (nearly 18 years) and a 2009 Office bug (about 17).

Most get listed soon after disclosure, but a stubborn tail is confirmed years after the bug first appeared.
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
- Conditioning trap: this is a distribution over CVEs that ALREADY reached KEV, so it says
  nothing about age as a predictor of exploitation, nor whether the old-tail exploitation is
  new ("resurgence") or long-running. Do NOT claim "freshness is a weak triage signal",
  "recency catches most of what CISA confirms", or "the bug that suddenly comes back". Keep it
  descriptive: "listing dates only tell us CISA confirmed it years after disclosure."
- Chart accents the "Over 3 Years" bar (primary/navy, luminance-distinct) so the image carries
  the tail story; the other five bars are the standard accent blue. Subtitle spells out KEV.
- Do NOT resurrect the "flagged a day ahead" vendor examples (Cisco/Microsoft/Fortinet/
  Ivanti) or "both ends at once" framing; all were the date bug.
- "about 17 years", not "nearly two decades" (17 < 18).
- Window is the current calendar year (added since Jan 1), evergreen; year-added split shows
  the shape is stable 2023-2026, so the 153-CVE sample is representative; 2022 excluded.
- Buckets partition the cohort, largest-remainder rounded to sum to 100. Footer darkened to
  the subtitle grey for WCAG AA. Stamped with the KEV catalog dateReleased.

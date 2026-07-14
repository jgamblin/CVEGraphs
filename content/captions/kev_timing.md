# Caption — Bars: how old a CVE is when CISA adds it to KEV (`kev_timing`)

Image: `graphs/kev_timing_<ratio>_<date>.png`. House style: no em dashes; factual
Title-Case heading. Exploitation-timing lane (new); pairs with `exploited_cwe` /
`kev_severity` (which classes / how severe → how long until exploited).

Finding (verified, KEV dateAdded minus CVE List datePublished, KEV entries added in the
last 24 months, 507 CVEs):
Age at KEV listing: before/at publication 24% (123), 1-7 days 15%, 8-30 days 12%, 1-12
months 24%, 1-3 years 9%, over 3 years 16%. Median gap 27 days. Note the tie: "before
publication" and "1-12 months" are both 24%. The "before publication" bucket is a mix: some
true zero-days cataloged before the CVE record went public, some CVE records simply published
late (a date artifact). Extremes: Mozilla Firefox CVE-2022-26485/26486 added to KEV 290 days
before publication, with Chromium / Adobe ColdFusion / Apple macOS weeks-to-months ahead.
All-time (incl the 2021 bulk load): 15% before publication, median 292 days, oldest ~19 years.

## LinkedIn / Mastodon
Attach: `kev_timing_wide_<date>.png`.
```
When CISA flags a vulnerability as actively exploited, how old is it? The answer runs to both extremes.

I measured the gap from a CVE going public to landing on CISA's Known Exploited Vulnerabilities list, for everything added in the last two years. The largest share, 24%, tied with the one-to-twelve-month group, landed on the exploited list before the CVE record was even published. Some are true zero-days caught in the wild; others are cases where the CVE record was simply published late. Two Firefox records trailed their KEV listing by 290 days. But the other end is just as loud: 1 in 6 exploited vulnerabilities is more than three years old, and a quarter are over a year old.

So freshness is a weak triage signal. The pre-publication cases are a detection and incident-response problem, not a patch-queue one, because there is no ticket to close yet. And a three-year-old KEV entry cannot be dismissed as stale. Which end is your program weaker at?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
When CISA flags a CVE as exploited, how old is it?

The largest share, 24%, was on the exploited list before the CVE record was published, some true zero-days, some just late-published records. But 1 in 6 is more than three years old.

Freshness tells you almost nothing: a bug CISA flags as exploited is about as likely to be years old as brand new.
```

## Alt text
```
Vertical bar chart of how long after a CVE is published it lands on CISA's Known Exploited
Vulnerabilities list, for the 507 CVEs added in the last 24 months, in six age buckets that
sum to 100%. "Before it was public" is the largest at 24%, then 1 to 7 days 15%, 8 to 30 days
12%, 1 to 12 months 24%, 1 to 3 years 9%, and over 3 years 16%. Source: CISA KEV and CVE List V5.
```

## Notes / caveats
- Gap uses CVE List `datePublished` (the canonical public date), NOT NVD's published date,
  which lags and would inflate the "before published" bucket with timing noise.
- Restricted to the last 24 months of KEV additions so the 2021 bulk-load of old CVEs (when
  the KEV program launched) does not skew the age distribution. All-time median is 292 days;
  recent-additions median is 27 days.
- The "before publication" bucket is NOT all zero-days: a negative gap can also mean the CVE
  record was published late (a process/date artifact), not proven in-the-wild-before-disclosure.
  Copy says "some true zero-days, some just late-published records." The substantial ahead cases
  (Firefox 290d, Chromium/ColdFusion weeks-to-months) are the real ones; do not over-read the
  day-scale ones. Same "dates measure process, not reality" confound as the CVSS scorer note.
- "Before publication" (24%) ties the "1-12 months" bucket (also 24%); do not call it "the
  single biggest" (the chart shows the tie).
- Buckets are a partition (each CVE in exactly one age bin), largest-remainder rounded so the
  six bars sum to 100.
- Stamped with the KEV catalog `dateReleased` (KEV is CISA-sourced), not the data-refresh date.
- Heading is factual + Title Case; the two-ended story lives in the post copy.

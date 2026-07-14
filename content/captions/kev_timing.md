# Caption — Bars: how old a CVE is when CISA adds it to KEV (`kev_timing`)

Image: `graphs/kev_timing_<ratio>_<date>.png`. House style: no em dashes; factual
Title-Case heading. Exploitation-timing lane (new); pairs with `exploited_cwe` /
`kev_severity` (which classes / how severe → how long until exploited).

Finding (verified, KEV dateAdded minus CVE List datePublished, KEV entries added in the
last 24 months, 507 CVEs):
Age at KEV listing: before/at publication 24% (123), 1-7 days 15%, 8-30 days 12%, 1-12
months 24%, 1-3 years 9%, over 3 years 16%. Median gap 27 days. The "before published"
cases are real zero-days cataloged before the CVE record went public; extremes: Mozilla
Firefox CVE-2022-26485 and CVE-2022-26486 added to KEV 291 days before publication, with
Chromium / Adobe ColdFusion / Apple macOS flagged weeks-to-months ahead. All-time (incl the
2021 bulk load) it is 15% before publication, median 292 days, oldest ~20 years.

## LinkedIn / Mastodon
Attach: `kev_timing_wide_<date>.png`.
```
When CISA flags a vulnerability as actively exploited, how old is it? The answer runs to both extremes.

I measured the gap from a CVE going public to landing on CISA's Known Exploited Vulnerabilities list, for everything added in the last two years. The single biggest group, 24%, was on the exploited list before the CVE was even published. Real zero-days, caught in the wild before the record went public. Two Firefox flaws were flagged 291 days ahead. But the other end is just as loud: 1 in 6 exploited vulnerabilities is more than three years old, and a quarter are over a year old.

So a patch queue tuned only for fresh criticals is losing on two fronts. You have to move on zero-days before a CVE even exists, and you cannot close a three-year-old ticket just because it feels stale. Which end is your program worse at?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
When CISA flags a CVE as exploited, how old is it?

The biggest group, 24%, was on the exploited list before the CVE was even published. Real zero-days. Two Firefox flaws were flagged 291 days ahead.

But 1 in 6 is over three years old. The bug that gets you is as likely to be ancient as brand new.
```

## Alt text
```
Vertical bar chart of how long after a CVE is published it lands on CISA's Known Exploited
Vulnerabilities list, for the 507 CVEs added in the last 24 months, in six age buckets that
sum to 100%. "Before it was public" is the largest at 24%, then 1 to 7 days 15%, 8 to 30 days
12%, 1 to 12 months 24%, 1 to 3 years 9%, and over 3 years 16%. The two ends (caught before
disclosure, exploited long after) are highlighted navy. Source: CISA KEV and CVE List V5.
```

## Notes / caveats
- Gap uses CVE List `datePublished` (the canonical public date), NOT NVD's published date,
  which lags and would inflate the "before published" bucket with timing noise.
- Restricted to the last 24 months of KEV additions so the 2021 bulk-load of old CVEs (when
  the KEV program launched) does not skew the age distribution. All-time median is 292 days;
  recent-additions median is 27 days.
- The marginal "before publication" cases (<=1 day ahead) can be publication-timing noise;
  the claim rests on the substantial ahead-of-publication tail (Firefox 291d, Chromium and
  ColdFusion weeks-to-months). Do not over-read the day-scale ones.
- Buckets are a partition (each CVE in exactly one age bin), largest-remainder rounded so the
  six bars sum to 100.
- Stamped with the KEV catalog `dateReleased` (KEV is CISA-sourced), not the data-refresh date.
- Heading is factual + Title Case; the two-ended story lives in the post copy.

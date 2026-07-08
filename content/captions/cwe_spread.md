# Caption — Range chart: top 10 CWEs, CVSS 80% range and median (`cwe_spread`)

Image: `graphs/cwe_spread_<ratio>_<date>.png`. House style: no em dashes.
Companion to `cna_spread` (which holds the weakness fixed and varies the
scorer). Data: CVE List V5, CVSS v3, the 10 most common CWEs.

Finding: medians run from 5.3 (missing authorization, info exposure) to 8.5 (stack
overflow). Memory-safety and injection classes score highest (stack overflow 8.5,
OS command injection 7.8, SQL injection 7.3, path traversal 7.2); the high-volume
web and access-control classes sit lower (XSS 6.4, CSRF 5.4, info exposure 5.3,
missing authz 5.3). XSS has the widest 80% band (3.5-7.1), which is partly real
severity spread and partly scorer disagreement (XSS is the most contentious class
to score, per `cna_spread`). Band width here pools all scorers, so it mixes
real variation with that disagreement.

## LinkedIn / Mastodon
Attach: `cwe_spread_wide_<date>.png`.
```
"Critical vulnerability" is doing a lot of work in most reports. Here are the 10 most common weakness types and the CVSS scores they actually get.

The pattern is clear. Memory corruption and injection sit at the top: stack overflows run a median 8.5, OS command injection 7.8, SQL injection 7.3. The classes that dominate the CVE feed by sheer volume sit noticeably lower: cross-site scripting 6.4, CSRF 5.4, information exposure and missing authorization both 5.3.

Two things worth sitting with. First, the class barely narrows the range. Even within one weakness type the middle 80% of scores spans two to four points, so knowing a bug is "an XSS" or "a path traversal" tells you surprisingly little about its severity. Second, the widest, most inconsistent class is also the most common one: XSS. Part of that spread is real, and part of it is that scorers cannot agree on how to rate XSS in the first place.

So "it is a critical CWE" is not really a category. Severity lives in the specific bug, and for some classes even the experts scoring them land two points apart.

Which weakness class do you think your program over-weights, and which does it wave through?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
The 10 most common CWEs and the CVSS scores they actually get.

Memory corruption and injection score highest (stack overflow median 8.5, OS command injection 7.8). The high-volume web classes sit lower (XSS 6.4, CSRF 5.4).

Even within one class the middle 80% spans 2-4 points. "Critical CWE" is not a category.
```

## Alt text
```
Range chart of CVSS v3 base scores for the 10 most common CWEs, one row each, sorted by median from Stack overflow at the top (median 8.5) down to Missing authorization at the bottom (5.3). Each row has a bar showing where the middle 80% of that weakness class's scores fall, colored by severity from light grey for low up to deep navy for high, with a tick at the median. Memory-safety and injection classes score highest; web and access-control classes lower. XSS has the widest band, from 3.5 to 7.1. Source: CVE List V5.
```

## Notes / caveats
- v3 for coverage; pools all scorers, so band width = real severity spread + scorer
  disagreement. The scorer part is largest for XSS (see `cna_spread`).
- Tick is the median (a pooled distribution is skewed; median is the honest center).
- Names are shortened for the axis (e.g. "Missing authz" = CWE-862, "OOB read" = CWE-125).
```

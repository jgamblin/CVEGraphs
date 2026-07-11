# Caption — Bars: KEV (exploited) rate by CWE (`cwe_kev`)

Image: `graphs/cwe_kev_<ratio>_<date>.png`. House style: no em dashes.
Exploitation companion to `cwe_spread` (severity by class). Prompted by a comment
asking to correlate the classes with KEV. Data: CVE List V5 (CWE + CVSS v3)
joined to CISA KEV (`processed/kev_catalog.json`).

Finding (verified): KEV rate = share of each class's CVEs on CISA's KEV list, over
all CVEs of that CWE. OS command injection 1.30%, input validation 1.00%, path
traversal 0.69%, stack overflow 0.48%, info exposure 0.30%, OOB read 0.16%, SQLi
0.15%, XSS 0.05%, missing authz 0.05%, CSRF 0.02%. Correlation with median CVSS is
~0.6, so severity tracks exploitation loosely but not tightly: stack overflow has
the highest median (8.5) yet is only 4th exploited; SQLi (7.3) is 7th; XSS is the
most common class but near the bottom (exploited ~25x less than OS command inj).

## LinkedIn / Mastodon
Attach: `cwe_kev_wide_<date>.png`.
```
Attackers do not read your CVSS scores.

I recently charted CVSS by weakness class, and a few of you asked the obvious next question: which of these actually get exploited? So here are the same 10 classes, ranked by the share that have landed on CISA's KEV list.

Severity and exploitation do line up a little, but the gaps are the story. OS command injection leads, exploited about 25 times as often as XSS. Cross-site scripting is the most common bug on the internet and sits near the bottom. SQL injection carries a high 7.3 median yet is rarely exploited. And the single highest-severity class, stack buffer overflow at a median 8.5, is only fourth for real-world exploitation.

Look at the CVSS column on the right. Sorted by what actually gets used, the severity scores fall out of order. A high base score is a statement about potential impact, not a prediction that anyone will bother.

So if you rank your queue by CVSS alone, you are optimizing for the wrong thing. Exploitation evidence, KEV and EPSS, tells you where attention is actually going.

Thanks to the folks who asked for this one.

What share of your remediation is driven by exploitation signal versus raw severity?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
Attackers do not read your CVSS scores.

The 10 most common weakness classes, ranked by how often they land on CISA's KEV list. OS command injection leads. XSS, the most common bug, is near the bottom. The highest-severity class (stack overflow, CVSS 8.5) is only 4th.

Severity is potential. Exploitation is what happens.
```

## Alt text
```
Horizontal bar chart of the KEV (CISA Known Exploited Vulnerabilities) rate for the 10 most common CWEs, sorted from most exploited at the top to least at the bottom. OS command injection leads at 1.30%, then input validation 1.00% and path traversal 0.69%; XSS, missing authorization and CSRF are at the bottom near 0.02 to 0.05%. Each row also shows its median CVSS on the right, and those medians are out of order relative to the exploitation ranking, showing severity does not predict exploitation. Source: CVE List V5 plus CISA KEV.
```

## Notes / caveats
- KEV rate is relative and small (the KEV catalog is ~1,635 CVEs total); read the
  bars as a comparison across classes, not absolute exploitation probability.
- Denominator is all CVEs of the class; numerator is those on KEV (all-time,
  cumulative). Older/large classes have had more time to accrue KEV entries.
- Correlation of median CVSS with KEV rate is ~0.6: related, not the same. Do not
  say "no relationship"; the honest claim is severity loosely tracks but does not
  predict exploitation.
- Same 10 classes as `cwe_spread` (top by CVSS-v3 volume); primary/first CWE per CVE.
- SCOPE: these 10 classes are only ~10% of KEV, and 64% of KEV CVEs have no CWE at
  all. This chart is exploitation RATE within the common classes, NOT where
  exploitation concentrates. For that, see the companion `exploited_cwe`.
- Not yet through a pre-post persona review. Numbers computed directly and verified.
```

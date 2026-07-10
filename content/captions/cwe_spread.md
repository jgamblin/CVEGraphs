# Caption — Range chart: top 10 CWEs, CVSS 80% range and median (`cwe_spread`)

Image: `graphs/cwe_spread_<ratio>_<date>.png`. House style: no em dashes.
Companion to `cna_spread`. IMPORTANT: this chart is SINGLE-SOURCE (the CNA's own
v3 vector, one per CVE), so it shows severity variation across CVEs within a
class. It does NOT measure scorer disagreement. Keep all scorer-disagreement
language in `cna_spread`, never here. Data: CVE List V5, CVSS v3, the 10 most
common CWEs by volume.

Finding: medians run from 5.3 (missing authz, info exposure) to 8.5 (stack overflow).
Memory-corruption and injection classes score highest (stack buffer overflow 8.5,
OS command injection 7.8, SQL injection 7.3), with path traversal and input
validation close behind at 7.2. Higher-volume web and access-control classes sit in
the middle and below (XSS 6.4, CSRF 5.4, info exposure 5.3, missing authz 5.3). But
the category does not decide severity: out-of-bounds read, also a memory bug, sits
low at 5.5. Within every class the middle 80% is wide: about 3 points even for the
tightest (stack overflow, SQLi) up to ~4.5 for the widest of these ten (OOB read
3.3-7.8, path traversal 4.6-9.0, input validation 4.4-8.8). XSS is the most common
class by far (~20K CVEs) and spans 3.5-7.1. These are the CNA's own v3 scores, one
per CVE, so band width is severity variation across CVEs, not scorer disagreement.

## LinkedIn / Mastodon
Attach: `cwe_spread_wide_<date>.png`.
```
A CWE is a genre, not a grade.

Here are the 10 most common weakness types and the CVSS scores they actually get. Memory corruption and injection score highest: stack buffer overflows run a median 8.5, OS command injection 7.8, SQL injection 7.3. The classes that dominate the CVE feed by sheer volume sit lower: cross-site scripting 6.4, CSRF 5.4, information exposure and missing authorization both 5.3. And the category is not destiny. Out-of-bounds read, also a memory bug, sits down at 5.5.

Two things worth sitting with. First, the class barely narrows the range: even within one weakness type the middle 80% of scores spans three to four and a half points, so knowing a bug is "an XSS" or "a path traversal" tells you surprisingly little about its severity. Second, that flatness holds even for the class you see most: XSS runs from 3.5 to 7.1 across its CVEs, low to high. The label does not predict the score.

So a "critical CWE" is not really a thing. The class shifts the odds, but severity lives in the specific bug.

Which weakness class do you think your program over-weights, and which does it wave through?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
A CWE is a genre, not a grade.

The 10 most common CWEs and the CVSS scores they actually get: memory corruption and injection highest (stack overflow median 8.5, OS command injection 7.8), high-volume web classes lower (XSS 6.4, CSRF 5.4). Out-of-bounds read, also a memory bug, lands at 5.5.

Even within one class the middle 80% spans 3 to 4.5 points. The label does not predict the score.
```

## Alt text
```
Range chart of CVSS v3 base scores for the 10 most common CWEs, one row each, sorted by median from Stack overflow at the top (median 8.5) down to Missing authorization at the bottom (5.3). Each row has a bar showing where the middle 80% of that weakness class's scores fall, colored by severity from light grey for low up to deep navy for high, with a tick at the median. Memory-corruption and injection classes score highest, though out-of-bounds read (also a memory bug) sits low at 5.5. Even within one class the middle 80% spans three to four and a half points. Source: CVE List V5.
```

## Notes / caveats
- SINGLE-SOURCE: cvss_v3 is the CNA's own vector, one per CVE. Band width = real
  severity variation across CVEs within a class. It does NOT measure scorer
  disagreement (that is `cna_spread`, which varies the scorer). Never import
  scorer-disagreement or "same bug, two sources" language into this post.
- XSS is NOT the widest band (3.6, mid-pack, 6th of 10). Widest are out-of-bounds
  read 4.5, path traversal 4.4, input validation 4.4. Band widths run 3.0 (stack
  overflow, SQLi) to 4.5. Do NOT claim "XSS is widest" or "most disagreed on."
- Use "memory corruption," not "memory-safety": out-of-bounds read is a memory-safety
  bug but sits low (5.5), so "memory-safety scores highest" is false. Name the
  specific high classes (stack overflow, OS cmd, SQLi) instead of the category.
- Top 10 is a volume cutoff; excluded CWE-284 (n=1999) also has band 4.5, so scope
  "widest" to "these ten."
- Tick is the median (pooled distribution is right-skewed; median is the honest center).
- First CWE only per CVE (4% of CVEs have >1 CWE). Names shortened for the axis.
```

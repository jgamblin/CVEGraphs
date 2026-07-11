# Caption — Bubble strip: CVSS spread of exploited (KEV) CVEs, by weakness class (`kev_severity`)

Image: `graphs/kev_severity_<ratio>_<date>.png`. House style: no em dashes.
Answers a question from Sasha Romanosky (CVSS co-author) on the `exploited_cwe` post:
"what are the average CVSS scores of those most exploited (memory corruption and
code execution)?" Companion to `exploited_cwe` (which classes carry the most KEV).

Finding (verified from CISA KEV cwes joined to CVSS v3, KEV dateReleased 2026-07-07):
exploited bugs cluster high, but how high depends on the class. Per-class medians run
from 7.8 (out-of-bounds write) up to a wall of 9.8 for the code-execution classes
(code injection, OS command injection, deserialization) and the auth classes (improper
auth, missing auth). The memory-corruption classes (use-after-free, memory buffer error,
type confusion) sit a notch lower around 8.8. Grouped: memory corruption mean 8.4 /
median 8.8 (n=373); code execution + injection mean 9.0 / median 9.8 (n=293). All KEV
with a v3 score: mean 8.4 / median 8.8. The 12 shown classes cover ~850 of 1,635 KEV.

## LinkedIn / Mastodon
Attach: `kev_severity_wide_<date>.png`.
```
Someone asked a sharp question on my exploited-bugs post: fine, attackers reach for memory corruption and code execution, but how severe are those bugs actually scored?

So I plotted every CVE on CISA's Known Exploited Vulnerabilities list at its CVSS v3 score, split by weakness class. Each bubble is a score, sized by how many CVEs land there, with the class median marked in red.

Two things stand out.

Exploited bugs really do cluster high. Across the whole KEV list the median is 8.8, and almost nothing sits in the medium range. If you are looking for a floor, "it got exploited" and "it scored high" mostly travel together here.

But the ceiling is where the classes separate. Code execution rides it: code injection, OS command injection, and deserialization all carry a median of 9.8, with most of their mass piled at the very top. Memory corruption lands about a point lower: use-after-free, memory buffer errors, and type confusion cluster around 8.8, and out-of-bounds write sits lowest of the group at a median of 7.8. Grouped up, code execution averages about 9.0 and memory corruption about 8.4.

One honest caveat, because a CVSS co-author was asking. These scores blend NVD and CNA scorers, and the 9.8 pile in the remote-code classes partly reflects NVD's habit of scoring remote code execution at 9.8. Some of that gap is the scorer, not the bug.

The takeaway is not "CVSS works." KEV is what already got caught, so conditioning on it and then reading the scores is not a test of whether severity predicts exploitation. It is a description of where the exploited bugs happen to sit, and they sit high, with code execution highest.

If you triaged only by score, which of these classes would you still miss?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
Someone asked: how severe are the bugs that actually get exploited?

Every CVE on CISA's KEV list, by CVSS v3 and weakness class. Median across the whole list is 8.8.

Code execution rides the ceiling (median 9.8). Memory corruption sits a notch lower (median 8.8). Almost nothing is "medium."
```

## Alt text
```
A bubble strip chart of every CISA KEV (exploited) CVE's CVSS v3 base score, one row
per weakness class, for the 12 classes with 30 or more exploited CVEs. Each bubble is a
distinct score, sized by the number of CVEs there and colored by severity band (navy
Critical, blue High, grey Medium); a red diamond and a right-hand column mark each
class median. Rows are sorted by median, low at the bottom. Out-of-bounds write has the
lowest median at 7.8; use-after-free, memory buffer error, and type confusion sit at
8.8; code injection, OS command injection, deserialization, improper auth, and missing
auth all reach a median of 9.8. Most mass is High or Critical, with a thin tail into the
mediums. Four CVEs score below 4 (min 2.7) and are not shown. Source: CISA KEV + NVD/CVE List.
```

## Notes / caveats
- Source is CISA's KEV `cwes` field joined to CVSS v3 (NVD first, else CVE List). Same
  CWE source as `exploited_cwe`, so the two charts are internally consistent.
- Row order is by MEDIAN (not mean): for ceiling-piled data the mean is distorted by the
  left tail, and a mean sort inverted the median story (an earlier draft placed
  out-of-bounds write above path traversal despite a lower median). The red diamond +
  right-hand "Median" column make the ordering verifiable on-chart.
- Bubble size within a row is a true CVE count (each CVE appears once per class). Do NOT
  sum row counts as a CVE total: a CVE can carry >1 CWE, so the 12 rows sum to ~850
  (cve,cwe) pairs, and the subtitle is scoped to "the 12 most-exploited classes," not
  "every KEV CVE."
- Scorer confound (see memory note): scores blend NVD and CNA scorers; the 9.8 pile in
  the RCE classes partly reflects NVD scoring convention. Footnoted on-chart and owned in
  the LinkedIn copy because the asker is a CVSS co-author.
- Framing guardrail: this is severity CONDITIONAL on exploitation, not evidence that
  CVSS predicts exploitation. Keep it consistent with `exploited_cwe` / `cwe_kev`.
- Stamped with the KEV catalog release date (2026-07-07), not the data-refresh date.
```

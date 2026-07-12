# Caption: CVSS dot-plot of Foxit PDF Editor's July 8 CVE batch (`foxit_batch`)

Image: `graphs/foxit_batch_<ratio>_<date>.png`. House style: no em dashes.
Sunday curio, ties to the `exploited_cwe` post. One-off (product/date hardcoded).
Data: CVE List V5, Foxit-assigned CVEs for Foxit PDF Editor on 2026-07-08.

Finding (verified): 28 CVEs, all published 2026-07-08, all Foxit-assigned, all for
Foxit PDF Editor. CWE breakdown: 15 use-after-free (CWE-416), 6 out-of-bounds read
(CWE-125), plus type confusion, out-of-bounds write, invalid pointer release, array
index, buffer copy (1 each) = 26 memory-safety of 28. The other two: 1 XXE (CWE-611)
and 1 with no CWE. CVSS v3 range 6.1-8.2, median 7.8; notably 20 of the 28 carry the
identical score 7.8 (the tower in the dot-plot). The use-after-free bulk sits near the
top of what actually gets exploited (see `exploited_cwe`); the out-of-bounds reads do
not. This was a routine scheduled release (Foxit PDF Editor 2026.1.2); batch disclosure
at a version bump is their normal cadence, so 28 is the largest batch so far, not an anomaly.

## LinkedIn / Mastodon
Attach: `foxit_batch_wide_<date>.png`.
```
Foxit shipped its routine 2026.1.2 update this week, and it fixed 28 CVEs in PDF Editor. 26 are memory-safety bugs, 15 of them use-after-free, and 20 land on the exact same CVSS score, 7.8.

This is not a knock on Foxit. Batch fixes at a version bump are their normal cadence, and any large program that parses untrusted files produces this bug shape. The interesting part is the mix: nearly all memory corruption, the class that actually gets exploited, sitting at a 7.8 that clears a critical-only filter but not a High SLA.

Would you triage a use-after-free in a file parser differently from the same CVSS somewhere else?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
This week I posted that attackers exploit memory corruption and injection far more than the common web bugs like XSS.

A vivid example from this week's CVE disclosures: Foxit disclosed 28 CVEs for its PDF Editor in one release. 26 of 28 are memory-safety bugs. 15 are use-after-free.

All patched. But memory-safety in a file parser is the exact bug class attackers reach for.
```

## Alt text
```
A dot plot of the 28 CVEs Foxit disclosed for PDF Editor on July 8, 2026, each dot
placed at its CVSS v3 base score and colored by weakness family. A tall column of 20
dots sits at score 7.8 (15 use-after-free at the base and 5 other memory-safety above),
a shorter column of 6 at score 6.1, and single dots at 6.5 and 8.2. Twenty-six of the
28 are memory-safety bugs, and 20 share the identical score 7.8. Source: CVE List V5.
```

## Notes / caveats
- Verified: 28 CVEs, all 2026-07-08, all Foxit-assigned, all Foxit PDF Editor; 26
  memory-safety, 15 use-after-free; median CVSS 7.8. The two non-memory: 1 XXE, 1 no CWE.
- Framing: NOT "picking on Foxit." 2026-07-08 was a routine scheduled release (Foxit PDF
  Editor 2026.1.2 / 14.0.5 / 13.2.5); batch disclosure at a version bump is their normal
  cadence (15 CVEs on their first CNA day, 2025-12-19), and memory-unsafe file parsers
  produce this bug shape by nature. Copy must NOT imply 28-in-a-day is anomalous. The
  point is the class mix. Overlap-with-exploitation is scoped to the use-after-free bulk
  (`exploited_cwe`); the 6 out-of-bounds reads are NOT among the top exploited classes.
- Scope note: Foxit became a CNA only 2025-12-19, so its self-assigned history is ~7
  months; press reported 30+ fixes across Reader AND Editor, but CVE List tags all 28 as
  Foxit PDF Editor, so "28 for PDF Editor" is accurate to the data we hold.
- One-off: product and date are constants at the top of `foxit_batch.py`. Stamped with
  the disclosure date (2026-07-08), not the data-refresh date.
- Memory-safety CWE set is listed in the module (MEM). "Everything else" = XXE + no-CWE.

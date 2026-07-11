# Caption — Waffle: Foxit PDF Editor's 28-CVE single-day batch (`foxit_batch`)

Image: `graphs/foxit_batch_<ratio>_<date>.png`. House style: no em dashes.
Sunday curio, ties to the `exploited_cwe` post. One-off (product/date hardcoded).
Data: CVE List V5, Foxit-assigned CVEs for Foxit PDF Editor on 2026-07-08.

Finding (verified): 28 CVEs, all published 2026-07-08, all Foxit-assigned, all for
Foxit PDF Editor. CWE breakdown: 15 use-after-free (CWE-416), 6 out-of-bounds read
(CWE-125), plus type confusion, out-of-bounds write, invalid pointer release, array
index, buffer copy (1 each) = 26 memory-safety of 28. The other two: 1 XXE (CWE-611)
and 1 with no CWE. CVSS v3 range 6.1-8.2, median 7.8. These are the memory-corruption
classes that dominate real-world exploitation (see `exploited_cwe`).

## LinkedIn / Mastodon
Attach: `foxit_batch_wide_<date>.png`.
```
Earlier this week I posted that the bugs attackers actually exploit skew hard to memory corruption and injection, with use-after-free near the top, not the common web bugs like XSS and CSRF. Here is a vivid example from the same week's CVE feed.

Foxit disclosed 28 CVEs in its PDF Editor in a single day. 26 of the 28 are memory-safety bugs. Fifteen are use-after-free. The other memory-safety ones are out-of-bounds reads (and one write), a type confusion, and a few odds and ends. Two of the 28 are not memory bugs at all: an XML-parsing flaw and one with no assigned class. Basically the shelf attackers shop from, restocked in one release.

To be clear, this is not a Foxit problem, and to their credit they found these, fixed them, and disclosed them, which is exactly what you want a vendor to do. Any large C or C++ program that parses untrusted files produces this shape of bug, and a PDF is untrusted input by definition. It is why document parsers have been an exploitation workhorse for two decades, and why the whole industry keeps pushing memory safety and sandboxing.

The interesting part is the mix. These score a median 7.8, they belong to the classes that show up most in real-world exploitation, and there are 28 in one product on one day. A queue sorted only by "critical" labels or KEV listings can walk right past a batch like this.

Would you triage a use-after-free in a file parser differently from the same CVSS somewhere else?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
This week I posted that attackers exploit memory corruption and injection far more than the common web bugs like XSS.

A vivid example from the same feed: Foxit disclosed 28 CVEs for its PDF Editor in a single day. 26 of 28 are memory-safety bugs. 15 are use-after-free.

The shelf attackers shop from, restocked in one release.
```

## Alt text
```
A grid of 28 tiles, one per CVE, for the 28 vulnerabilities Foxit disclosed in Foxit
PDF Editor on July 8, 2026. Fifteen dark tiles are use-after-free, eleven medium tiles
are other memory-safety bugs (out-of-bounds reads and writes, type confusion, and
similar), and two light tiles are everything else. Twenty-six of the twenty-eight are
memory-safety bugs. Source: CVE List V5.
```

## Notes / caveats
- Verified: 28 CVEs, all 2026-07-08, all Foxit-assigned, all Foxit PDF Editor; 26
  memory-safety, 15 use-after-free; median CVSS 7.8. The two non-memory: 1 XXE, 1 no CWE.
- Framing: NOT "picking on Foxit." Batch disclosure is normal, and memory-unsafe file
  parsers produce this bug shape by nature. The point is the class mix, and its overlap
  with what actually gets exploited (`exploited_cwe`).
- One-off: product and date are constants at the top of `foxit_batch.py`. Stamped with
  the disclosure date (2026-07-08), not the data-refresh date.
- Memory-safety CWE set is listed in the module (MEM). "Everything else" = XXE + no-CWE.

# Caption — Range chart: one weakness class, how CNAs disagree on CVSS (`cna_spread`)

Image: `graphs/cna_spread_<ratio>_<date>.png`. House style: no em dashes.
Third beat after the corrected `ridgeline_severity` and `scorer_divergence`
posts. Data: CVE List V5, CVSS v3 (broadest cross-CNA coverage), CWE-79 (XSS)
by default; the chart is CWE-swappable via the `cwe` arg / `CWE` constant.

Finding: for XSS scored with v3, the 13 CNAs with >= 100 CVEs each average from
3.4 (VulDB) to 6.7 (Microsoft), but the range is mostly VulDB alone at the bottom;
the other 12 cluster 5.5 to 6.7. Biggest driver of VulDB's floor is NOT Scope, it is
Confidentiality impact: VulDB scores C:None on ~100% of its XSS vs C:Low+ on ~98% for
the field, worth ~1.4 points (the largest single lever, from a field-typical 6.1).
Scope (VulDB 0% Changed vs field 88%) and Privileges are each worth ~0.7. VulDB-typical
XSS = 3.5, field-typical = 6.1. No single dial orders the other 12 (Scope:Changed rate
vs mean correlates r=-0.59). `scorer_divergence` (same CVE, same scorer) is the proof.

## LinkedIn / Mastodon
Attach: `cna_spread_wide_<date>.png`.
```
A CVSS score is not a fact about a bug. It is an opinion with a decimal point.

Cross-site scripting is the most common bug on the internet. Here it is scored by 13 different organizations: the same weakness averages about a 3.4 at VulDB and about a 6.7 at Microsoft. Same bug class, same scoring system, more than a full severity band apart.

Most of that spread is really one organization. VulDB sits alone at the bottom while the other twelve cluster between 5.5 and 6.7. So the real question is why VulDB reads the same bugs so much lower.

The biggest reason is not the metric people argue about. It is whether an XSS leaks data at all. VulDB scores confidentiality impact as None on essentially every XSS, treating it as a bug that can alter a page but not read anything. Almost everyone else scores it Low: an XSS can read the page, lift a session token, scrape what the victim can see. That single call is worth about 1.4 points, the largest lever in the whole vector.

VulDB then stacks two more conservative calls on top: it marks XSS as not crossing a trust boundary (Scope:Unchanged) where most others mark it Changed, and it usually requires the attacker to already have some privilege. Each is worth about half as much as the confidentiality call. That is the twist: Scope is the metric the community argues about most for XSS, yet the quieter confidentiality call moves the score twice as far.

None of these orgs is being sloppy. They are applying the same defined metrics to a genuinely ambiguous bug and landing in different places, and no single dial orders them. The number just depends on who holds the pen.

When a CVE carries two different CVSS scores, which one does your program actually use?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
A CVSS score is not a fact about a bug. It is an opinion with a decimal point.

13 orgs scored XSS: averages run 3.4 to 6.7, mostly because VulDB sits alone at the bottom. The biggest reason is not the metric people argue about (Scope), it is whether an XSS leaks data at all. That one call is worth ~1.4 points, double Scope.
```

## Alt text
```
Range chart of CVSS v3 base scores for cross-site scripting (CWE-79), one row per scoring CNA, for the 13 CNAs with at least 100 XSS CVEs. Each row has a bar showing where the middle 80% of that CNA's scores fall, colored by severity from light grey for low scores up to deep navy for high, with a bold tick at the average. VulDB sits alone at the bottom with an average of 3.4; the other twelve CNAs cluster between 5.5 and 6.7, up to Microsoft at 6.7. The same weakness gets very different scores depending on who rates it. Source: CVE List V5.
```

## Notes / caveats
- v3, not v4: v3 has the broadest per-CNA coverage. v4 per-CNA volume is still thin.
- The spread is mostly VulDB, not a gradient. VulDB averages 3.4; the other 12 cluster
  5.5-6.7. Across those 12, Scope:Changed rate correlates NEGATIVELY with the average
  (r=-0.59, vs +0.38 across all 13), so no single metric orders the field. Do NOT claim
  "most of the gap is Scope."
- Per-metric decomposition (CVSS v3.1, from a field-typical XSS = 6.1, flipping one
  metric to VulDB's value):
    - Confidentiality None (vs Low): **-1.4** <- largest lever
    - Scope Unchanged (vs Changed): -0.7
    - Privileges Low (vs None): -0.7
  VulDB-typical vector (AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:N) = 3.5.
- Vector distributions (verified): VulDB C:None 100%, S:U 100%, UI:R 100%, PR-required
  86%. Field: C:Low+ ~98%, S:C 88%, PR-required ~68%. So VulDB models XSS as a
  self-contained integrity-only bug; the field models it as leaking data and crossing
  a boundary. Both are defensible readings; FIRST's own v3.1 examples score XSS as
  Scope:Changed with confidentiality impact.
- Other conventions: adobe's XSS are 90% PR:L (authenticated); Wordfence marks 80% UI:None.
- Small samples: Microsoft n=113, sap n=109; treat 6.7 as an indicative endpoint (within
  noise of @huntrdev 6.60 and INCIBE 6.57), not a precise leader.
- Framing: do NOT imply any CNA is "wrong." Honest claim: defined metrics, applied
  inconsistently to an ambiguous bug, so a base score reflects who scored it.
- Bars colored by severity (light grey low -> deep navy high); VulDB the pale low outlier.
```

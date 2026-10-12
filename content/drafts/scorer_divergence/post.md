# Caption — Dumbbell: who scores a CVE moves it more than which version (`scorer_divergence`)

Image: `graphs/scorer_divergence_<ratio>_<date>.png`. House style: no em dashes.
Companion to the corrected `ridgeline_severity` post. Data: CVE List V5, same CNA
scoring the same CVE with both v3 and v4 (its own vectors, authoritative).

Finding: for the same weakness class, the two highest-volume dual-scorers (VulDB,
VulnCheck) assign v4-vs-v3 shifts that disagree, sometimes on direction. XSS
(CWE-79): VulDB +1.78 vs VulnCheck -0.86. SQLi (CWE-89): VulDB -0.60 vs VulnCheck
+0.43. A few classes agree (buffer overflow down, SSRF down, info-leak up, path
traversal up). The per-CWE v4/v3 gap is a property of the scorer, not the version.
Two scorers only (VulDB + VulnCheck have the volume); state that plainly.

## LinkedIn / Mastodon
```
Here is the CVSS finding that surprised me most this week: which score a bug gets depends more on who rates it than on which version of CVSS they use.

Take the exact same weakness classes, and look at how two of the busiest scoring organizations move a bug from CVSS v3 to v4. They do not just differ in size. They differ in direction.

Cross-site scripting: one scorer rates v4 almost two points higher than v3. The other rates it nearly a point lower. Same weakness, opposite call. SQL injection flips too. On a handful of classes they agree (buffer overflows drift down, information leaks drift up), but the headliners split.

This is the thing to sit with. CVSS feels like a ruler. It is really a lot of rulers, held by a lot of different hands, and the reading depends on the hand. When you compare severity across years, across vendors, or across data feeds, you are partly comparing scorers, not severity.

Which is why severity alone was never a great way to rank your queue. Exploitation is. But if you do lean on CVSS, know whose CVSS you are leaning on.

When a CVE has two different CVSS scores, which one does your program actually use?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
The CVSS thing that surprised me most: a bug's score depends more on WHO rates it than which version they use.

Same weakness classes, two big scorers, v3 to v4: XSS goes +1.8 for one and -0.9 for the other. SQLi flips too.

CVSS isn't one ruler. It's many, held by different hands.
```

## Alt text
```
Dumbbell chart of CVSS v4 minus v3 by weakness class (CWE), for the same CVEs scored
by the same organization with both versions. Two scorers are plotted per class, VulDB
and VulnCheck. For XSS and SQL injection the two dots sit on opposite sides of zero,
meaning the scorers disagree on whether v4 is higher or lower than v3. Source: CVE List V5.
```

## Notes / caveats
- Only VulDB and VulnCheck have enough same-CNA dual-scored CVEs to be stable, so this
  is two scorers, not the whole ecosystem. Do not overclaim "all CNAs."
- Uses CVE List V5 CNA vectors (authoritative), not the NVD feed (whose v4 was low).
- Pairs with the corrected ridgeline: v3 and v4 score about the same overall; this
  chart shows the variance hides inside who does the scoring.
```

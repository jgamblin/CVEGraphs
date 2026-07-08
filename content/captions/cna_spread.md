# Caption — Range chart: one weakness class, how CNAs disagree on CVSS (`cna_spread`)

Image: `graphs/cna_spread_<ratio>_<date>.png`. House style: no em dashes.
Third beat after the corrected `ridgeline_severity` and `scorer_divergence`
posts. Data: CVE List V5, CVSS v3 (broadest cross-CNA coverage), CWE-79 (XSS)
by default; the chart is CWE-swappable via the `cwe` arg / `CWE` constant.

Finding: for XSS scored with v3, the 13 CNAs with >= 100 CVEs each average from
3.4 (VulDB) to 6.7 (Microsoft). The spread is mostly ONE contested metric, Scope:
VulDB marks XSS Scope:Changed 0% of the time, most others 90-100% (Microsoft 49%,
GitHub 63%), and that one call is worth ~1.5-2 points. Secondary drivers are real
population differences (adobe's XSS are 91% PR:L / authenticated, which genuinely
rates lower) and other metric conventions (Wordfence marks 82% UI:None). All are
defensible CVSS readings, not errors. This chart illustrates the effect; the
`scorer_divergence` chart is the rigorous same-CVE proof.

## LinkedIn / Mastodon
Attach: `cna_spread_wide_<date>.png`.
```
Here is one weakness, cross-site scripting, the most common bug on the internet. And here is the same weakness scored by 13 different organizations. The typical XSS gets rated about a 3.4 by VulDB and close to a 6.7 by Microsoft. Same class of bug, same scoring system, more than a full severity band apart.

So I dug into why, and most of the gap comes down to a single contested call in the CVSS math: is an XSS "Scope: Changed"?

The case for yes: the injected script runs in the victim's browser, a different component than the vulnerable server, so the impact crosses a boundary. The case for no: it is all still the one web app. The spec leaves room for both, and the scorers split hard. One organization marks XSS Scope:Changed almost never. Most of the others mark it Scope:Changed almost always. That single metric is worth roughly two points, and it is most of the gap.

The rest is real difference in the bugs themselves. Some scorers mostly catalog authenticated XSS, which genuinely rates lower.

None of this is anyone being wrong. It is careful people resolving the same ambiguity in defensible but different ways. Which is exactly the problem. A CVSS base score is not a fact about a bug, it is an opinion with a decimal point, and the opinion depends on who holds the pen.

So comparing scores across sources quietly compares scorers, and severity alone stays a weak way to rank your work. Exploitation evidence travels better.

When a CVE carries two different CVSS scores, which one does your program actually use?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
Why do CVSS scores for the same bug vary so much? Take XSS: 13 orgs score it, averages run 3.4 to 6.7.

Most of the gap is one contested call: is XSS "Scope: Changed"? One org says never, most of the rest say almost always. That metric alone is worth ~2 points.

A CVSS score is an opinion with a decimal point.
```

## Alt text
```
Range chart of CVSS v3 base scores for cross-site scripting (CWE-79), one row per scoring CNA, for the 13 CNAs with at least 100 XSS CVEs. Each row has a bar showing where the middle 80% of that CNA's scores fall, colored by severity from light grey for low scores up to deep navy for high, with a bold tick at the average. Average scores climb from VulDB at the bottom (3.4, a pale low-scoring outlier) up to Microsoft at 6.7, so the same weakness gets very different scores depending on who rates it. Source: CVE List V5.
```

## Notes / caveats
- v3, not v4: v3 has the broadest per-CNA coverage. v4 per-CNA volume is still thin.
- Not unique to XSS: most high-volume classes show a similar cross-CNA spread. The
  chart is CWE-swappable (`render(cwe="CWE-89")`) if you want to show SQLi etc.
- **Precise mechanism (verified from vectors):** the gap is mostly the Scope metric.
  VulDB marks XSS Scope:Changed 0% of the time; most others 90-100% (Microsoft 49%,
  GitHub 63%). In CVSS v3 that is worth ~1.5-2 points and explains VulDB's floor.
  Secondary: adobe's XSS are 91% authenticated (PR:L), genuinely lower; Wordfence
  marks 82% UI:None. All defensible readings of an ambiguous spec, not errors.
- Framing: do NOT imply any CNA is "wrong." The honest claim is that scorers resolve
  the same spec ambiguities (Scope above all) differently, so a base score reflects
  who scored it. This is the illustrative chart; `scorer_divergence` (same CVE,
  same scorer) is the rigorous proof.
- Bars are colored by CVSS severity (light grey low -> deep navy high), so VulDB reads
  as the pale low outlier. Small-sample rows (Microsoft 113, sap 109) are shown as-is.
```

# Caption — CWE anatomy (hierarchical circle pack) (`cwe_circles`)

Image: `graphs/cwe_circles_<ratio>_<date>.png`. House style: no em dashes.
Grouping is authoritative: MITRE CWE-1000 pillars (from cwe.mitre.org), not
hand-curated. Size = 2026 CVE count, color = average CVSS. Paragraphs are single
lines for clean LinkedIn paste.

## LinkedIn / Mastodon
```
Here is the 2026 CVE landscape, organized the way MITRE actually organizes it.

Every CWE (weakness type) rolls up to one of MITRE's 10 top-level pillars. This maps the top 22 weaknesses of 2026 into those pillars: circle size is how common the weakness is, color is how severe it tends to be on average (darker = higher CVSS).

Two pillars dominate, almost tied. Improper Neutralization (injection) is one giant pale circle, XSS, surrounded by the darker, higher-severity injection bugs: SQLi, code injection, OS command injection. Improper Resource Control is just as big: use-after-free and other memory-safety bugs, path traversal, SSRF, deserialization. Improper Access Control is the third: missing and broken authorization.

The reframe is right there in the shading. The single most common weakness, XSS, is one of the milder ones (pale). The dangerous ones are the small dark circles: injection, deserialization, command execution. Common and severe are not the same axis.

The grouping is straight from MITRE's CWE-1000 research view, not buckets I made up.

Which pillar surprised you most?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
The 2026 CVE landscape, mapped onto MITRE's own CWE pillars.

Size = how common. Color = severity. Two pillars dominate: Improper Neutralization (injection, incl XSS) and Improper Resource Control (memory safety, path traversal, SSRF).

The catch: the most common bug, XSS, is one of the mildest. Common and severe are different axes.
```

## Alt text
```
Hierarchical circle-packing chart of the top 22 CWEs in 2026, grouped into MITRE's CWE-1000 pillars. Large outlined circles are the pillars (Improper Neutralization, Improper Resource Control, Improper Access Control, plus small pillars for CSRF and NULL-pointer dereference). Inside each, individual CWEs are circles sized by CVE count and shaded by average CVSS on a light-to-navy scale. XSS is the largest circle but pale (moderate severity); injection and deserialization circles are smaller but dark navy (severe). Sources: NVD, cwe.mitre.org.
```

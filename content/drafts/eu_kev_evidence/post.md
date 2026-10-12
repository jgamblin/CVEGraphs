# Caption: Graded table, EU KEV entries that differ from CISA KEV (`eu_kev_evidence`)

Image: `graphs/eu_kev_evidence_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Exploitation lane (Thursday). Built
2026-09-23 at Jerry's request ("a chart of sources and evidence"). Companion to
`eu_kev_overlay`; this is the lead chart, the overlay can go in the first comment.

**Attach the PORTRAIT.** Twelve CVE rows with evidence text are the payload.

**Grades are hand research, stored in `GRADES` in `charts/eu_kev_evidence.py`.** `render()`
raises if the live EU-only set stops matching them, so re-grade after any refresh that
changes the 12. The EU-first group and its CISA-ADP SSVC values are computed live from
`data/cvelistV5`. Evidence per CVE and the sources checked are in the provenance audit in
`content/drafts/eu_kev_overlay/post.md`.

## Numbers (2026-09-23 pull)
- EUVD 1,733; CISA KEV 1,721; all 1,721 on both.
- EU first: 9, all 9 with CISA-ADP SSVC `Exploitation: active`; CISA added them 1 to 69
  days after the EU date.
- EU only: 12. Supported 3 (FortiWeb, two Zbtlink), Partial 1 (MikroTik), None found 5,
  Contradicted 3 (two GeoNetwork, Microsoft Entra).

## Caveats (keep them next to the claim)
- "None found" means none in the record, its references, and the pages they cite. ENISA
  may have a source it doesn't publish. Never write "wrong" for that group.
- The Zbtlink "Supported" is live implant beaconing, not documented attacks. The row says so.
- "CISA's own rating came first" is a match on the record, not proof ENISA reads it. The
  SSVC timestamp history isn't in the shallow clone.
- KEV rule: "on the EU list", "added to KEV"; the EU's field name is "exploited".

## Post copy
> Treat the EU's exploited list as CISA KEV plus a short list of leads you still have to check.
>
> ENISA's EUVD lists 1,733 CVEs as exploited, and all 1,721 on CISA's KEV catalog are among them. The records don't say where any "exploited" flag came from, so I checked the 21 places the lists disagree. The nine the EU listed first all carried CISA's own "Exploitation: active" rating in the CVE record before CISA got them onto KEV.
>
> That leaves 12 CVEs only the EU has. Three have a vendor or researcher behind them, and FortiWeb is the clearest: Fortinet marked it exploited, and CISA added only its sibling. For five I found nothing. Three are contradicted, including two GeoNetwork CVEs the EU dated a day before they were published.

## First comment
> How I graded them: EUVD references and linked advisories, the CVE record, and the vendor,
> CERT and researcher pages those cite, checked Sep 23 2026. "None found" means I found
> nothing, not that ENISA had nothing. Credit to VulnCheck, whose 2025 look at EUVD
> found 4 unique entries in 1,632. The overlay of both lists is in the image below.

## Status
Built, tells linter passed, `/post-review` not run, not posted.

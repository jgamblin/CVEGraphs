# Caption: Step lines, EU KEV overlaid on CISA KEV (`eu_kev_overlay`)

Image: `graphs/eu_kev_overlay_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Exploitation lane (Thursday). Built
2026-09-23 at Jerry's request ("overlay EU KEV and CISA KEV").

**Attach the SQUARE or PORTRAIT to LinkedIn.** The wide works for X.

**Data pulled 2026-09-23:** ENISA EUVD `api/search?exploited=true` (1,733 rows, newest
exploitedSince Sep 22) and CISA KEV (1,721 entries, released Sep 22 19:02 UTC). New
fetch `refresh_data.fetch_euvd_exploited()` writes `processed/euvd_kev.json` and now runs
inside `fetch_feeds()`. Re-derive every number below with
`python -c "from charts.eu_kev_overlay import stats; print(stats())"`.

## The numbers
- EU list 1,733 CVEs; CISA KEV 1,721. **All 1,721 KEV CVEs are on the EU list; 0 are on
  CISA's only.** 1,721 of 1,733 = 99.3% overlap.
- **12 CVEs are EU only** (0.7%): CVE-2011-4085, CVE-2015-7501 (Red Hat, both dated
  Jul 14 2025), CVE-2025-25231 (Omnissa), CVE-2025-59719 (Fortinet), and eight 2026 CVEs
  (three GitHub, two VulnCheck, one each Joomla, CERT-PL, Microsoft).
- **Dates:** 1,712 of the 1,721 shared CVEs carry the SAME date on both lists. The other
  9 were listed by the EU **first**, 1 to 8 days ahead for eight of them and 69 days for
  CVE-2026-1340 (EU Jan 29, CISA Apr 8). The EU never lists a shared CVE later than CISA.
- **18 of the 21 independent signals (12 EU-only + 9 earlier) are from 2026.** That is the
  credit line: the list is starting to do its own work.
- Same-date entries go back to KEV's Nov 3 2021 bulk load, years before EUVD went live
  (May 13 2025). The EU's `exploitedSince` for these is CISA's `dateAdded`, so the chart
  left of the launch line is CISA's history as EUVD records it, not independent EU
  judgement. Say "matches", never "copies": the API does not say where each row came from.

## Provenance audit (2026-09-23): do NOT ship "the list is starting to lead"
EUVD records carry no source or evidence field for `exploitedSince`. Checked every one of
the 21 independent entries against EUVD references/advisories, the CVE record, and the
cited sources:
- **The 9 "EU first" CVEs all carry a CISA-ADP SSVC `Exploitation: active` rating in the
  CVE record** (e.g. CVE-2026-1340: SSVC active Jan 29, the EU date; KEV Apr 8). So the
  lead is most likely CISA's own ADP signal arriving before CISA's KEV entry, not an
  independent EU finding. Unproven (the local cvelistV5 is a shallow clone, so no SSVC
  history), but it fits all 9.
- **EU-only, supported:** CVE-2025-59719 (Fortinet FG-IR-25-647 says "Known Exploited: Yes"
  for 59718 and 59719 together; CISA added only 59718). Zbtlink CVE-2026-74232/74233
  (VulnCheck sinkholed 392 beaconing devices; implant use, no attacks documented).
- **EU-only, partial:** CVE-2026-67276 (CERT-PL confirms a two-CVE MikroTik chain is
  exploited, among three CVEs; CISA added the other two, 67277 and 86060).
- **EU-only, no evidence found:** CVE-2011-4085 and CVE-2015-7501 (Jul 14 2025 batch, refs
  are 2011-2015 Red Hat errata), CVE-2025-25231 (Omnissa), CVE-2026-41679 (Paperclip, SSVC
  poc), CVE-2026-49049 (Joomla Helix3, sole ref is joomshaper.com homepage).
- **EU-only, contradicted:** CVE-2026-58400/63219 (GeoNetwork: EU date Sep 2 precedes the
  Sep 3 CVE publication, and the only press reference, The Hacker News, says no reporting
  of exploitation). CVE-2026-69836 (Microsoft Entra: MSRC CSAF says "Exploited:No", SSVC
  none).

## Prior work, credit it
VulnCheck's "Does ENISA EUVD live up to all the hype?" (2025) found the EUVD exploited feed
99.8% sourced from CISA KEV, 4 unique of 1,632. This post is the update, not the
discovery: 12 unique of 1,733 now, and the earlier-than-CISA listings are new. Credit
VulnCheck in the first comment.

## Language
- KEV rule: "on the KEV list" / "added to KEV", never "exploited" as a blanket. The EU list
  calls its field "exploited"; quote it as the EU's label.
- Both lists are floors on exploitation, not a census.
- Do not frame ENISA as lazy. EUVD pulls from existing sources, CISA among them, by design.
  Credit then consequence: the consequence is a smaller watchlist for the reader.

## Post copy
> You don't need a second KEV feed for Europe. You need a watchlist of 12 CVEs.
>
> ENISA's EU Vulnerability Database lists 1,733 CVEs as exploited. Every one of the 1,721
> on CISA's KEV catalog is in it, and 1,712 of those carry the same date CISA added them,
> back to 2021. EUVD draws on existing sources and CISA's catalog is one of them, so if
> your team already works from KEV, it is already covering 99.3% of the EU list.
>
> The other 12 are the EU's own, and nine more CVEs showed up there 1 to 69 days before
> CISA added them. 18 of those 21 came this year. The list is starting to lead, a little.

## First comment
> Credit to VulnCheck, who measured this in 2025: 4 unique entries out of 1,632. It is 12
> of 1,733 now. Both lists are floors, not a full count of exploitation. Data: ENISA EUVD
> API (exploited=true) and CISA KEV, both pulled Sep 23 2026.

## Status
Built, not reviewed, not posted. Run `/post-review eu_kev_overlay` before it goes out.

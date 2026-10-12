# Caption for the "NVD's SSVC section is dead weight" commentary post (`nvd_ssvc_deadweight`)

**No chart.** Commentary post. House style: no em dashes. Scoring / measurement
lane. Numbers come from two sources, both reproducible:

1. **The live NVD change-history API**, pulled 2026-08-27:
   `https://services.nvd.nist.gov/rest/json/cvehistory/2.0?changeStartDate=2026-08-26T00:00:00.000&changeEndDate=2026-08-27T20:00:00.000`
   (3,189 change events). A comparison window of 2026-08-20 to 08-21
   (1,865 events) was pulled to test the before/after claim; see the trap below.
2. **The NVD mirror snapshot** `data/nvd.json` (2026-08-18, 378,750 records),
   chunk-scanned by scratchpad `scan_ssvc.py`.

## Thesis (Jerry's, and the data backs it)

A JSON field you cannot use without leaving the record is worse than no field at
all, and shipping one anyway moves the work onto everyone downstream. NVD looked
at its SSVC and affected fields, concluded the problem was bandwidth, and fixed
its own bill. The measurements below say the fields hand the consumer three jobs
in exchange: absorb re-syncs for changes that are not changes, refetch a second
system to learn what changed, and run the SSVC decision tree yourself because
only the inputs ship. That is a cost transfer, not a saving, and it is the spine
of the post. **Keep the body short.** Most of the numbers in this caption are
deliberately NOT in the copy; they are comment ammunition. The body carries two
(486 and 166) and spends the rest of its length on the argument.

## The measurement (change feed, 2026-08-26 to 08-27, 3,189 events)

**SSVC churn:**
- 2,280 of the events are "CVE Modified". **486 of those have the SSVC field as
  their only change.**
- **166 of the 486 carry no semantic change at all**: same exploitation, same
  automatable, same technical impact.
- 915 SSVC change details total: 732 "Added", 183 "Changed". **Of the 183
  "Changed" details, 171 (93.4%) have identical decision points and only the
  timestamp moved. 162 of those timestamps moved BACKWARDS.**
- Only **12** of the 183 record an actual change to a decision point.
- Typical example: **CVE-2026-16233**, timestamp
  `2026-08-25T16:50:19.199915Z` became `2026-08-25T00:00:00+00:00`. Same
  calendar day, precision discarded, decision points untouched, and every
  pipeline keying on `lastModified` re-pulled the record for it. This is the same
  date-granularity pattern that bites KEV `dateAdded` comparisons.

**Affected-history pointers:**
- **980 "Affected" change details across 848 CVEs. All 980 are a prose sentence
  with an `<a href>` HTML anchor embedded in a JSON value.** Verbatim:
  `"newValue": "Affected value modified.  <a href=\"https://github.com/CVEProject/cvelistV5/blob/main/cves/2026/10xxx/CVE-2026-10059.json\">CVE-2026-10059</a>"`
- **Zero of the 980 carry an `oldValue`.**
- **All 980 are labelled `action: "Added"`,** including the 454 whose own text
  says "Affected value modified." (526 say "New affected value received.")
- **Every link targets `/blob/main/`,** which is HEAD. Following it shows today's
  file, not the version that changed. So the entry gives you no old value, no new
  value, a wrong action label, and a link to the wrong revision.

## The corpus side (snapshot 2026-08-18, 378,750 records)

- 174,857 records carry `ssvcV203`. **174,696 (99.91%) come from the CISA ADP**
  (`134c704f-9b21-4f2e-91b3-4a467353bcc0`, role "CISA Coordinator"), already
  published in cvelistV5.
- **157,529 (90.1%) carry a decision timestamp earlier than the Jun 17 2026
  rollout.** By year: 58,862 in 2024, 66,830 in 2025, 48,629 in 2026.
- **Every one of the 174,857 ships exactly three decision points (exploitation,
  automatable, technicalImpact) and no decision outcome.** No mission and
  well-being input, no Act / Attend / Track / Track*. Re-verified live 2026-08-27.
- NVD's Jun 17 note, verbatim: *"The NVD now provides a Computed SSVC Score that
  shows how a vulnerability priority was decided."*
- 2026-published cohort (53,473 CVEs): 88.1% carry SSVC decision points, 22.2%
  carry a CVSS score authored by NVD (15.1% for CVEs published on or after
  Apr 15 2026).
- Exemplar record: **CVE-2026-20805**, Microsoft Windows Desktop Window Manager
  information disclosure, published and added to the KEV list 2026-01-13. NVD
  status "Analyzed", CISA exploitation "active", and the only CVSS on the record
  is Microsoft's own 5.5 Medium.

## Traps (each one was checked and each one killed a draft)

- **Do NOT say the Aug 26 notice introduced the pointer.** I pulled the
  2026-08-20 to 08-21 window to test it: all 691 Affected details there were
  ALREADY pointer prose with no `oldValue`, and the change-entry schema is
  byte-for-byte the same shape before and after. Neither window has a top-level
  `affected` key. The behaviour predates the announcement, so describe the
  CURRENT state of the feed and quote the Aug 26 note only for NVD's stated
  reason (bandwidth in the `/cvehistory` feed).
- **Do NOT say NVD stopped or withdrew SSVC.** The Aug 26 entry ADDS SSVC to the
  HTML detail page, and `/cves/` still returns `ssvcV203` inline as of
  2026-08-27. The GitHub forwarder covers `affected` data in Audit History only;
  verbatim, *"the current CVE detail endpoint (/cves/) unchanged; it still
  returns the latest full 'affected' JSON."*
- **Do NOT say NVD went all in on SSVC and then cried uncle.** The Apr 15 "we
  cannot keep up" note came 43 days BEFORE the May 28 SSVC announcement.
- **Do NOT blame NVD for the timestamp precision loss.** It may originate
  upstream at CISA. The defensible claim is where it lands, which is in your
  feed as a modification event.

## Caveats to carry in the copy

- **12 of the 183 SSVC changes recorded a real decision-point change.** Say so.
  The field is not inert, it is mostly inert, and that is the honest word.
- **Pointing at cvelistV5 instead of duplicating it is defensible in principle.**
  The failure is the execution: HEAD instead of the revision, no old value, an
  anchor tag inside a JSON value. Attack the execution, not the intent.
- **Nobody is forced to consume `/cvehistory`.** The `/cves/` endpoint is
  unaffected. Scope the complaint to change consumers.
- **The 22.2% NVD-authored CVSS figure is April policy working as designed**, not
  neglect, and the KEV tier is delivering: 119 of the 125 CVEs published in 2026
  that are on the KEV list are marked "Analyzed".
- **Three decision points is SSVC as designed.** Mission prevalence and public
  well-being are stakeholder inputs; CISA cannot supply them for you. The
  complaint is the word "Computed", which tells a reader a decision arrived.
- **Two-day window.** It is one weekday pair, not a longitudinal claim. Say
  "two days" in the copy and let the reader size it.
- **KEV language:** "added to the KEV list", never a blanket "exploited".

## LinkedIn / Mastodon

```
NVD would be better off deleting its SSVC section than shipping what is currently in it.

Here is the announcement, "Technical Update: NVD SSVC and 'affected' Data Delivery," August 26, in the News and Updates block: https://www.nist.gov/itl/nvd. It says the affected payload is being offloaded to GitHub links because that "significantly reduces bandwidth and payload sizes in the /cvehistory feed." So NVD has looked at these two fields and decided the problem was bytes. I think the problem is that neither field is usable when it arrives.

Look at what that costs downstream. In two days of the change feed, 486 "CVE Modified" events had the SSVC field as their only change, and 166 of those carry no change at all. Every one is a re-sync somebody paid for. To see what actually changed in the affected list you now fetch a second system, and the link points at the current file rather than the revision that changed, so you cannot rebuild the diff unless you were already keeping your own copy. And to get a priority out of SSVC, you supply the missing fourth input and run the decision tree yourself.

That is three jobs moved onto the consumer so one bandwidth bill could come down. NVD's cost pressure is real and well documented. But this is not a saving, it is a transfer, and nobody downstream was asked.

How much of your pipeline is now work that someone upstream decided not to do?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X

```
NVD says the problem with its SSVC and affected fields is bandwidth: https://www.nist.gov/itl/nvd

Two days of its change feed: 486 "CVE Modified" events whose only change is SSVC, 166 with no change at all.

That is not a saving. It is a transfer.
```
(248 of 280 characters.)

## Bluesky

```
NVD says the problem with its SSVC and affected fields is bandwidth: https://www.nist.gov/itl/nvd

Two days of its change feed: 486 "CVE Modified" events whose only change is SSVC, 166 with no change at all. No old value, and the link points at HEAD.

Not a saving. A transfer.
```
(277 of 300 graphemes.)

## The link, and where it goes

- **There is no permalink for the Aug 26 entry.** The News and Updates block on
  https://www.nist.gov/itl/nvd renders each item inline with no per-entry anchor
  (the container id is `pastNews`), and `https://nvd.nist.gov/general/news`
  301-redirects to the landing page, so the old news subsystem is retired. Cite
  it by entry title and date: *"Technical Update: NVD SSVC and 'affected' Data
  Delivery," August 26, 2026.* The Apr 15 item, by contrast, does have a real
  news-release URL:
  https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth
- **This is the first post in the franchise with a URL in the LinkedIn body.**
  Zero of the shipped captions have one. LinkedIn does suppress reach on posts
  carrying an outbound link in the body, and the standard mitigation is to move
  the link to the first comment. Jerry asked for it in the body, so it is in the
  body; if the post underperforms, that is the first variable to test, not the
  hook.
- **The link earns its place because the announcement is the counter-party.** The
  post is not "look what NVD did", it is "NVD looked at these fields and
  concluded the problem was bytes." You cannot make that argument without
  showing the reader the conclusion you are disagreeing with.
- **Bridge to keep honest:** the Aug 26 note is about `affected` payload
  delivery, NOT about SSVC churn. A careful reader will notice. The copy handles
  it by using the note for what it does say (NVD's diagnosis was bandwidth) and
  never implying it addressed or admitted the churn.

## Pre-loaded first comment (post it yourself, immediately)

```
Reproduce the whole thing in one call, no API key needed:

curl "https://services.nvd.nist.gov/rest/json/cvehistory/2.0?changeStartDate=2026-08-26T00:00:00.000&changeEndDate=2026-08-27T20:00:00.000"

Count the details where type == "SSVC", then compare oldValue.options to newValue.options. The 166 empty ones are the entries where those two are identical.
```

## Notes (comment ammunition, do not put in the body)

- **Reproduce the whole thing in one call**, paste-ready for anyone who doubts it:
  `curl "https://services.nvd.nist.gov/rest/json/cvehistory/2.0?changeStartDate=2026-08-26T00:00:00.000&changeEndDate=2026-08-27T20:00:00.000"`
  then count `details` where `type == "SSVC"` and compare `oldValue.options` to
  `newValue.options`. Inviting the check is stronger than defending the number.
- **"You are describing normal ETL noise" rebuttal:** 486 of 2,280 modification
  events in two days is 21% of the modification traffic, attributable to one
  optional field, and 166 of them are provably empty. That is not noise, it is a
  third of a full day's re-sync budget.
- **"SSVC gives you exploitation awareness CVSS lacks" rebuttal:** in the active
  tier it is the KEV list re-encoded. Of the 1,668 corpus records where CISA set
  exploitation to "active", **1,662 (99.6%) are on the KEV list**. Useful, but a
  second copy of a list you already ingest.
- **"So delete it and lose CISA's work?" rebuttal:** the work is not NVD's to
  lose. 99.91% of it is CISA's and it is in cvelistV5, where most ADP consumers
  already read it. Deleting NVD's copy removes a duplicate, not a source.
- **"NVD stopped working" pre-empt:** 119 of 125 2026-published KEV CVEs are
  Analyzed; 24,239 of 2026's CVEs are Analyzed overall. The tiering is real.
- The Apr 15 2026 policy note, for anyone asking why NVD's own score is scarce:
  *"Going forward, we will no longer routinely provide a separate severity score
  for those CVEs."* Submissions up 263% 2020 to 2025, Q1 2026 up 33%.

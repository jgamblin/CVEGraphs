---
chart: kev_triage
posted: 2026-09-10
platforms: LI
migrated: 2026-10-11
---
# Caption: forensic triage on 2026 KEV additions (`kev_triage`)

Image: `graphs/kev_triage_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Built 2026-09-10 from a fresh scan of the
KEV feed at Jerry's request ("look at the data and come up with something new").
**Exploitation lane, Thursday, on-lane.** Second chart post of the Mon Sep 7 week after
`patch_tuesday` (Sep 8), so it sits at the 2/week cap and does not exceed it.

Chart: `charts/kev_triage.py`. Unit dots, one per KEV entry, stacked into the ISO week
CISA added it, Jan 1 to Sep 9 2026, split by the catalog's per-entry forensic-triage
flag. **Novel form for the franchise:** the last four SHIPPED chart posts were stacked bars
(`patch_tuesday`, Sep 8) and ranked bars (`patch_tag` Sep 4, `detection_coverage` Aug 24)
plus a line/path chart (`epss_kev_window_pct`, Aug 20). `nvd_deferred` was built and
reviewed but never went out, so do not cite it as a shipped precedent. No shipped chart
has used unit dots.

Data: `processed/kev_catalog.json`, catalog release 2026-09-09T19:00:50Z, 1,703 entries.
Refreshed with `cvegraphs refresh --feeds-only` on 2026-09-10. `stats()` prints
every derived figure so the copy never retypes one off the image.

## What the flag is, and why it is not a schema curio

`forensicTriage` is a real, documented CISA field, verified on cisa.gov 2026-09-10:

- **BOD 26-04, issued June 10 2026**, replaced the flat KEV deadline with a table keyed
  on four variables: public asset exposure, KEV status, exploit automatability, and
  technical impact. The top cell of Table 1 is **"3 days & forensic triage"**.
- The directive defines the phrase: **"'& forensic triage' means that the agency must
  complete remediation or mitigation action within the timeline (three days) and carry
  out a forensic triage of the asset to assess whether the system is compromised."**
- The public KEV catalog page renders the field as **"Forensic triage required per
  BOD-26-04"**, Yes or No, per entry.
- The implementation guidance defines an adequate triage as six steps: Scoping,
  Preserve and Collect Evidence, Critical Patching and Stabilization, Contain and
  Control, Triage Analysis, Escalation Decision.

## Finding (verified 2026-09-10 against the Sep 9 catalog release)

**The flag did not exist on a single KEV entry before July 1 2026. It is now on two
thirds of what CISA adds.**

| Measure | Value |
|---|---|
| Entries added Jul 1 to Sep 9, 2026 | 73 |
| Of those, forensic triage required | **48 (65.8%)** |
| Entries added before Jul 1 (all time) | 1,630 |
| Of those, forensic triage required | **0** |
| 2026 additions to date | 219, of which 48 flagged |
| Monthly flagged / total | Jul 21 of 26 · Aug 17 of 31 · Sep 10 of 16 |
| Distinct vendors flagged | 32 of the 48 entries |

- **The flag is the three-day tier, near enough.** Of the 53 entries since Jul 1 with a
  three-day window, 48 are flagged and 5 are not. Not one of the 20 fourteen-day entries
  is flagged. So the two obligations travel together, exactly as Table 1 says.
- **It is not a vendor grade.** Eight vendors sit on BOTH sides of the flag since Jul 1:
  Microsoft, Cisco, Fortinet, Citrix, Linux, WordPress, JFrog, TrueConf. The tier is
  keyed on that bug's exposure, automatability and impact, not on who shipped it. Use
  this to kill the "CISA is naming and shaming vendors" reading before it starts.
- **Age is no protection.** 42 of the 48 are 2026 CVE IDs, but the set includes
  CVE-2008-4128 (Cisco IOS, 6,507 days between publication and listing, 17.8 years),
  CVE-2019-1068 (Microsoft SQL Server, 2,599 days) and CVE-2023-49105 (ownCloud, 1,010).
  CISA is asking for compromise assessment on a 2008 Cisco IOS bug.
- **13 of the 48 were flagged within a day of the CVE record going public**, so there was
  no window in which a diligent team could have already patched. Median age at listing
  is 10.5 days.
- **Only 3 of the 48 are ransomware-linked** (`knownRansomwareCampaignUse: Known`): both
  SonicWall SMA1000 entries and Microsoft SharePoint Server CVE-2026-45659. The flag is
  not a ransomware proxy, so do not let the copy imply it.

## Caveats that must survive into the copy

- **The shipped copy does not mention the two-hour target at all**, which is the
  simplest way to be right about it: the caveat below existed only to hedge a number the
  post did not need, and deleting the mention deleted the hedge. The rule stays here as a
  guard on any future draft.
- **The six triage timings are recommended, NOT required.** The guidance says so
  outright: *"the below timelines are recommended best practices to guide agencies
  through their forensic triage. The requirement of BOD 26-04 is that an adequate
  forensic triage analysis is performed; the specific timeline below is not required."*
  Target timelines are Scoping within 2 hours of the KEV addition, evidence and critical
  patching 2 to 24, containment 6 to 24, analysis 24 to 48, escalation decision 48 to 72.
  **A draft that says "the real clock is two hours" or "the first thing you owe is due
  in two hours" is wrong and will be corrected in the comments.** Say "recommended
  pace", and say that the requirement is the triage, not the stopwatch.
- **June is ambiguous and is left unclaimed.** BOD 26-04 was issued Jun 10 and first
  cited in a KEV `requiredAction` on Jun 11, but the first `forensicTriage: Yes` is
  Jul 1. The 12 three-day entries added under BOD 26-04 before Jul 1 carry no flag. That
  is either 12 genuine "no triage needed" calls or a field CISA had not started
  populating, and the catalog cannot tell them apart. **This is why the headline
  denominator is 73 (Jul 1 onward) and not 86 (BOD 26-04 onward).** Do not say "CISA
  started requiring this on July 1"; say the first flagged entry is dated July 1.
- **`forensicTriage: No` is populated catalog-wide**, on all 1,655 unflagged entries
  including the 2021 bulk load, so the pale first half of the chart is the catalog's own
  value and not missing data. **But do not read that "No" as a CISA determination.**
  1,617 of the 1,655 were added before BOD 26-04 existed, so for them it is a schema
  default; only 38 unflagged entries were added under the directive. This is why the
  legend says "Not Flagged" and not "Remediate Only": the earlier wording asserted a
  triage call CISA never made on 1,617 entries.
- **This is a federal directive.** BOD 26-04 binds FCEB agencies. It is not a legal
  obligation for a private company, and the copy must not imply it is. The reason it
  matters outside government is that KEV is used as a de facto private-sector priority
  list, and this changes what the list is asking for.
- **KEV is a conservative floor**, not an exploitation census. Standing house rule: say
  "added to KEV" and "on the KEV list", never a blanket "exploited".
- **Not a scoop.** CISA published the table, the field and the guidance in public. The
  hook credits that and lands on the consequence, per the credit-then-consequence rule.

## Comment ammunition (deliberately not in the post)

- **PRE-LOAD THIS AS THE FIRST COMMENT.** The two-thirds figure is pooled over Jul 1 to
  Sep 9, and the monthly path is 21 of 26 in July (81%), 17 of 31 in August (55%), 10 of
  16 in September (63%). A reader who recomputes August alone will see "two thirds" as a
  window pick, and this repo has been bitten by exactly that shape before
  (`epss_report_card`'s pooled Simpson's artifact). 55% is still most, so the body claim
  holds, but have the monthly numbers ready rather than discovered. Precedent for a
  pre-loaded first comment: `detection_coverage` (Aug 24) did this with its recency
  confound.
- **If anyone raises the clock:** CISA's six triage steps carry target timelines (scoping
  within 2 hours of the KEV addition, evidence preservation and critical patching 2 to
  24, containment 6 to 24, analysis 24 to 48, escalation decision 48 to 72), and the
  guidance states outright that those are recommended best practice and not the
  requirement. The requirement is that an adequate forensic triage was performed. Answer
  with the distinction, never with the two-hour number alone.

- **Gitea CVE-2026-60004 was added to KEV on Aug 25, and its CVE record was published
  Aug 26.** CISA listed it, with the triage flag, a calendar day before the record was
  public.
- Due-date windows collapsed across 2026 independently of this flag: median 21 days in
  Jan and Feb, 14 in Mar through May, 3 from June on. Deliberately NOT plotted, because
  Jerry's BOD 26-04 commentary already covered the clock (about 30,000 impressions) and
  two step-changes on one canvas splits the finding.
- Vendors with the most flagged entries: Microsoft 6, SonicWall 4, Fortinet 3, N-able 3,
  Cisco 2, Adobe 2, Oracle 2, Langflow 2.
- The five three-day entries since Jul 1 with no triage flag: Citrix NetScaler
  CVE-2026-8452, Microsoft IKE CVE-2026-33824, Cisco ASA/FTD CVE-2026-20349, Apache
  Tomcat CVE-2026-34486, Cisco FMC CVE-2026-20316.
- Every KEV `requiredAction` since Jul 1 is byte-identical boilerplate, all 73 of them.
  Checked whether that was new and it is not: `requiredAction` has always been
  boilerplate (893 entries all time say "Apply updates per vendor instructions."), so
  there is no "CISA stopped writing instructions" story here. Killed before drafting.
- Langflow has three flagged entries counting IBM Langflow, which is the AI-stack thread
  from the Sep 4 backlog scan. Not used as the hook: the dev/AI cohort is flagged at
  8 of 12 against 40 of 61 for everything else, statistically the same rate, so
  "AI infrastructure gets the harsh tier" is an invented pattern.

## Post copy (LinkedIn)

KEV used to be a patch list. Now, for most of what CISA adds, it is an IR list: was this
box already owned?

48 of the 73 entries CISA has added to the KEV list since July 1 carry its
forensic-triage flag. The 1,630 entries added before that date do not.

When I wrote about BOD 26-04 in June, the three-day clock was the argument. The catalog
says the clock was the smaller half. The directive, issued June 10, replaced the flat
KEV deadline with a risk table, and its top tier is three days plus what CISA calls
"& forensic triage". The directive defines that: "carry out a forensic triage of the
asset to assess whether the system is compromised." CISA cited the requirement in June
entries, the per-entry flag starts July 1, and CISA publishes which entries carry it.

Your process is at least built for the patch half. The other half is a person opening up
the box, preserving evidence, and deciding whether to call it an incident. Two thirds of
new KEV entries now need somebody who can make that call inside three days.

BOD 26-04 binds federal agencies. You're outside it, and the flag is CISA's worst-case
exposure call, which agencies settle asset by asset. It fires on internet-reachable,
automatable, total-impact exploitation, and that's the profile where patching on day
three still leaves day one unaccounted for.

If a flagged KEV entry landed on you this afternoon, who makes the
was-it-already-compromised call: the patch owner, or IR?

**253 words. Passes `scripts/tells.py`: contrast 0.0 per 1k, no banned vocabulary,
sentence mean 16.9 / sd 8.8, contractions 60%, no sentence over 45 words.**

**The payoff paragraph carries ONE idea on purpose (Jerry, 2026-09-10: "this is a little
too dense").** The 284-word version stacked the CISA-guidance caveat and the sliding-share
caveat onto the end of the payoff, which is four jobs in one paragraph and kills the
momentum right where the post should land. Both moved to the comments below. **Do not put
them back in the body.**

## X (270 of 280)

KEV used to be a patch list. Now, for most of what CISA adds, it is an IR list: was this
box already owned?

48 of the 73 KEV entries added since July 1 carry CISA's forensic-triage flag. The 1,630
before them predate it.

BOD 26-04's top tier: 3 days & forensic triage.

## Bluesky (268 of 300)

KEV used to be a patch list. Now, for most of what CISA adds, it is an IR list: was this
box already owned?

48 of the 73 entries added since July 1 carry CISA's forensic-triage flag. The 1,630
before them predate it.

BOD 26-04's top tier: "3 days & forensic triage".

## Alt text

Dot chart titled "Forensic Triage on 2026 KEV Additions". One dot per CISA KEV entry,
stacked into the seven-day bin CISA added it in, from January to September 9, 2026.
Every dot from January through June is muted blue-grey, meaning not flagged. A heavy
dashed line marks July 1, and from there the bottom of each column turns dark navy,
meaning CISA also requires a forensic triage of the asset. 48 of the 73 dots right of
the line are dark; none of the dots left of it are.

## Review log

- Built and drafted 2026-09-10. Data: KEV feed refreshed same day (`--feeds-only`),
  catalog release Sep 9 19:00 UTC.
- BOD 26-04 issuance date, Table 1 wording, the forensic-triage definition, the six
  triage steps and the "timelines are not required" note all verified against cisa.gov
  on 2026-09-10 before the copy was written.
- Chart fixes applied pre-review: dot centers moved from half-integers to integers so
  the top dot of an n-high column lands on the n gridline and the stack reads off the
  axis; legend moved from "Patch Only / Patch + Forensic Triage" to "Remediate Only /
  Remediate + Forensic Triage", because the directive says "remediation or mitigation
  action" and the legend is the most screenshottable element on the image.
- Two stats bugs fixed pre-review: `june_3day_unflagged` was counting all 43 pre-July
  three-day entries back to January rather than the 12 added under BOD 26-04, and the
  ransomware figure was a hardcoded None.
- Copy drafted under `~/Documents/Github/Blogs/humanize.md`. First draft FAILED the
  tells linter on contrast constructions (2 hits, 7.0 per 1k against a 1.0 limit) and on
  uniform sentence length; both fixed. The killed constructions were "those hours are
  best-practice guidance, not the requirement" and "the thing that moved is not a
  deadline", each rewritten positively so the caveat survives without the shape.
- **`/post-review` run 2026-09-10, 12 personas, all returned. COPY "post with fixes",
  GRAPH "fix first". Every blocker and every should-fix applied the same day.**
- **Graph blocker, and the one that mattered: the "Jul 1" divider was not at Jul 1.**
  Bins were ISO weeks, so the bin holding Jul 1 also held Jun 29 and 30, and
  CVE-2026-48558 (added Jun 29) sat to the right of the line. Two reviewers counted
  **74 dots against a copy figure of 73**, and on a unit chart the reader can check.
  Fixed by anchoring seven-day bins on Jul 1 itself (`(added - ANCHOR).days // 7`) so a
  bin edge lands exactly on the date; verified 73 dots right of the divider, 48 flagged,
  0 flagged left. Month ticks now sit on the bin CONTAINING the 1st, so a label cannot
  drift a column from the date it names.
- **Graph blocker: the y=16 and y=14 gridlines ran through the legend text and the
  callout**, reading as accidental strikethrough, and the dark legend swatch floated
  over the January columns, where the chart asserts no flagged entry exists. The key
  moved out of the data field. Two placements were tried and rejected before the third
  worked: above the axes it landed on the headline (draw_header's subtitle occupies
  ~0.815 to 0.830 against an axes top of 0.80), and anchored to the axes it left-indented
  to the plot edge while every other text element aligns at x=0.05. It now sits in the
  clear band under the x-tick labels, in FIGURE coordinates on the house left margin.
  Headroom dropped from 1.22x to 1.06x, which also removed ~110px of dead space.
- Graph blocker: y-axis label was sentence case; house rule is Title Case on axis labels.
- Graph should-fixes applied: divider hardened (it carries the entire finding and
  measured 1.98:1 at feed scale) to `COLORS["text"]`, lw 1.8/1.5, dash (7,4), alpha 1.0;
  pale series moved from `COLORS["light"]` (#afc0d4, 1.86:1 on white) to
  `COLORS["neutral"]` (#8da0b5). **Deviation from the panel here on purpose:** it asked
  for #7f95ad, which is a slightly better contrast but not in the house ramp, and an
  existing token beats an invented hex. Subtitle now carries "48 of the 73 since Jul 1
  are flagged" so the image states its own finding when it travels without the copy;
  footnote names the `forensicTriage` field and closes the off-chart gap with
  "(no earlier entry is flagged)".
- **Copy blocker 1: "Two thirds of KEV entries ... that day" was wrong twice.** Five
  reviewers hit the dropped denominator (unqualified it reads as two thirds of the
  1,703-entry catalog, which is 2.8%), and "that day" invented a same-day clock. CISA's
  own steps put Triage Analysis at 24 to 48 hours and the Escalation Decision at 48 to
  72. Now "two thirds of NEW KEV entries ... inside the three-day window", which is true
  for all 48 (every one has dueDate minus dateAdded of 3).
- **Copy blocker 2: the flag-population date was standing in for the requirement date.**
  This caption warned against it and the first draft did it anyway. 13 June entries
  already cite the Forensics Triage Requirements and 12 carry a three-day window. The
  zero survives; one sentence now separates the two dates.
- **Copy blocker 3: the exposure conditional was missing.** The flag fires on
  internet-reachable, automatable, total-impact exploitation, and exposure is settled
  asset by asset per CISA's FAQ. Restored, and it doubles as the non-federal reader's
  reason to care.
- Copy should-fixes applied: hook noun changed from "the opening step of an incident
  response" (IR is a term of art carrying notification and legal clocks; the modal
  triage outcome is "no evidence") to "opens with a question for IR", which also plants
  the closing question; the sliding share owned in the copy before a commenter finds it
  (81% July, 55% August); continuity marker to the June BOD 26-04 post (30,635
  impressions, the top post of the 90-day pull); closing question turned into a fork
  with two defensible answers, since "do they know that's their job?" answered itself
  with "no"; two thesis restatements deleted; the two stacked caveat blocks merged and
  the precision credited to CISA; "Your process already handles the patch half" softened
  to "is at least built for", which protects `patch_tag` (Sep 4); the broken sentence
  "Which entries land there gets published per entry" rewritten.
- **Bluesky was unpostable at 352 characters against its own 300 limit.** Rewritten to
  287; X rewritten to 267.
- Own catch, not the panel's: the first draft asserted the Table 1 cell reads
  "3 days & forensic triage" verbatim, and the cell text was never seen. The phrase
  "& forensic triage" IS quoted verbatim in the directive's definition sentence, so the
  copy now quotes only that phrase and attributes it as what CISA calls it.
- **Post-review revision 2026-09-10, Jerry's call: the payoff paragraph was too dense.**
  It ran four jobs (the patch/triage split, the payoff, the CISA-guidance caveat, the
  sliding-share caveat). Fixed by cutting the two-hour mention entirely, which removed
  the caveat that existed only to hedge it, and by moving the sliding share to a
  pre-loaded first comment. 284 words to 247, still linting clean. **Note this cuts
  against one panel should-fix** ("own the trend before a commenter does"): the trend is
  still owned, in the first comment rather than the body, because pre-empting a rebuttal
  inside the payoff sentence is defensive writing in the post's best slot.
- **Second Jerry pass 2026-09-10, two changes.** (1) *"I don't know what this means and
  wouldn't talk like this: the triage half runs six steps to an escalation decision."*
  That sentence cited the STRUCTURE of CISA's guidance document rather than saying what
  the work is, and the post never explains what the six steps are, so "six steps" was
  carrying no meaning for a reader. Replaced with the work in plain words: "a person
  opening up the box, preserving evidence, and deciding whether to call it an incident."
  That is a fair compression of CISA's steps 1, 2, 5 and 6 (Scoping, Preserve and Collect
  Evidence, Triage Analysis, Escalation Decision), and it now pays off the closing
  question, since "make that call" and "who makes the call" are the same words. **The
  six-step structure stays in this caption for the comments; keep it out of the body
  unless the post has room to say what the steps are.**
  (2) Hook sharpened to name both states outright: "KEV used to be a patch list. Now, for
  most of what CISA adds, it is an IR list." The previous "opens with a question for IR"
  was the panel's hedge against IR being a term of art, and it blunted line one, which is
  the highest-leverage sentence in the post. **Jerry asked for the sharper claim and it is
  his call.** It is grounded rather than loose: the concrete question ("was this box
  already owned?") follows the colon, and the body still carries the exposure conditional
  and the federal-scope caveat, so the claim is arguable by design rather than
  unsupported. The "patch list / IR list" repetition of "list" is deliberate antithesis,
  not the noun churn that [[copy-readability-voice-pass]] warns about.
- Panel recommendations DISMISSED with reasons (recorded so they are not re-litigated):
  a second dashed rule at Jun 10 (three weeks is about three columns at a 38px pitch,
  the labels would collide, and the text budget allows one callout); collapsing Jan to
  Jun into a band (the full pale stretch IS the evidence for the zero); replotting as
  flagged share by month (two stories on one canvas); a tinted "48 of 73" bracket
  (furniture the text budget forbids, and redundant now the subtitle carries it);
  naming a vendor for concreteness (nothing in the data supports singling one out);
  sentence-case legend labels (INSIGHTS.md requires Title Case on legend labels, and
  the reviewer had the rule backwards).
- Code hygiene from the panel, applied: `stats()["newest_add"]` was a max over the whole
  catalog while feeding a footnote that asserts a 2026 range, now scoped to YEAR; a stale
  comment said 17 where the computed value is 12; the "read the stack off the axis"
  comment was false for odd-height columns under even-only ticks, now corrected.
- Two bugs found and fixed BEFORE review, neither of which had fired yet: the weekly
  frame reindexed to the weeks already present, so a week with zero KEV additions would
  have silently vanished and compressed the time axis; and the month label was taken from
  the bin's start date, so a Monday-start week beginning in December would have printed
  "Dec" as the first tick of a chart titled 2026.

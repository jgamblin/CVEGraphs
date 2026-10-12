# Graph backlog

Idea bank for the social engine. Status: ✅ built · 🔨 next · 💡 idea.
Tiers: **Evergreen** (re-render on cadence) · **Rotating** (topic changes) ·
**Novelty** (occasional, high-share). Full rationale in `../PLAN.md`.

## Evergreen (weekly workhorses)
- ✅ **pace** — YTD CVEs by year, apples-to-apples, "one every N minutes" hook
- ✅ **kev** — monthly KEV additions (trailing 12mo), ransomware-linked highlighted
- ✅ **cna** — top CNA issuers year-to-date leaderboard
- 💡 **forecast** — 2026 run-rate vs CVEForecast projection
- 💡 **severity** — critical/high/med/low mix of the trailing window

## EPSS (predicted exploitation) — pairs with the KEV thesis
Data: `processed/epss.parquet`; join with `data.load_nvd(with_epss=True)`.
- ✅ **epss_funnel** — exploitation signal: all CVEs vs EPSS ≥ 0.1 / on KEV /
  EPSS ≥ 0.5. One image showing predicted-rare AND confirmed-rare. Strong evergreen.
- ✅ **epss_report_card** — the backtest: what EPSS and CVSS had each flagged 30
  days BEFORE every 2026 KEV addition. The story is the SPLIT, not the pooled
  totals (pooled 33 vs 28 is a Simpson's artifact): under a year old CVSS 9.0+
  wins 20 vs 10, on the year-plus backfill EPSS wins 23 vs 8. Static score vs
  living score. First positive EPSS post; supersedes the epss_vs_kev idea with
  a time-machine design that dodges the "EPSS reacts to KEV" circularity. Data
  via `src/cvegraphs/precompute/epss_report_card.py` (historical snapshot backtest,
  auto-runs in refresh_data.py). Caption in `captions/epss_report_card.md`.
- ✅ **epss_gain** — gain curves (coverage vs effort, Jay Jacobs' suggested
  form): sweep each score's threshold against 2026 KEV additions, split
  fresh/backfill, policy dots labeled with absolute remediation workloads.
  Image 2 of the epss_report_card post; shares its precompute and caption.
- 💡 **epss_vs_kev** — EPSS distribution of KEV vs non-KEV CVEs: does the model
  score the truly-exploited ones higher? (Largely superseded by
  epss_report_card, which answers it point-in-time instead of post-hoc.)
- 💡 **high_epss_board** — the highest-EPSS CVEs published this period (a watchlist).
- ✅ **cvss_epss_gap** — CVSS vs EPSS scatter: severe on paper, quiet in the wild.
  Companion to the "vulnpocalypse that wasn't" post (scoped to Chrome via FOCUS).
- ✅ **scorer_divergence** — dumbbell: same bug, same CNA, v4 minus v3 by CWE;
  VulDB vs VulnCheck disagree (even on direction). "Who scores matters more than which
  version." Caption in `captions/scorer_divergence.md`.
- ✅ **cna_spread** — range chart: one weakness class (XSS default, CWE-swappable),
  CVSS v3 by scoring CNA; bar = middle 80% of scores, tick = average, spanning ~3.4 to
  ~6.7. "A CVSS score is an opinion with a decimal point." Caption in `captions/cna_spread.md`.
- ✅ **cwe_spread** — range chart: top 10 CWEs, CVSS v3 80% range + median. Memory/
  injection high (stack overflow 8.5), web/authz lower (XSS 6.4); XSS widest band. Companion
  to cna_spread. Caption in `captions/cwe_spread.md`.
- ✅ **score_disagreement** — agreement scatter: same CVE scored by both its own CNA
  and NVD (5,458 pairs in 2026), band flips in red. 11% exact match, 56% band flips;
  split is in impact metrics, not exploitability. The missing cell of the scoring
  series (same bug, same version, different scorer). Data:
  `processed/score_pairs.parquet` via `src/cvegraphs/precompute/score_pairs.py` (also
  captures CISA-ADP scores, excluded from the chart as 90% echoes). Caption in
  `captions/score_disagreement.md`.

## Detection coverage (open rulesets) — the exploitation lane's new data source

First charts to read a data source outside the CVE/KEV/EPSS triangle. Data:
`processed/detection_rules.parquet` via `src/cvegraphs/precompute/detection_rules.py`
(auto-runs in refresh_data.py; fetches ~120 MB of rules per run).
- ✅ **detection_coverage** — ranked bars: share of each vendor's KEV entries that at
  least one open rule NAMES by CVE ID. 224 of the 553 KEV CVEs published since 2023-08-01 (40.5%); cohort is publication date, not CVE-ID year.
  The shape is the story: Apache/Fortinet/Ivanti/Citrix above 70% because network
  signatures are CVE-shaped, and Apple 0 of 31, Google 0 of 24, Android 0 of 10,
  Qualcomm 0 of 8 because endpoint detection is behavioral by design. Caption in
  `captions/detection_coverage.md`.
- 🔨 **detection_breadth** — BUILT, RENDERS, **cut from the detection_coverage post
  2026-08-22 and unshipped.** Distinct CVE IDs named by each ruleset: Emerging Threats Open
  2,138, SigmaHQ 180, Elastic 85, union 2,273, against Nuclei's 4,386 offense-side templates.
  Cut because the offense comparison is a category comparison (a Nuclei template is a CHECK
  for whether you are vulnerable; a detection rule watches for exploitation) and it needs a
  paragraph of caveat the host post could not spare. **Do not re-attach it to a coverage post.**
  Re-hook it as the LEAD of its own post where the offense/defense framing has room: the
  honest thesis is that the two sides file knowledge differently, and the proof is that Nuclei
  names zero of the 67 Apple and Google KEV entries too. Pairs naturally with `time_to_rule`.
## Rulezet evaluated 2026-08-24: NOT a replacement, viable as a supplement

Suggested in a comment on the `detection_coverage` post. [rulezet.org](https://rulezet.org) is an
open aggregator, ~205k rules across nine formats (Sigma, Suricata, YARA, Zeek, Wazuh, Elastic,
CRS, Nova, NSE), AGPL, with a public no-auth CVE endpoint:
`GET /api/rule/public/search_rules_by_cve?cve_ids=CVE-...` (comma-separated batches OK).

**Do NOT re-cut the coverage graph on it as the primary source.** Its CVE index misses the
network side almost entirely: of 12 CVEs that ET Open demonstrably names, Rulezet returned rules
for **1**. ET is 206 of the 225 named in the shipped chart, so switching would crater coverage
from 40% to single digits as a plumbing artifact, not a finding.

**Probable cause, worth reporting upstream to Rulezet as a real bug:** Suricata cites CVEs as
`reference:cve,2021-44228`, with no `CVE-` prefix, so a generic string search never matches them.
This repo's `src/cvegraphs/precompute/detection_rules.py` carries a dedicated `ET_REF` regex for exactly
this. Rulezet's ET import also appears as a single `emerging-all.rules.zip by admin admin` upload
rather than per-rule CVE-indexed records.

**Where it genuinely adds:** on 80 CVEs this repo calls unnamed, Rulezet found a rule for 4 (5%),
from community sources not scanned here (Agent-Threat-Rule, Hatchepsoute/sigma-rules, one F5 KB).
Extrapolated that moves 329 unnamed to roughly 313, so 60% to about 57%: same story, slightly
softer. It also brings formats this repo has none of (YARA, Zeek, Wazuh, CRS, NSE).

- 💡 **detection_coverage_v2** — direct ET/Sigma/Elastic scan UNION Rulezet's other formats, which
  is strictly better than either source alone. Needs the bulk dump (`/rule/private/dumpRules`,
  account required, not created) or per-CVE API calls at ~1 request per CVE.

- 💡 **time_to_rule** — days between a public detection rule first appearing and the CVE
  landing on KEV. Does open detection lead or lag CISA? Needs git-history mining of
  SigmaHQ and Elastic (both public); ET Open has no public git history, so the network
  side would have to drop out or come from a mirror. The strongest follow-up.
## BOD 26-04 forensic triage: KEV's second obligation (built 2026-09-10)

- ✅ **kev_triage** — unit dots, one per KEV entry, stacked into the week CISA added it,
  Jan 1 to Sep 9 2026, split by the catalog's per-entry `forensicTriage` flag. **The flag
  is on zero of the 1,630 entries added before Jul 1 2026 and on 48 of the 73 added
  since (65.8%).** BOD 26-04 (issued Jun 10 2026) replaced the flat KEV deadline with a
  table keyed on public exposure, KEV status, exploit automatability and technical
  impact; its top cell reads "3 days & forensic triage", meaning fix it in the window AND
  "carry out a forensic triage of the asset to assess whether the system is compromised."
  Reads straight from `processed/kev_catalog.json`, no precompute. Caption in
  `captions/kev_triage.md`. **First franchise chart to use unit dots**, chosen because
  the four preceding chart posts were ranked or stacked bars.
  **Load-bearing caveat: the six triage step timings (scoping within 2 hours, escalation
  decision at 48 to 72) are CISA's recommended best practice and explicitly NOT the
  requirement.** Any copy claiming a two-hour obligation is wrong.
  **Cohort caveat: the headline denominator is 73 (Jul 1 onward), not 86 (BOD 26-04
  onward)**, because the 12 three-day entries added under 26-04 before Jul 1 carry no
  flag and the catalog cannot say whether that is 12 "no triage" calls or an unpopulated
  field.

Ideas this opened, none built:
- 💡 **triage_backlog** — cumulative count of flagged entries against a rolling
  "still inside the recommended 72-hour escalation window" line. Turns a policy chart
  into a workload chart. Needs a view of what an agency actually has deployed, which
  this repo does not have, so it would have to be framed per-entry, not per-agency.
- 💡 **triage_vs_detection** — join the 48 flagged entries to
  `processed/detection_rules.parquet`. If CISA is asking "were you already compromised",
  the fair question is whether anything public would have told you. Direct follow-up to
  `detection_coverage`, and the cohort is small enough to name every entry.
  **Check the recency confound first:** all 48 are since July, and ET Open/Sigma/Elastic
  coverage of very fresh CVEs is thin for reasons unrelated to this flag.
- 💡 **kev_window_collapse** — the due-date ladder across 2026 (median 21 days in Jan and
  Feb, 14 in Mar to May, 3 from June). Deliberately kept OFF `kev_triage` so the two step
  changes do not split one canvas. Only worth its own post if it carries something
  Jerry's BOD 26-04 commentary (about 30,000 impressions) did not.

- 💡 **rule_gap_watchlist** — KEV entries with a public exploitation template and no
  public defensive rule (on the earlier ID-year cohort, 54 of 631). A watchlist card, not a ranking.

## Rotating deep-dives
- ✅ **cwe_circles** — hierarchical circle pack: CWEs grouped by MITRE pillar
  (authoritative, from cwe.mitre.org), sized by count, colored by CVSS
- 💡 **cwe** — weakness class of the week (trend + top examples)
- 💡 **vendor** — one vendor's count + YoY, rotating the top 20
- 💡 **product** — hot target spotlight (e.g. OpenClaw tracker)
- 💡 **rhythm** — day-of-week / hour publishing heatmap ("Patch Wednesday")
- 💡 **time_to_kev** — days from publication to KEV listing
- 💡 **cvss_drift** — average/median CVSS over years
- 💡 **us_vs_world** — who *publishes* the world's CVEs (July 4 post)
- 💡 **reserved_gap** — reserved-but-unpublished ID backlog
- 💡 **id_burn** — annual CVE ID block consumption rate

## Themed / one-off (reusable as data updates)
- ✅ **chrome_day** — "Out with Patch Tuesday, in with Chrome Day": monthly
  biggest-single-day head-to-head, Microsoft vs Chrome CNA. Caption in
  `captions/chrome_day.md`.

## Novelty formats (non-bar, for feed variety)
- ✅ **calendar_heatmap** — GitHub-style daily-publishing grid (best in wide)
- ✅ **waffle_exploit** — 1,000 squares, ~2 exploited; the volume-vs-risk thesis
- ✅ **ridgeline_severity** — CVSS distribution by year, per-year average marker
- ✅ **cna_bump** — monthly CNA rank-flow: GitHub and MITRE trade places (#7->#1 vs #1->#7)
- 💡 **cna_race** — animated bar-chart-race GIF of top CNAs over time
- 💡 **streamgraph** — severity composition month over month
- 💡 **woke_up** — "since you woke up" real-time-ish stat card
- 💡 **milestone** — auto-fire cards on round numbers (350,000th CVE, etc.)

## Adding a chart
1. Create `charts/<name>.py` exposing `render(nvd=None, ratios=DEFAULT_RATIOS)`
   that returns the written paths (copy `charts/pace.py` as the template).
2. Register it in `make.py` `CHARTS`.
3. Add a caption template in `content/drafts/<chart>/post.md<name>.md`.
4. Slot it into `content/planning/CALENDAR.md`.

## CWE declared in free text, invisible to parsers (queued 2026-08-13)

A CNA can declare a weakness class two ways in CVE Record Format 5: the optional
`cweId` key, or a bare `CWE-79 Cross-Site Scripting (XSS)` string in the
`problemTypes.descriptions[].description` field. Consumers that read only `cweId`
score the second group at zero.

Found while building `cwe_cna_rank`: this repo's own parser did exactly that and
printed a red 0.0% next to WPScan when its real 2026 figure is 100.0% (697 of 697
records carry a `CWE-<n>` in description text, and exactly zero set `cweId`). Fixed in
`refresh_data.py` via `CWE_IN_TEXT`.

Others doing the same, all 2026: CERT/CC 150 of 150 records, Samsung Mobile 117 of 117,
plus Go and curl below the volume floor. Corpus-wide the fix moved CWE presence from
39.59% to 40.90%, about 4,672 records.

**Why it is a post:** it is a named-cast data-plumbing story with a concrete fix, and
the villain is a schema affordance rather than a lazy vendor. It also inverts the
usual "vendor did not bother" framing, which makes it a better follow-up to
`cwe_cna_rank` than another coverage chart. Chart idea: for each CNA, stacked share of
CWE declared via `cweId` versus free text versus not at all.

**Caveat to carry:** this repo shipped the bug too. Say so.

## Week of Aug 31 2026 scan (2026-09-04, fresh refresh, V5 newest record Sep 4 21:48 UTC)
Jerry dropped the whole queue on 2026-09-04 and asked for a fresh look at this week's data.
Week (Mon Aug 31 to Fri Sep 4): 2,046 CVEs published, 7th of 36 weeks in 2026, nothing
unusual in volume. Three candidates came out of it, ranked; the volume items are footnotes.

1. **`nvd_deferred` (scoring/measurement lane, Tue). BUILT 2026-09-08, proposed for Tue Sep 8; see `captions/nvd_deferred.md`. Note the shipped cohort includes Modified rows, so the headline is 39.2%, not the 42.5% below.** NVD now marks 2026 CVEs it will not
   enrich as `vulnStatus = Deferred`; 20,076 of the 47,200 settled (Analyzed + Deferred)
   2026 CVEs, 42.5%, rising to 53% for August publications and 78% for this week's. Deferred
   = no CPE, no NVD score, ever; 89% still carry the CNA's own v3. It is a CNA lottery, not a
   severity cut: Patchstack, Wordfence, WPScan, TR-CERT ~100% deferred; VulDB 71%; VulnCheck
   55%; MITRE 54%; GitHub 29%; Linux 6%; Microsoft, Apple, Chrome, Adobe, Mozilla 0%; Oracle
   0.1%. 2,058 Deferred CVEs carry a CNA Critical score (890 are 9.8). All 140 KEV-listed
   2026 CVEs are Analyzed (policy working). Flag bulk-applied 2026-06-17 (8,256 that day).
   Chart: deferred share of settled CVEs by CNA, top 25 by volume. Traps: compute over
   settled rows only (Aug has 3,879 "Received"); the SSVC caption already quotes the Apr 15
   policy and "119 of 125 KEV analyzed", reuse, do not contradict; NVD's public label is
   "Lowest Priority - not scheduled for immediate enrichment", the API says "Deferred".
2. **`kev_dev_stack` / `kev_ai_stack` (exploitation lane, Thu).** Triggered this week by
   LiteLLM's third 2026 KEV listing (Sep 2) plus IBM publishing 17 Langflow CVEs and NVIDIA
   30 Megatron Bridge deserialization CVEs, and OpenAI (CNA `OAI`) publishing its first Codex
   CVEs (4 this week, 6 all-time). Strict AI-stack cohort (Langflow incl. IBM Langflow,
   LiteLLM, Ray, MLflow): 1 KEV entry through 2025, 10 in 2026 so far. Broader developer
   tooling cohort (source forges, CI/CD, build tools, frameworks, ML/LLM frameworks,
   orchestrators; CMSes, appliances, OS/browser, commercial apps excluded): 2023 9, 2024 16,
   2025 22, 2026 32 of 211 (15.2%, vs 4.8% / 8.6% / 9.0%). Same window Jan 1 to Sep 4: 5, 13,
   14, 32. Taxonomy is the attack surface: publish the inclusion list in the caption and use
   the strict AI cohort in the copy. Publish-to-KEV gaps this week: Starlette 99 days, Kestra
   68, LiteLLM 56, SonicWall 1, Chrome 1.
3. **BOD 26-04 three-day clock (data, not commentary).** 91 of 211 2026 KEV additions carry a
   3-day due date; monthly share went 2 of 17 (Jan) to 22 of 26 (Jul) and 21 of 31 (Aug).
   Vendors have blogged the policy heavily and Jerry's BOD commentary already did 30k; only
   worth it as a chart if paired with something new (e.g. 12 of the 91 had no CNA CVSS at all).

Volume footnotes, milestone-only: **August 2026 is the busiest CVE month ever, 12,271**, 26%
over July's 9,759, 3.4x Aug 2025 (Linux +810, VulnCheck +547, WPScan +316, IBM +286 vs July;
Oracle's Aug 18 batch of 889 in six minutes was Helidon and Hyperion, not a CPU). 2026 YTD is
59,572 and crosses 60,000 around Sep 6 (2025 same window: 31,728). HPE published 86 in a day
(18x its weekly average), Canva became a CNA (2 CVEs), CIRCL is a new 2026 CNA with 15 this week.

**Built 2026-09-04 from Jerry's ask, not from the scan above: `patch_tag`** (which CNAs tag
the fix). 12.0% of 2026 CVEs carry a reference tagged `patch`; 3 of 26 volume CNAs tag
nearly all, 15 tag none; Linux links the fix commit on 100% and tags zero; CNA-or-NVD tag
23.5%. **Shipped Fri Sep 4 2026** (see CALENDAR log; 1,000 impressions at 4 days). Caption: `content/posts/2026-09-04-patch_tag/post.md`. Data:
`src/cvegraphs/precompute/patch_tag.py` (raw V5 reference tags, not in the main parquet).

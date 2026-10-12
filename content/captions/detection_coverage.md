# Caption — KEV CVEs named by an open detection rule (`detection_coverage`)

**Single-image post.** `graphs/detection_coverage_<ratio>_<date>.png`.

**`detection_breadth` was cut from this post on 2026-08-22 (Jerry's call, I agreed).** It was
image 2 and its entire hook was the offense-side comparison: 2,273 defensive CVE IDs against
Nuclei's 4,398. A Nuclei template is a CHECK for whether you are vulnerable; a detection rule
watches for exploitation. Counting one against the other is a category comparison that needs a
paragraph of caveat this post cannot spare, and "offense keeps the better index" was the
sentence most likely to read as a shot at defenders. The chart, its caption facts and
`scripts_precompute_detection_rules.py` all still build; see BACKLOG for the re-hook.
House style: no em dashes; factual Title-Case heading AND labels. Exploitation lane.
**Claimed Tue Aug 25 2026** (off-lane on purpose, see CALENDAR). Cohort rescoped 2026-08-24 from
CVE-ID year to publication date at Jerry's request. The Aug 24-30 week was verified empty on 2026-08-22 from LinkedIn creator analytics; `epss_kev_window_pct` shipped Aug 20, not Aug 27.

`/post-review` run THREE times: twice on 2026-08-22, once on 2026-08-24 after the rescope.

**Round 1** (COPY "post with fixes", GRAPH "fix first"): caught that the copy claimed Citrix
clears 70% when it is 63.6%; that five reviewers read the red zero rows as a shame list; that
image 2's union bar sat above components summing higher; and that "WebKit sandbox escape" was
a category error. Two of the panel's own numbers were wrong and were NOT propagated: the
breadth overlap is 118 CVEs named by more than one ruleset (130 is the double-count excess),
and the four zero vendors are 0 of 79 KEV additions in 2023-2025, not the 0 of 73 it cited
(0 of 73 is a real figure, but it is the count inside the posted cohort, a different measure).

**Round 3** (2026-08-24, after the publication-date rescope) is logged in CALENDAR.
**NOTE: round 3 ran 11 of 12 personas.** `review:domain-skeptic` died on an API error, and that
is the persona that pushes hardest on methodology, so the rescope has NOT had a full adversarial
method review.

**Round 2**, run because the round-1 fixes changed the chart's whole emphasis system and no
reviewer had seen the new render. It paid for itself by catching THREE defects introduced or
missed in round 1, two of them in code:
1. **"None of the 40 Apple entries on the CISA KEV list" is false as written.** Apple has 94
   KEV entries; 40 is the 2023+ subset. The scope sat in the *next* sentence, and that line is
   the most screenshottable in the post. Method sentence now comes first.
2. **The method sentence over-promised.** It said "the CVE ID appears anywhere in a rule file",
   but `_scan_et` matches ET Open with `ET_REF`/`ET_META` only, never the free-text `CVE_RE`.
   Now "counting a hit if a rule file cites the CVE ID", matching the chart footnote.
3. **`ax.spines["bottom"].set_bounds(0, 100)` was never applied.** A round-1 patch landed its
   comment but not its code, so the baseline still ran past 100%. Also fixed: the row track
   (zorder 1) was painting over the gridlines (zorder 0), making the rate scale invisible
   exactly where it was needed, and Apache's value label crossed the track edge. Value labels
   now sit in a fixed column at x=102.

## Finding (verified 2026-08-22, on refreshed data)

Measured question, and the only one the data supports: **does at least one rule in a
widely used open ruleset explicitly NAME this CVE ID?**

Scope: the **554 CVEs on the CISA KEV list whose CVE record was PUBLISHED on or after
2023-08-01** (records run 2023-08-03 to 2026-08-17). Publication date, not CVE-ID year, which
is what this repo uses everywhere else and is the more precise cut: 82 KEV entries carry a
2023-or-later ID but went public before the cutoff, and 4 carry an older ID published after it
(CVE-2021-27137 was published in 2026). Three full years also keeps every ruleset in its own
era, since an unscoped read of a catalog reaching back to CVE-2002 measures "the ruleset had
not been written yet" rather than coverage. Two KEV entries (CVE-2026-72529, CVE-2026-72530)
have no record in either feed yet and drop out; the chart counts them so the drop is not silent.

**The posted image, KEV coverage (554 CVEs published since 2023-08-01):**
- Named by at least one open defensive rule: **225 (40.6%)**, so **329 (59.4%) are not**
- Emerging Threats Open 206 (37.3%) · SigmaHQ 42 (7.6%) · Elastic 25 (4.5%)
- Host side alone (Sigma + Elastic): 51 (9.2%)
- Clearing 70%: **Apache 9 of 9 (100%)**, SolarWinds 5 of 7 (71.4%), Ivanti 17 of 24
  (70.8%), Fortinet 12 of 17 (70.6%). **Citrix 5 of 9 (55.6%) and Palo Alto 7 of 11 (63.6%)
  do NOT clear 70%** (an early draft said Citrix did). **Progress fell below the 7-entry
  floor on this cohort and is no longer charted;** do not cite it.
- Bottom: **Apple 0 of 31, Google 0 of 24, Android 0 of 10, Qualcomm 0 of 8** (73 CVEs, no
  named rule anywhere). Microsoft 20 of 95 (21.1%), Cisco 9 of 27 (33.3%).
- Chart shows the 18 vendors with 7+ KEV entries, 318 of the 554. The 137 smaller vendors
  run 125 of 236 named (53.0%), so the charted slice is BLEAKER than the headline, not
  cherry-picked. The subtitle states both.

**NOT POSTED. `detection_breadth`, corpus-wide breadth (all years, distinct CVE IDs named).**
Kept for the re-hook and for comments:
- Emerging Threats Open **2,138** from 50,715 enabled rules
- SigmaHQ **180** from 3,797 active rules
- Elastic detection-rules **85** from 2,192 rules
- All three, de-duplicated **2,273** (118 CVE IDs are named by more than one, which is why
  the union is smaller than the 2,403 the bars add up to)
- Nuclei (offense-side templates) **4,398** from 13,416 templates, **1.9x** the defensive union

**Supporting, for copy and comments (not charted):**
- On the same cohort, ransomware-linked KEV entries run **66 of 96 named (68.8%)**
  versus 40.5% overall. The community does prioritize.

- **CUT FROM THE POST, keep for comments only.** Nuclei names 4,398 distinct CVE IDs against the
  three defensive rulesets' 2,273, and names **0 of the 67** Apple and Google entries. If anyone
  asks "what about offense-side tooling", that last figure is the answer: offense is not winning
  on endpoint, it is absent there too, which is the cleanest proof this is indexing and not effort.
- All 24 Google entries are Chromium-family (V8 13, Chromium 4, Skia 2, Mojo, WebRTC,
  libvpx, WebP, Dawn). Zero are Android or endpoint.
- Of the 31 Apple entries, 17 are memory-safety classes (memory corruption 8, use-after-free 4,
  buffer overflow 4, out-of-bounds 3, type confusion 1). Only 6 mention WebKit, and exactly one
  is a WebKit type confusion, so **do NOT use "a WebKit type confusion" as the exemplar** the
  way an earlier draft did; the generic memory-safety-in-a-browser-engine framing is what holds.

## LinkedIn / Mastodon
Attach: `detection_coverage_wide_<date>.png`. Single image.
```
"Do we have detection for this CVE?" is normally the first question after a CVE lands on CISA's (Cybersecurity and Infrastructure Security Agency) KEV list. Six times in ten, nothing public can even tell you.

I checked the 554 KEV CVEs published in the last three years against Emerging Threats Open, SigmaHQ, and Elastic detection rules, counting a hit if a rule file cites the CVE ID. 329 have none. None of Apple's 31. None of Google's 24, every one of those a Chromium bug. Microsoft: 20 of 95.

The split tracks how a bug is reached, not how well it is defended. Network-reachable bugs get network signatures, and a signature carries the CVE number: Apache 9 for 9, then SolarWinds, Ivanti, and Fortinet all above 70%. Endpoint rules match attacker techniques instead, so a browser or kernel bug almost never carries its CVE, even when the EDR catches the attack.

The CVE is the identifier the due date arrives in, the identifier the auditor asks for, and the identifier your dashboard tracks. For 60% of these CVEs, there are no detection rules to track against.
```

**AS SHIPPED 2026-08-24.** Jerry's final edit. Changes from the reviewed draft: hook reworded to
"Do we have detection for this CVE?" (stronger, and it names the actual question practitioners
ask), CISA spelled out on first use, Oxford commas, "detection rules" not "detection-rules", the
EULA scope note moved from the method sentence into the first comment, and the closing question
dropped so the post ends on the statement. The comment carries the question instead.

## X
```
"Are we covered for this one?" is the first question after a CVE hits KEV. Six times in ten, nothing public can tell you.

329 of 554 KEV CVEs published since Aug 2023 have no open rule naming them. Apple: 0 of 31.

An indexing gap, not a detection one. What do you send back?
```

## Bluesky
Separate from X: the 300-grapheme cap truncates the X text through its payoff.
```
"Are we covered for this one?" is the first question after a CVE hits CISA KEV. Six times in ten nothing public can tell you.

329 of 554 KEV CVEs published since Aug 2023 have no open rule naming them. Apple: 0 of 31.

More indexing gap than detection gap. What do you send back?
```

## First comment (pre-loaded, post it yourself right after publishing)
```
A note on scope: I only checked open rulesets. Most commercial EULAs forbid publishing what a product does or does not detect, so a CVE-level coverage comparison is not available to anyone outside the vendor.

That cuts both ways. It means this measures the open ecosystem only, and it also means nobody outside those vendors can audit their coverage claims either. If your EDR or IDS vendor does publish CVE-level coverage, I would genuinely like to see it.
```

Held in reserve for replies, not posted up front:
- **Recency:** coverage falls as rules accrue after disclosure, 48% for CVEs published in 2024 and
  31% for 2026. It does NOT explain the zeros: Apple's entries are the oldest cohort on the chart,
  and the four zero-coverage vendors are 0 of 79 across every KEV addition from 2023 through 2025.
- **Ransomware:** on this cohort, ransomware-linked KEV entries are named 66 of 96, about 69%
  against 40.6% overall. Use if the thread needs the good news.
- **Offense-side:** Nuclei's templates name 4,398 distinct CVE IDs against the three defensive
  rulesets' 2,273, but zero of the Apple and Google entries. Different filing systems, not effort.

## Alt text

Image 1:
```
Horizontal bar chart ranking 18 software vendors by the share of their CISA KEV entries
that at least one open detection rule names by CVE ID, covering the 554 KEV CVEs published
on or after August 1, 2023. Apache is highest at 100%, 9 of 9, then Ivanti 71%, 17 of 24,
Fortinet 71%, 12 of 17, SolarWinds 71%, 5 of 7, Palo Alto Networks 64%, 7 of 11, Adobe 63%,
5 of 8. Microsoft is 21%, 20 of 95, Cisco 33%, 9 of 27, and Linux 13%, 1 of 8. Four vendors
are at zero: Apple 0 of 31, Google 0 of 24, Android 0 of 10, Qualcomm 0 of 8. Source: CISA
KEV, CVE List V5, Emerging Threats Open, SigmaHQ, Elastic detection-rules.
```

Image 2:
```
Horizontal bar chart of how many distinct CVE IDs each open ruleset names. Nuclei's
offense-side exploitation templates name 4,398 CVE IDs from 13,416 templates, shown in red
at the top. Emerging Threats Open, SigmaHQ and Elastic detection-rules de-duplicated name
2,273. Individually: Emerging Threats Open 2,138 from 50,715 enabled rules, SigmaHQ 180
from 3,797 active rules, Elastic 85 from 2,192 rules. Source: rulesets retrieved 2026-08-22.
```

## Notes / caveats

- **THE framing rule. Never say "undetectable", "blind", or "X% of KEV cannot be
  detected."** This measures NAMING, not detection. Endpoint detection is overwhelmingly
  behavioral and deliberately does not carry CVE IDs, so a zero is a lookup gap. Both
  images carry this in the footnote because a screenshot travels without the post.
  The copy says "an indexing gap more than a detection gap", comparative on purpose:
  nothing here tested whether behavioral rules actually fire, so the flat binary
  ("not a detection gap, an indexing gap") is an affirmative the data cannot support.
- **Do not present SigmaHQ's 180 as a coverage failure.** Sigma's stated design is
  behavior over signature; measuring it by CVE names grades it against a goal it openly
  rejects. That is the finding, not an indictment. This is the single biggest tone risk
  in the post: these are volunteer and vendor-supported communities Jerry knows
  personally. Frame as a map, never a scorecard.
- **CHART: no red on the zero vendors.** An earlier render drew Apple/Google/Android/
  Qualcomm in alert red. Five reviewers independently read it as "these vendors are
  dangerously uncovered", i.e. the exact claim the footnote refutes, aimed at four named
  companies. All bars are navy now; emphasis rides on the absent bar, bold weight and the
  literal "0 of 31". (Red remains legitimate on the Nuclei bar in the now-cut `detection_breadth`,
  which is one accent with one meaning.) Do not reintroduce it here.
- **Do not say Citrix clears 70%.** Citrix is 55.6% and Palo Alto 63.6%. The four that clear
  it are Apache (9 of 9), SolarWinds, Ivanti and Fortinet. Progress is no longer charted.
- **The Sigma count is the generous read, but ET's is not.** SigmaHQ and Elastic are scanned
  free-text, so 180 counts any CVE ID anywhere in the rule file including reference URLs
  (145 come from `cve.*` tags alone). ET Open is matched on its `reference:cve,` and
  `metadata: cve` fields only. The generous read is charted for Sigma on purpose, so its low
  figure cannot be attacked as a parsing artifact; strict-tag-only scoring moves the headline
  254 to 252, so nothing turns on it. Because the two sides differ, the copy says "a rule
  file cites the CVE ID" and must NOT claim a uniform free-text scan.
- **ET Open is a deliberately trimmed, lagged subset of ET Pro.** Part of the 37.2% is a
  licensing decision, not missing knowledge. ET also ships 19,483 rules commented out by
  default; those are excluded, and 350 CVEs are named ONLY by disabled rules. Counting them
  would overstate what an out-of-the-box deploy alerts on.
- **Nuclei is not a detection ruleset** and the chart labels it "offense-side". The honest
  claim is about how each side INDEXES its knowledge, never "offense is beating defense at
  detection". It names zero of the 67 Apple and Google entries, which is the proof: it is a
  different filing system, not a better one.
- **Vendor names are CISA's own `vendorProject` field, unedited**, and the chart footnote
  says so. Google and Android are separate rows; "Apple" pools iOS, macOS and WebKit. The
  four zero-coverage vendors total 87 CVEs however you group them.
- **The publication-date cut is load-bearing.** Unscoped, the full 1,674-entry KEV catalog
  reads about 35%, mixing CVE-2002 entries against rulesets written in 2017 and later. Scoping
  on CVE-ID year instead (the earlier draft) gives 631 CVEs and 40.3%, close but less precise:
  it pulls in 82 records published before the cutoff and misses 4 published after it.
- **Recency confound, disclosed in the first comment:** coverage falls with recency as
  rules accrue after disclosure (49% for 2024 CVE IDs, 30% for 2026). It does NOT explain
  the zeros: the four zero vendors are 0 of 79 across 2023-2025 KEV additions, and 0 of 73
  inside this cohort.
- **Do not claim a time-to-rule finding.** Whether the community writes rules before or
  after a KEV listing is a separate question this data cannot answer (ET Open has no public
  git history). It is a good follow-up chart, not a line in this post.
- **SIGMA'S LANES. Do not say SigmaHQ rejects CVE indexing.** Verified 2026-08-24 against the
  shipped tarball: 160 of Sigma's 180 CVE IDs live in `rules-emerging-threats/` (473 files),
  while the generic `rules/` corpus of 3,144 files names just 48. The accurate claim, and the
  sharper one, is that the GENERIC rules are threat-agnostic by design and the CVE-named
  content sits in a small separate lane. "SigmaHQ is threat-agnostic, full stop" is checkable
  and wrong, and a detection engineer who knows the repo layout will read the post's
  load-bearing justification as false.
- **NEVER write "no rule anywhere".** A draft said the 329 "have no rule anywhere with their
  number on it". That un-scopes a three-ruleset measurement into a claim about all detection,
  and it is the single line most likely to be screenshotted to dismiss the post. Name the three
  rulesets inside the sentence that carries the number.
- **Percentages are rounded HALF-UP, not by Python's default.** Three vendors share denominator
  8 and land on exact .5; `f"{62.5:.0f}"` gives 62 while `f"{37.5:.0f}"` gives 38, so a reader
  checking two rows finds the rule inconsistent. `_pct_label` in the chart uses Decimal
  ROUND_HALF_UP: Adobe 63%, Linux 13%, Oracle 38%.
- **COPY BUDGET: one caveat, stated once.** After three panel rounds the copy carried FOUR
  sentences making the same caveat ("None of that is a defense ranking", "not because they are
  better defended", "a filing problem before it is a detection problem", "nobody can look the
  CVE up, which is not the same as nobody can see it"), plus a "My read:" hedging tic and a
  personified "the index" whose antecedent had been cut with the Nuclei paragraph. Jerry called
  the result "AI slop", correctly. Stripped 2026-08-24: 310 words to 262, caveat stated once as
  "a zero means nobody wrote the number down. It does not mean nobody can see the attack."
  **Each review round adds a hedge and none removes one.** If another round runs, treat added
  caveats as suspect and check the whole piece reads aloud before applying them.
- **CHART BUDGET: ONE subtitle line. Everything else goes under the graph.**
  Three review rounds each added a defensible caveat line to the deck, and the cumulative
  result was an image that was **53% text and 47% bars**, which Jerry rejected as no longer a
  graph. Two stacked grey bold subtitle lines also just look wrong under the headline. The
  rule now: the subtitle carries the headline stat and nothing else; the definition of
  "named", the sample reconciliation and the sources are three footnote lines below the plot.
  If a future panel wants another line on the image, move something off first.
- **Commercial rulesets are out of scope BY NECESSITY, and say so.** Most commercial EULAs
  forbid publishing what a product does or does not detect, so a coverage comparison is not
  available to anyone outside the vendor. Stated in the post copy (in the method sentence, where
  it reads as rigor rather than as a hedge) and expanded in the first comment. This is the single
  most likely reply, and the answer is stronger than a dodge: it also means nobody outside those
  vendors can audit their coverage claims.
- **METHOD WORDING IS LOAD-BEARING.** Say "a rule file cites the CVE ID", never "appears
  anywhere in a rule file". ET Open is matched on its `reference:cve,` and `metadata: cve`
  fields only; only Sigma and Elastic are scanned free-text. The looser phrasing describes a
  method that was not run.
- **NEVER write "the 31 Apple entries on the CISA KEV list" unqualified.** Apple has 94 KEV
  entries in total. Establish the three-year publication scope BEFORE any vendor count, because
  that sentence is the one that gets screenshotted away from its qualifier.
- **The `cwe_cna_rank` self-citation was CUT (round 3).** It read "Twelve days ago I posted
  four CNAs that never attach a weakness class, Apple among them. Same shape, one layer down."
  Three reasons, any one sufficient: the date was only true for an Aug 25 publish while the
  chart stamped Aug 24; it is a dangling reference for everyone who missed Aug 13; and the
  equivalence is WRONG in a way that contradicts this post's own thesis. Apple chooses not to
  emit a CWE on its own records. Nobody at Apple decides what SigmaHQ indexes. Do not restore it.
- **X is 271 of 280 characters and Bluesky 294 of 300 graphemes.** Recount if either is edited.
  Both say "published since Aug 2023", not "since Aug 2023": the short form reads as ADDED to KEV
  since then, which is a different set.
- **The magnitude is stated in the NEGATIVE in the copy (329 of 554) and the POSITIVE on the chart
  (225 of 554 named).** Both are the same fact and the arithmetic checks, but never write the 329 as
  "329 have no detection" or "six in ten are undetectable". It is 329 with no rule CARRYING THEIR
  NUMBER. Also do not swap in the neither-defensive-nor-Nuclei figure: it mixes offense and defense
  and needs a sentence the hook cannot spare, and the offense side is cut from this post anyway.
- **Panel dismissals, do not relitigate:** re-cutting the chart by attack-surface class
  instead of vendor (different chart, backlog); sqrt(n) bar thickness or splitting bars
  into ET-vs-host segments (every row already prints its denominator); leading with
  Microsoft instead of the Apple zeros (the zeros are the reason anyone stops scrolling);
  "pooling 40.3% contradicts the Aug 20 never-pool-KEV thesis" (that split mattered because
  pooling INVERTED the result; here the split is monotone and changes no conclusion);
  sqrt-scaled bar thickness or Wilson whiskers (every row prints its own denominator);
  raising the vendor floor to 10 (deletes Progress and SolarWinds to tidy the sample);
  dropping the Android and Qualcomm rows (deleting inconvenient rows is worse than
  annotating them); a 70% reference line (the per-row percentages are the check).

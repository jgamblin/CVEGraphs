# Caption: Ranked bars, which CNAs tag the fix (`patch_tag`)

Image: `graphs/patch_tag_<ratio>_<date>.png`. House style: no em dashes; no "n="; factual
Title-Case heading + labels; post-date stamp. Data-quality lane (Tuesday). Same shape and
250-CVE floor as `cwe_cna_rank` (Aug 13) so the two CNA-practice charts read as a pair.
Built 2026-09-04 at Jerry's request: the patch link, why it matters to defenders, how few
CNAs add it. Aligns with cnascorecard.org, which scores the same tag (10 of 100 points).

Data: `processed/patch_tag.parquet` via `scripts_precompute_patch_tag.py` (raw CVE List V5
clone, published and non-rejected, by publication date, CNA container only). NVD-side tags
from `processed/nvd_ref_tags_2026.parquet` (one-off scan of `data/nvd.json`).

**Jerry's rule (2026-09-04): the chart measures the `patch` tag and nothing else.** An
earlier build drew a pale second bar for records linking a fix commit without the tag;
Jerry killed it ("I just want to measure everyone using the correct patch tag"). The
untagged-fix-link numbers survive below only as caveat material for comments.

## What the tag is
CVE JSON 5 lets a CNA tag each reference URL. The schema definition of `patch`: *"The
reference contains an update to the software that fixes the vulnerability."* It is the only
machine-readable way a record can say "the fix is here". `vendor-advisory` does not qualify
(an advisory may say there is no fix yet), which is also the rule cnascorecard.org applies.

## Finding (verified 2026-09-04 on data refreshed the same day)

**7,135 of the 59,572 CVEs published in 2026 carry a reference tagged `patch`: 12.0%.**

Of the 26 CNAs that have published 250+ CVEs in 2026 (48,859 CVEs, 82% of all volume):

| CNA | Tagged | 2026 CVEs |  | CNA | Tagged | 2026 CVEs |
|-----|-------|-------|--|-----|-------|-------|
| Microsoft | 100.0% | 1,970 | | Patchstack | 0.0% | 3,773 |
| IBM | 99.8% | 906 | | Linux | 0.0% | 5,229 |
| Erlang (EEF) | 98.5% | 259 | | Wordfence | 0.0% | 2,756 |
| CPANSec | 56.2% | 258 | | GitHub | 0.0% | 9,585 |
| VulnCheck | 29.6% | 5,491 | | Red Hat | 0.0% | 807 |
| Apache | 17.0% | 716 | | GitLab | 0.0% | 300 |
| VulDB | 15.8% | 4,532 | | Chrome | 0.0% | 2,506 |
| ICS-CERT | 0.3% | 359 | | Oracle | 0.0% | 2,442 |
| MITRE | 0.1% | 2,909 | | Adobe, Apple, Mozilla, Cisco, Dell, VMware, Joomla, TR-CERT | 0.0% | 254 to 608 each |
| WPScan | 0.1% | 985 | | | | |

Zero rows are ordered by volume on the chart (ties on 0.0% break on CVE count).

- **Three CNAs tag nearly every record**: Microsoft 1,970 of 1,970, IBM 904 of 906, the
  Erlang Ecosystem Foundation 255 of 259. Four sit in between (CPANSec, VulnCheck, Apache,
  VulDB). **Nineteen tagged five or fewer records all year; fifteen tagged none.** The four
  non-zero stragglers: MITRE 4, Patchstack 1, WPScan 1, ICS-CERT 1.
- **Caveat material, NOT on the chart:** the fix is often in the record, unlabelled.
  Linux links the exact fix commit on git.kernel.org on all 5,229 of its 2026 records and
  tags none. GitHub links a commit, pull request or compare URL on 5,167 of 9,585 (54%)
  and tags none. Wordfence links a plugins.trac.wordpress.org changeset on 60%. Use this
  to answer "but Linux DOES link the patch" in comments, never to soften the measurement.
- **NVD used to add the label, and now mostly does not.** NVD's own `Patch` reference tag
  is on 9,154 2026 CVEs (15.4%): 28.8% of the records it has Analyzed, 0% of the 20,075
  it has marked Deferred (42.5% of settled 2026 records; see the NVD deferred memory /
  BACKLOG scan). NVD tags 100% of the Linux records it analyzes as Patch, and 52% of
  GitHub's, so it has been supplying exactly the label those two CNAs omit. **CNA or NVD
  tag combined: 13,974 CVEs (23.5%). No machine-readable patch pointer from anyone:
  45,598 (76.5%).**
- **KEV-listed 2026 CVEs (141):** CNA tag 22.0%, NVD tag 26.2%, either 44.7%.
- **Adoption is rising fast, from nothing.** CNA `patch` tag share by publication year:
  2022 0.8% (197 CVEs), 2023 2.8% (815), 2024 2.2% (871), 2025 5.7% (2,742), 2026 12.0%
  (7,135). CNAs using it at least once: 11 of 201 in 2022, 78 of 367 in 2026; at 50%+:
  1 then 38. Microsoft went 47% (2024) to 99.9% (2025) to 100%; IBM 1.2% to 70.8% to 99.8%.
  Pre-2022 figures are meaningless (tags there are the JSON 4 to 5 conversion's
  `x_refsource_*` labels).
- Floor sensitivity: 100+ CVEs gives 59 CNAs (90% of volume), 5 at 90%+, 11 in between,
  43 at 1% or under; 500+ gives 16 CNAs, 2 / 3 / 11. The shape does not depend on the floor.

## LinkedIn / Mastodon
Attach: `patch_tag_portrait_<date>.png`.
```
The most useful thing in a CVE record is the link to the fix. Hardly any CNA labels it.

The CVE format lets a CNA tag a reference as "patch". That is how a tool knows which link is the fix. This year, 12% of CVEs have the tag.

I looked at the 26 CNAs that published 250 or more CVEs in 2026. Three tag nearly every record: Microsoft, IBM and the Erlang Ecosystem Foundation. Fifteen tagged none, including GitHub, Linux, Chrome, Oracle and Apple. This is about the tag, not whether a fix exists. The Linux kernel links the exact fix commit on every record and tags none of them. The link is right there. Nothing says it is the fix.

NVD adds its own Patch label to about three in ten of the CVEs it analyzes. It has marked 20,075 of this year's CVEs as Deferred, and those get nothing. Even counting both, three quarters of 2026 CVEs have no link anyone has labelled as the fix.

If you could make one field mandatory for every CVE, what would it be?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
The most useful thing in a CVE is the link to the fix. Hardly any CNA labels it.

12% of 2026 CVEs have the "patch" tag. Of 26 big CNAs, 3 tag nearly all, 15 tag none. Linux links the fix commit on every record, tags none.

If you could make one CVE field mandatory, which one?
```

## Alt text
```
Horizontal bar chart ranking 26 CVE Numbering Authorities by the share of their 2026 CVEs that carry at least one reference tagged "patch", best at the top. Microsoft 100 percent, IBM 99.8, Erlang Ecosystem Foundation 98.5, CPANSec 56.2, VulnCheck 29.6, Apache 17.0, VulDB 15.8, ICS-CERT 0.3, MITRE 0.1, WPScan 0.1, Patchstack under 0.1. Fifteen rows show no bar and read 0.0 percent: GitHub, Linux, Wordfence, Chrome, Oracle, Red Hat, Adobe, Apple, Mozilla, Cisco, Dell, GitLab, VMware, Joomla and TR-CERT. A dashed vertical line behind the bars marks the 12 percent average across all 2026 CVEs. A right-hand column headed "2026 CVEs" gives each CNA's count. Source: CVE List V5.
```

## First comment (pre-loaded, post it yourself right after the post)
```
Mine would be this tag. If your scanner shows a "fix available" link pulled from it, that link is missing on three of every four 2026 CVEs. Affected-version ranges are the other route to the fix, and six in ten records carry one, but only the tag tells a tool which link to follow.
```

## Comment ammunition
- Schema definition of `patch`, quoted above; `vendor-advisory` deliberately does not count.
- cnascorecard.org scores this exact tag as 10 of 100 points (Patch Information).
- NVD adds its own `Patch` tag on 28.8% of the 2026 records it analyzes and on none of
  the 20,075 Deferred ones. Linux: NVD tags 100% of analyzed kernel records as Patch, so
  the kernel's fix links are machine-readable only for the 2,194 records NVD got to.
- Oracle's 2,442 records all carry a `vendor-advisory` tag on the CPU page, Adobe 99%,
  Microsoft 100% (alongside `patch`). Chrome links its release blog on every record,
  untagged. Apple, Cisco, Mozilla, Linux, Wordfence tag nothing at all on any reference.
- 64% of 2026 CVEs have at least one tagged reference; GitHub's are the legacy
  `x_refsource_CONFIRM` / `x_refsource_MISC`, Patchstack's are `vdb-entry`.
- CISA ADP tags references on 7,331 2026 CVEs but uses `patch` on 8.
- On the 141 KEV-listed CVEs published in 2026, 44.7% have a patch tag from CNA or NVD.

## Review log
**Readability and voice pass 2026-09-04 (Jerry: "ridiculously hard to read", "make sure these sound like me").** Editor found the draft was not hard by grade level (5.5 vs Jerry's shipped 7.0) but churned six nouns for two ideas (tag, label, link, fix, patch, reference) and had no short sentences after paragraph two. Rewrite: 189 words, one word for the thing ("tag"), short-then-long rhythm, caveat announced plainly ("This is about the tag, not whether a fix exists"). **Jerry replaced the closing question:** the "score or the patch" forced choice dropped a term the post never introduced. Now: "If you could make one field mandatory for every CVE, what would it be?" and the first comment seeds the author's own answer.

`/post-review` run 2026-09-04 (12 personas, all completed): COPY "post with fixes", GRAPH "fix first". Blocker: the "no machine can find it" universal (false, see Traps). All should-fixes applied to copy and chart; the panel's corrected totals (48,859; 7 of 34,727; Deferred 20,075 within the non-rejected cohort) verified locally before use.

## Traps (do not ship these)
- **Never say a CNA "gives no fix" or "does not link the patch".** The metric is the
  LABEL. Oracle's CPU advisory carries the fixed versions; Chrome's release post names
  the fixed build; Linux links the literal commit. The claim is that a machine cannot tell
  which reference is the fix, not that the fix is missing.
- **The untagged fix-link figures are a heuristic, conservative by design** (commit,
  changeset, pull request, compare, patch/diff file, Gerrit) and they are NOT on the chart
  by Jerry's decision. If quoted in a comment, phrase as "links a fix commit, untagged".
- **12% is CNA-only.** The "either" figure is 23.5%; the "three quarters with nothing"
  line depends on the NVD merge and the Deferred count, both dated 2026-09-04.
- **Do not rank CNAs on "care" or "effort".** Microsoft and IBM emit the tag from a
  pipeline; Linux's omission is a template choice. Same rule as `cwe_cna_rank`: a map of
  practice, never a scorecard of intent.
- **Do not claim NVD "stopped tagging".** It still tags 28.8% of what it analyzes; the
  gap is the Deferred tier, which is policy (Apr 15 2026), not neglect.
- **"Nineteen tagged five or fewer" is exact; "nineteen tagged none" is false** (MITRE 4,
  Patchstack 1, WPScan 1, ICS-CERT 1). Fifteen at exactly zero. **The chart shows sixteen
  rows at 0.0% because Patchstack's 1 of 3,773 rounds down**; if challenged, that is the
  answer, and the copy's "fifteen tagged none" stays correct. **Chart fix 2026-09-04:**
  true zeros now draw no bar and Patchstack reads "<0.1%", so the chart shows exactly
  fifteen 0.0% rows and matches the copy.
- **Never say "no machine can find it" or "no machine-readable pointer from anyone".**
  Killed by the review panel: Linux and Microsoft carry the fixed version in
  `affected[].versions[].lessThan`, which IS the machine-readable route VM tooling uses.
  The claim is scoped to the reference LABEL: "no link that anyone has labelled as the fix".
- **Do not say "NVD used to add that label for everyone".** NVD tags Patch on 28.8% of
  the 2026 records it analyzes, about a quarter historically; never a universal.
- **"The field CNAs fill in least" is FALSE (Jerry caught it 2026-09-04).** Fill rates
  on 2026 CNA containers: mitigation tag 0.1%, configurations 0.7%, exploits 0.9%,
  release-notes tag 2.1%, workarounds 2.7%, solutions 8.2%, affected[].cpes 8.9%, then
  patch tag 12.0%. What IS true: patch is filled in far less than the fields people
  think of as the record (CVSS 79.8%, CWE 78.3%, title 80.3%, credits 43.4%), and 59.5%
  of records encode a fixed version in affected[].versions, so "where the fix is" must
  be phrased as "which link is the fix". Full table in scratchpad `fill_rates.py`.
- **Do not write "the field CNAs treat as optional".** Reads as motive, and the author's
  own `product_id` (75% no CPE/PURL) shows other fields are filled in less often than a
  reader would guess. "The field CNAs fill in least" is the checkable superlative.
- Pre-2022 trend numbers are conversion artifacts. Start any trend at 2022.

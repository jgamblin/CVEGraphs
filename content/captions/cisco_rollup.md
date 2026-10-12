# Caption — Stacked bars: Cisco CVEs that cover more than one vulnerability (`cisco_rollup`)

Image: `graphs/cisco_rollup_<ratio>_<date>.png`. House style: no em dashes.
**Status: built and rendered, not yet slotted.** Natural Tuesday (scoring/CNA-practice)
post. Answers a question asked directly: of the CVEs Cisco published in the last three
months, how many are one vulnerability and how many are a bundle.

Data: CVE List V5 raw clone via `scripts_precompute_cisco_rollup.py`, by publication
date, published and non-rejected.

## What it shows

Cisco-assigned CVEs for Cisco-branded products, by publication month, Sep 2025 through
Aug 2026 (final month partial, through Aug 19). Each bar splits three ways:

| Bucket | Meaning | Last 12 months |
|--------|---------|----------------|
| One vulnerability per CVE | "A vulnerability in ..." | 228 |
| Rollup, same bug class | "Multiple vulnerabilities in ... could allow ... an XSS attack" | 9 |
| Rollup, hardening release | one CVE per CWE bucket, count undisclosed | 27 |

## The three-month answer

Window 2026-05-27 through 2026-08-19 (the newest Cisco record in the snapshot):

- **197 CVEs carry Cisco as the assigning CNA.**
- **125 of those are Splunk-family**, not Cisco-branded. Cisco's CNA scope absorbed
  Splunk; those records keep Splunk's own house style ("In Splunk Enterprise versions
  below ...") and land in large quarterly batches. 106 of them published on 2026-08-19
  alone. They are excluded from the plotted series so the denominator means something.
- **72 are Cisco-branded.** Of those, **27 are rollups (38%)** and 45 are one bug each.
- Counted from 2026-07-15, when the hardening program starts, it is **27 of 54, exactly
  half**.

## The mechanism, which is the actual finding

Cisco began a "Security Hardening Release" program on 2026-07-15. An engineering team
runs an internal review, and every weakness class it turned up gets exactly one CVE.
The record says so in as many words:

> The vulnerabilities tracked by CVE-2026-20313 are related to Improper link resolution
> before file access issues that are grouped under the Common Weakness Enumeration (CWE)
> CWE-1284.

Plural vulnerabilities, singular CVE, no count. Five advisories so far:

| Advisory | Product | Rollup CVEs | Published |
|----------|---------|-------------|-----------|
| `cisco-sa-hardening-roomos-AqNMbEq` | RoomOS | 6 | 2026-07-15 |
| `cisco-sa-hardening-iosxe-V8NMuMZJ` | IOS XE | 7 | 2026-08-05 |
| `cisco-sa-hardening-sdwan-faLcR3K` | Catalyst SD-WAN | 5 | 2026-08-05 |
| `cisco-sa-hardening-crosswork-UzDTU9Vh` | Crosswork | 4 | 2026-08-19 |
| `cisco-sa-hardening-csw1-shSvndWP` | Secure Workload | 5 | 2026-08-19 |

The CWE buckets used are mostly pillars and other very high-level classes: CWE-20
(input validation) four times, CWE-284 (access control) four times, CWE-119 three
times, then CWE-74, CWE-664, CWE-703, CWE-691, CWE-682, CWE-1284, CWE-59, CWE-89,
CWE-73, CWE-522, CWE-311, CWE-287, CWE-306, CWE-312. Picking the bucket coarse is what
lets one ID absorb an arbitrary number of findings.

**Every one of the 27 is High or Critical**: 13 Critical, 14 High, scores from 7.5 to
10.0, median 8.8, with five sitting at a flat 10.0. That score is necessarily the worst
bug in the bucket, so a 10.0 rollup may be one 10.0 next to several 5s, and nothing in
the record distinguishes those cases.

## Why no vulnerability count is plotted

Because there isn't one. Neither CVE List V5 nor NVD has a field for "how many
vulnerabilities does this CVE cover." Cisco declares the rollup in prose and stops
there. Any number put on the chart would have to be inferred from CWE breadth or
affected-product count, which would be inventing data. The chart counts CVE IDs and
says the rest in the footnote. **Do not add an estimated bug count to this chart.**

That is also why the classifier reads description text rather than a structured field.
It keys on the literal boilerplate `ongoing commitment to proactive security` for the
hardening bucket and on a `Multiple|Two|Three|Several vulnerabilit...` opener for the
classic bucket. If Cisco rewords the template the classifier goes quiet rather than
wrong, which is the failure direction to prefer, but check it before reposting.

## Post copy (draft)

> A CVE ID is supposed to identify one vulnerability. Cisco has decided that is
> optional.
>
> Since July 15 Cisco has shipped five "Security Hardening Release" advisories. Every
> weakness class an internal review turned up gets exactly one CVE, and the record says
> it plainly: "the vulnerabilities tracked by CVE-2026-20313 are ... grouped under CWE-1284."
> Plural bugs, singular ID, and no count anywhere. That is 27 CVEs in five weeks, half
> of everything Cisco published for its own products in that stretch. All 27 are High or
> Critical. Five are a flat 10.0.
>
> The scoring is the part that should bother you. A rollup's CVSS is the worst bug in
> the bucket, so a 10.0 here might be one genuine 10.0 sitting on top of a pile of 5s,
> and you cannot tell from the record which you are looking at. You cannot count these,
> you cannot prioritise inside them, and there is no CVE or NVD field that would let you.
> The fix is real, though: it is "upgrade to the hardening release," not "patch this bug."

## Notes / caveats
- The Splunk split was validated independently of the text classifier: **all 125
  Splunk-family records in the window reference a `advisory.splunk.com` advisory and
  none reference a `cisco-sa` one**, while every Cisco-branded record does the reverse.
  Prose bucket and reference host agree completely, so no Cisco-branded record is being
  hidden in the excluded bucket. (One record titled for the Cisco Talos Intelligence app
  is correctly Splunk-family: it is a Splunk Enterprise Security add-on, disclosed on a
  Splunk advisory.)
- **Splunk-family records are excluded** from the plotted series and the 38% figure.
  Include them and the rollup share falls to 14% of 197, which measures Splunk's release
  calendar rather than Cisco's disclosure practice. Say which denominator is in use.
- ClamAV records are **included**: Cisco assigns them, they use Cisco's phrasing, and
  they are one bug per CVE. Two ClamAV advisories carried seven CVEs each in the window.
- The classic same-bug-class rollup is not new and is not the story. Nine in twelve
  months, none at all inside the three-month window. It is on the chart for contrast.
- Advisory-level bundling is a different thing from a rollup CVE and is not plotted:
  57 advisories carried the window's 197 CVEs, the largest being Splunk's SVD-2026-0801
  with 60. One advisory covering many CVEs is normal and fine. One CVE covering many
  bugs is not.
- The March 2026 spike of 60 is ordinary Cisco advisory volume, not a bundling event.
- Aug 2026 is partial; the axis labels it "Aug MTD" and the footnote repeats it.
- **Data current as of 2026-08-19** for Cisco records, from a cvelistV5 clone last
  pulled 2026-08-27. The main `processed/` parquet is a week older and does not contain
  the 2026-08-19 batch, which is why this chart reads the raw clone through its own
  precompute rather than `load_cvelist()`.
- Rebuilt against the 2026-08-27 clone and the output is byte-identical to the 08-26
  run: same 915 Cisco records, same bucket split, no CVE added, removed or reclassified.
  Cisco's newest record is still 2026-08-19, so **every figure here is unchanged**. The
  in-repo `data/cvelistV5` clone was a day behind at that point; the rebuild used
  `CVEGRAPHS_CVELIST_DIR=~/Data/cvelistV5`, which the precompute now accepts so an
  external clone can drive it without a full `refresh_data.py` run.

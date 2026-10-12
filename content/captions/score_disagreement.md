# Caption — Agreement plot: same CVE, two official CVSS scores (`score_disagreement`)

Image: `graphs/score_disagreement_<ratio>_<date>.png`. House style: no em dashes.
The verdict post of the scoring series: cna_spread compared different bugs
across CNAs, scorer_divergence compared versions within one scorer; this holds
the bug constant and varies only the scorer. The cna_spread post (shipped
Jul 9) ended on "when a CVE carries two different CVSS scores, which one does
your program actually use?"; the scorer_divergence caption carries the same
closer but that post never shipped per the CALENDAR log, so the copy must not
say "twice". Data: `processed/score_pairs.parquet` via
`scripts_precompute_score_pairs.py` (NVD mirror, CVSS v3 base scores, CVEs
published in 2026).

Finding (refreshed 2026-08-18, post day): 5,564 CVEs published in 2026 carry
a v3 score from their own CNA and a second official score from NVD. Exact
match 10.8% (one decimal keeps the on-canvas partition honest: 62.6 + 26.5 +
10.8 = 99.9, pure rounding); 55% land in different severity bands; 35% differ
by 2.0+ points; NVD higher on 62.6% of pairs, CNA higher on 26.5%; 1,043 CVEs
are Critical to exactly one of their two scorers, including 188 the CNA
called Medium that NVD called Critical. The split is in impact,
not exploitability: among disagreeing pairs, availability/confidentiality/
integrity each differ in 34-39% of vectors while attack vector differs in 8%
and user interaction 12%. The largest single band-flipped pair is CNA 7.3 vs
NVD 9.8, shared by 237 CVEs (called out in red on the chart); CVE-2026-2172
is the named example, identical exploitability metrics, L/L/L vs H/H/H impact.

Caveats to carry:
- **Selection, not a random sample.** Pairs exist only where NVD re-scored:
  11.8% of 2026's v3-scored CVEs. NVD's enrichment backlog decides which
  records get a second score, so the pair population over-represents the CNAs
  NVD prioritizes. Do not generalize "56% of ALL CVEs would flip".
- **Not one weird CNA, but not uniform either.** Excluding GitHub and VulDB
  (the two biggest pair populations) the flip rate is still 49% (48.52%,
  rounds up). Per-CNA flip
  rates run from 37% (VulnCheck, Microsoft) to 86% (VulDB, median gap +2.5,
  consistent with cna_spread's finding that VulDB scores low).
- **Part of the gap is policy, conditionally.** NVD documents that WHEN a
  record lacks detail it scores the worst-case interpretation; it does not
  use the phrase "reasonable worst case" and the policy is not unconditional.
  The copy states it with the "when a record lacks detail" qualifier. The
  named exemplar pair (7.3 vs 9.8) is 94% VulDB records (222 of 237), so the
  copy names VulDB and lets the drop-GitHub-and-VulDB 49% line carry the
  "not one CNA's quirk" claim honestly.
- **CISA-ADP second scores are excluded**: 90% duplicate the CNA's score
  exactly (enrichment, not re-assessment). Stated in the chart footnote.
- 19 placeholder 0.0 scores (all-None vectors) excluded. 1.9% of pairs mix
  v3.0 and v3.1; the base formula is the same.
- Scores come from NVD's mirror; the CNA-side score is the metric whose
  source equals the record's owning CNA.

## LinkedIn / Mastodon
Attach: `score_disagreement_square_<date>.png`.
```
CVSS looks like a measurement, but it fails the first test of one: two people measuring the same thing should get roughly the same answer.

So far in 2026, 5,564 published CVEs carry two official CVSS scores: one from the CNA that published the record and one from NVD. The scores match exactly 10.8% of the time, and 55% of the time they do not even land in the same severity band. 1,043 of these CVEs are Critical to exactly one of their two scorers. If your triage keys on severity bands, the feed you pull decides the queue for half of the CVEs both feeds have scored. (That is the slice NVD has re-scored so far, about 12% of 2026's v3-scored CVEs.)

CVE-2026-2172 is the pattern in one record: VulDB scored it 7.3, NVD scored it 9.8, identical exploitability, opposite call on impact, and 236 other CVEs this year sit on that exact pair. Policy drives it from both sides. NVD documents that it scores the worst case when a record lacks detail, while CNAs like VulDB default unknowns down instead of up. But policy does not tell you which score belongs in your queue, and it is not one CNA's quirk: drop GitHub and VulDB entirely and the band-flip rate is still 49%. For a lot of teams, which feed that is was a scanner default rather than a choice. Which one does yours key on, CNA or NVD? I'd genuinely like to hear how teams picked, because I suspect most of us inherited the default.

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
Attach: `score_disagreement_wide_<date>.png`.
```
CVSS fails the first test of a measurement: two people scoring the same bug should get roughly the same answer.

5,564 CVEs published in 2026 carry two official CVSS scores, the CNA's and NVD's (the roughly 12% of 2026's v3-scored CVEs NVD has re-scored so far). 55% land in different severity bands; they match exactly just 10.8% of the time. 1,043 are Critical to exactly one of their two scorers.

Which feed does your queue key on, and did anyone pick it on purpose? I'd bet most of us inherited the default.
```

## Alt text
```
Scatter plot titled "Same CVE, Two Official CVSS Scores". Each dot is one of
5,564 CVEs published in 2026 that were scored by both their own CNA (x axis)
and NVD (y axis); dot area is proportional to how many CVEs share that score
pair. A dashed diagonal labeled "scores agree" marks perfect agreement, and
four light shaded squares stepping up the diagonal carry watermark band
names (LOW, MEDIUM, HIGH, CRITICAL) where both scorers land in the same
band. Light grey dots (same severity band) hug the diagonal; navy dots
(different severity band) spread widely on both sides and make up 55% of
pairs. Corner notes read "NVD scores higher, 62.6% of pairs" (top left) and
"CNA scores higher, 26.5% of pairs" (bottom right). A red dot marks the
largest band-flipped pair, explained in a key strip below the plot: 237
CVEs scored 7.3 (High) by their CNA and 9.8 (Critical) by NVD. The strip
also holds the class legend and a dot-size key for 1, 50, and 237 CVEs.
Only 10.8% of score pairs match exactly. The wide version moves these keys
into a left rail with three large stats: 10.8% exact score match, 55%
different severity band, 1,043 Critical to only one scorer.
```

## Notes (comment ammunition, do not put in the body)
- **"GitHub covers CWE well but flips 51% here" / coverage-vs-agreement
  pre-empt:** cwe_cna_rank measured whether a CNA fills a field in; this
  measures whether two scorers make the same judgment call. A CNA can be
  diligent about coverage and still disagree with NVD on impact. Different
  axes, no contradiction.
- **July reconciliation, paste-ready if someone cites the cvss_v4_adoption
  post:** "That July post compared the same author's score across two feeds,
  which measures extraction fidelity. This chart compares two different
  authors scoring the same bug, which measures judgment. Both can be true:
  the pipeline copies scores faithfully, and the scorers disagree."
- **"It's just boundary rounding" rebuttal:** only 1.6% of band flips are
  within 0.5 points of each other; the median gap among flipped pairs is 2.2
  points. These are not 6.9-vs-7.0 technicalities.
- 35% of all pairs differ by 2.0 or more points.
- Per-CNA flip rates (comment use, Aug 18 data): VulnCheck 37%, Microsoft
  37%, GitHub 51%, Red Hat 54%, IBM 54%, MITRE 59%, VulDB 86%.
- The scores agree on the vector's exploitability half far more than impact:
  AV 8%, UI 12%, Scope 19%, PR 22%, AC 24% vs C 36%, I 34%, A 39% (share of
  disagreeing pairs where that metric differs).

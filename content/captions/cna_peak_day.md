# Caption: each CNA's biggest single publishing day (`cna_peak_day`, companion `cna_top_days`)

Image: `graphs/cna_peak_day_<ratio>_<date>.png` (primary) and
`graphs/cna_top_days_<ratio>_<date>.png` (companion). House style: no em dashes; no "n=";
factual Title-Case heading; one-line subtitle; one footnote (source + as-of); post-date
stamp. Built 2026-09-15 at Jerry's request ("top publishing day by CNA, and where Oracle
and Microsoft rank this week"). Volume lane, so **milestone-only, off the Tue/Thu
template**. The trigger is Oracle's third 600-plus third-Tuesday batch in a row (634 on
Sep 15). `/post-review` run 2026-09-16 (12 personas): COPY "rework", GRAPH "fix first"; every
blocker and should-fix applied same day (see review log at the bottom). Not yet posted; log
it in CALENDAR only when Jerry confirms.

Data: `data.load_cvelist()` (CVE List V5), non-rejected, de-duplicated by CVE id, grouped
by `assigner_short_name` and the UTC calendar day of CVE.org publication, 2017 to date
(pre-2017 is MITRE sole-assigner backfill). Refreshed 2026-09-15 (newest record
22:39 UTC) and again 2026-09-16 after the review: 634, 965 and every rank unchanged. `charts/cna_peak_day.py:stats()` and `charts/cna_top_days.py:stats()` print
every figure below, so the copy never retypes them from the image.

## Two charts, one table
- **`cna_peak_day` (primary):** one bar per CNA, its record single day. 486 CNAs ranked,
  top 15 shown. Oracle #1 (1,097 on Jul 21, 2026), Microsoft #2 (965 on Sep 8, 2026),
  Linux kernel #3 (845 on Aug 15, 2026), ZDI #4 (709 on May 3, 2024), Chrome #5 (427 on
  Jun 4, 2026). Five of the 15 records were set in 2026.
- **`cna_top_days` (companion):** one bar per CNA-day, so a CNA can repeat. Plain navy,
  no highlight (Jerry, 2026-09-15: the rank labels and dates carry the reading). Three of
  the top nine are from Sep 8 to 15: Microsoft 965 on Sep 8 (#2 all time), Oracle 634 on
  Sep 15 (#7), Linux 431 on Sep 11 (#9). Oracle holds three of the top seven (1,097
  Jul 21; 889 Aug 18; 634 Sep 15).

## Verified figures (all from the 2026-09-15 snapshot)
| Figure | Value |
|---|---|
| Oracle's record day | 1,097 on Jul 21, 2026 (#1 of 486 CNAs) |
| Microsoft's record day | 965 on Sep 8, 2026 (#2); prior Microsoft high 570 on Jul 14, 2026 |
| Previous all-time single-CNA record | ZDI 709 on May 3, 2024; stood until Jul 21, 2026 |
| Oracle's biggest day, 2017 to May 2026 | 244 on Aug 8, 2017 |
| Oracle quarterly days over 100 CVEs, 2024 to 2025 | 1 of 8 (133 on Apr 16, 2024) |
| Oracle's three third-Tuesday batches | 1,097 (Jul 21) + 889 (Aug 18) + 634 (Sep 15) = 2,620 |
| Oracle CVEs by year | 2023: 295; 2024: 370; 2025: 314; 2026 to date: 3,076 |
| Single-CNA days of 300+ CVEs | 8 in all of 2017 to 2025; 15 so far in 2026 |
| Sep 8 Microsoft count | 955 in the same-day snapshot, 965 now (ten records landed 18:00 to 18:39 UTC) |
| Oracle advisory behind each batch (CVE reference URLs, raw CVE List V5 JSON) | May 28: 26 CVEs to `cspumay2026`; Jun 16: 240 to `cspujun2026`; Jul 21: 1,096 to `cpujul2026` (quarterly CPU) plus 1 to `cspuaug2026`; Aug 18: 889 to `cspuaug2026`; Sep 15: 631 to `cspusep2026` plus 3 to the open-source CVE page |
| Oracle's own description (cspusep2026.html, read 2026-09-16) | "Critical Security Patch Updates complement Oracle's existing quarterly cumulative Critical Patch Updates (CPUs)"; the September CSPU "contains 673 new security patches" |

## LinkedIn / Mastodon
Attach: `cna_peak_day_wide_<date>.png`, or post both images with `cna_top_days` second.
```
A 1,000-CVE day is a scheduling decision, not a security event.

Oracle's 1,097 on July 21 and Microsoft's 965 on the September 8 Patch Tuesday are the two biggest single-CNA publishing days on record, both set in the last two months. The previous mark, ZDI's 709 from May 2024, had stood for more than two years.

The chart ranks 486 CNAs by their biggest day, and Oracle's bar is the one with a calendar behind it. In 2024 and 2025 its quarterly batches ran 43 to 133 CVEs. Since May, Oracle has published a Critical Security Patch Update in the months between its quarterly Critical Patch Updates, and every off-cycle CVE links to one of those advisories: 240 in June, 889 in August, 634 on September 15, with the regular quarterly 1,097 in July between them. That's 2,620 CVEs in three months from a CNA that published 314 in all of 2025.

None of this is hidden; each batch has its own advisory page. The work moved to the reader: a CPU-sized batch now lands on the third Tuesday every month, one week after Microsoft's.

Oracle shops: are you folding the monthly batch into the Patch Tuesday window a week later, or holding it for the October 20 Critical Patch Update?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
Under 300 characters for Bluesky; count before posting.
```
A 1,000-CVE day is a scheduling decision, not a security event.

Oracle now ships a Critical Security Patch Update between its quarterly CPUs: 889 in August, 634 on Sep 15, plus July's 1,097 quarterly. 2,620 CVEs in three months vs 314 in 2025.

Oracle shops: monthly cycle now, or hold for Oct 20?
```

## Alt text
```
Horizontal bar chart titled "Each CNA's Biggest Single Publishing Day", ranking 15 CNAs by
the most CVEs each published on one calendar day since 2017. Oracle leads with 1,097 on
Jul 21, 2026 and Microsoft is second with 965 on Sep 8, 2026, both in dark navy. Inside
Oracle's bar a note reads "then 889 on Aug 18 and 634 on Sep 15". Then Linux Kernel 845,
ZDI 709, Chrome 427, MITRE 363, Mozilla 318, Patchstack 309, huntr 298, Android 262,
Adobe 253, Apple 245, Qualcomm 229, WPScan 203 and HackerOne 192 in pale blue.
Source: CVE List V5, data as of Sep 15, 2026.
```

## Notes / caveats
- **634 is a floor.** Oracle's Sep 15 batch ran 19:56 to 21:53 UTC and the snapshot is
  22:39 UTC the same day. Microsoft's Sep 8 count rose from 955 to 965 between the
  same-day and the one-week-later snapshots, so expect a small upward revision. Re-run
  `stats()` before posting and update the copy if the number moved.
- **Why Oracle changed is public, so say it.** The first draft said "I don't know what
  changed inside Oracle, and the CVE records don't say." The review checked the raw
  records and that was wrong: every off-cycle CVE references a Critical Security Patch
  Update advisory (`cspumay2026`, `cspujun2026`, `cspuaug2026`, `cspusep2026`), a program
  Oracle describes on those pages as complementing the quarterly CPUs. Jul 21 is the
  ordinary quarterly `cpujul2026`. The copy now credits the program and frames the
  consequence (the work moved to the reader). Do not revert to the mystery framing; the
  audience has been applying CSPUs since May. Cadence claim ("third Tuesday every
  month") is the observed pattern May to Sep, not an Oracle statement; Oracle's page says
  "complement", not "monthly". The CPU calendar stays quarterly (next: Oct 20).
- **Patches are not CVEs.** Oracle's September CSPU page says 673 security patches; the
  CVE count for the day is 634 (631 to the CSPU page). Quote the CVE count in the copy.
- **Oracle 2026 total (3,076) is 9.8x its 2025 total (314).** Fine for a comment; the post
  uses the three-batch sum (2,620) because that is the observable event.
- Baseline is scoped to 2024 and 2025 on purpose: those eight quarterly days ran 43 to
  133. The first draft said Oracle's big days "rarely cleared 100", which the chart's own
  2017 window contradicts (2017 to 2021 CPUs all cleared 100; 244 on Aug 8, 2017).
- Per-CNA "record" ties resolve to the earliest day. None of the top 15 are tied.
- Modern-era cut starts 2017 to exclude MITRE's sole-assigner bulk loads (up to 480 a day
  in 2001 to 2005). Same cut as `cna_burst`.
- The companion chart had a "since Patch Tuesday" highlight in its first build; Jerry cut
  it the same day. Its `stats()` still reports which top-15 bars fall in the last 7 days.
- Relationship to shipped charts: `patch_tuesday` (Sep 8) covered the 955 in depth;
  `cna_burst` (Jul) is the CNA-day ranking colored by era. This chart's new fact is the
  per-CNA table plus Oracle's third batch. Do not re-argue the memory-safety finding here.
- Pre-loaded first comment for the "you said 955 last week" reply: "Last week's post said
  955. Ten more Microsoft records landed later on Sep 8, so the day closed at 965."
- Re-run `refresh_data.py` and `charts/cna_peak_day.py` (prints `stats()`) the morning of
  posting. If 634 or 965 moved, update the copy, the table above and the alt text.

## Review log (2026-09-16, `/post-review`, 12 personas)
COPY: rework. GRAPH: fix first. Applied same day:
- Blocker: "I don't know what changed" replaced with credit-then-consequence naming the
  CSPU program (verified in raw CVE List V5 references and on oracle.com).
- Should-fix: baseline scoped to 2024 to 2025 (43 to 133); dates pinned ("634 on
  September 15", "the September 8 Patch Tuesday"); paragraph 2 collapsed to the two
  records plus the prior mark; new closing question without "still" or jargon; X copy
  under 300 characters.
- Graph: legend dropped (navy on the two rows already carries the highlight); one white
  in-bar note under Oracle's record ("then 889 on Aug 18 and 634 on Sep 15", computed
  in `_follow_on()`); header-to-plot gap widened; "Linux Kernel" Title Case; axis ticks
  with thousands separators; re-rendered with the post-date stamp.
- Dismissed (editor's call): swapping the primary image for an Oracle timeline; adding a
  Microsoft-vs-median figure (patch_tuesday shipped it); removing the axis or the rank
  prefixes; calling the 314 baseline a cherry-pick.

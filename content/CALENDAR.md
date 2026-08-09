# Posting calendar

Cadence: **2 posts/week. Hard cap — do not exceed.** Mid-morning US Eastern.
House style: no em dashes. End each post with a question to drive comments.

> **Why the cap:** the Jul 2026 engagement pull showed cadence is not the lever,
> lane is. Contested scoring/exploitation posts pull 2,000-3,500 impressions and
> 8-17 comments; pure-volume posts (daily_rate 497) are near-noise. Daily also
> trains the audience to skim. Two sharp, argument-driven posts beat five fillers.
> "Post daily to build an audience" is algorithmic-feed advice; it does not fit a
> data-expert franchise. If tempted to post a third in a week, hold it for next
> week or fold it into a deep-dive.

## Weekly template
Two CVE Insights chart posts (Tue + Thu), leading with the proven lanes. Volume is
**milestone-only**, never a scheduled slot. Wednesday is reserved for Empirical/work
posts, which sit outside this chart cadence and do NOT count against the 2/week cap.

| Day | Slot | Lead lane | Notes |
|-----|------|-----------|-------|
| Tue | Scoring / measurement | cna_spread · cna_metric_table · scorer_divergence · ridgeline · cwe_spread | The "CVSS is an opinion" franchise; highest comments/reposts |
| Wed | Empirical / work | (not a chart) | Company/research posts; separate audience-job from the chart franchise |
| Thu | Exploitation | kev · kev_severity · kev_timing · exploited_cwe · cwe_kev · waffle_exploit | What actually gets exploited vs what you'd expect |

## Rotation queue
Cycle within each lane so no chart repeats too soon:
- **Tue (scoring):** cna_spread → scorer_divergence → cwe_spread → ridgeline → cna_metric_table → (repeat)
- **Thu (exploitation):** kev_severity → exploited_cwe → kev_timing → cwe_kev → waffle_exploit → (repeat)

## Copy & angle playbook (what actually drives reach)
Reach is decided by the post copy more than the chart. Full rules in `content/INSIGHTS.md`
(Copy formula). The essentials:
- **Open on a one-sentence opinion, not a stat.** Line one is an arguable claim; the
  number is line two. Opinion-first posts pulled 2-3.5k impressions with many comments;
  number-first ones pulled about half and near-zero comments.
- **End on a genuine, varied question.** It is the comment engine; never drop it, never
  reuse a formula ("how does your pipeline handle X?").
- **Track reposts + comments**, not impressions/reactions, as the success metric.
- **Authority + stakes play:** periodically pair a chart with an outside authority's
  warning ("even \[credible outsider\] is saying X"). The Jul 2026 JP Morgan post did this
  and outran every chart (12 reposts). Never manufacture alarm the data does not support.
- **Format experiment:** try a native document/carousel for one data story. LinkedIn
  favors it, and the top performer of the period used it.

## Off-cadence (does NOT count against the 2/week cap only if genuinely newsworthy)
Milestone/volume posts (pace, daily_rate, two_year_overtake, calendar_heatmap) and
one-off curios (foxit_batch) are **milestone-triggered**, not scheduled. A big KEV
week can still warrant a same-day exploitation post, but that replaces the Thu slot,
it does not add a third.

## Queued / held (keep this current so holds are visible before they collide)
A chart claiming a future date must be listed here. `second_burst` was held for Tue Aug 4 2026
inside its own caption file and nowhere else, which double-booked the day with `camp_week`.

| Chart | Claimed date | Status |
|-------|--------------|--------|
| second_burst | (was Tue Aug 4 2026) | **Shelved.** Lost the slot to camp_week on perishability. Its own caption flags the "counts measure publishing, not risk" lane as saturated; do not hand it Thursday. |
| cwe_kev | Thu Aug 6 2026 | Next in the Thu exploitation rotation after kev_timing (Jul 14). Exploitation has been dark three weeks; hard-commit this. |
| credit_rise | unclaimed | Rendered, uncaptioned. |
| yoy_month_growth | unclaimed | Rendered, captioned. |

## Off-schedule triggers
- **Milestone** — fire a milestone card when a round number lands (e.g. all-time
  catalog crosses 350,000; H1 crosses 40,000).
- **Big KEV week** — an unusually large batch of KEV additions warrants a same-day post.

## Log
Newest first. Dates are posting dates (from LinkedIn relative timestamps). Impressions
and engagement are a snapshot **refreshed 2026-07-25** from post analytics on the
recent-activity page; they keep growing, so treat them as point-in-time. Reposts of
others' content are omitted. A few high-performing non-chart posts are included and
marked (non-chart) for performance comparison.

| Date | Chart | Platforms | Impressions | Engagement | Notes |
|------|-------|-----------|-------------|------------|-------|
| 2026-08-04 | camp_week | LI | | | "CVE Volume in Hacker Summer Camp Week"; ten years of Black Hat / DEF CON weeks vs the twelve weeks around each. **A null result, posted on purpose:** median year 10% below its typical week but half the years between 22% below and 30% above, average rank 6.3 of 13 against 7.0 for a random week (permutation p = 0.59). No severity or KEV shift either. Volume/calendar lane, off-cadence, **consumes the Tue slot on perishability** (only postable during camp week). **Slot conflict: `second_burst` was held for today (see its caption line 88); shelved, not moved to Thu.** Review panel forced two rebuilds: the small-multiples bar grid could not draw its own effect (2-5px), and sign-coloured delta labels faded exactly the four years that contradict the folklore. Now a strip plot; red tents break the palette by design. |
| 2026-07-30 | (AI Summit carousel) | LI | | | **(non-chart, document/carousel)** "A Bigger Map Is Not a Bigger Territory": 13-page LinkedIn-native PDF from the CVE Program AI Summit talk, same day as the talk. Naming/vocabulary lane, opinion-first hook ("vulnpocalypse has done more damage than most of the CVEs it was coined to describe"). Built portrait 4:5 dark, with the two talk charts rebuilt from live data; builder at Talks/AISummit/build_li_carousel.py. Full review panel run: **caught that the growth chart stopped at 2025, the only cutoff where its story holds** (T12M to Jul 2026 = CVEs 10.1x vs CNAs 10.4x, reversal), so slides 7 and 11 now concede 2026 may break the frame. [LinkedIn](https://www.linkedin.com/feed/update/urn:li:ugcPost:7488633132674363393/) |
| 2026-07-28 | cvss_epss_scatter | LI | | | "Severity vs Exploitation Ranking, 2026 Critical CVEs"; 4,719 CVSS v3 9.0+, half (2,493) identical 9.8, only nine distinct scores in the band; EPSS percentile median 37th, top decile holds 49 of the 54 on KEV. Scoring lane (Tuesday). **First post under the new opinion-first copy rule** (line one arguable, number line two). Four review rounds; chart went raw-EPSS+danger-band → log → percentile after Jay's anti-EPSS feedback. [LinkedIn](https://www.linkedin.com/feed/update/urn:li:share:7487873970999009280/) |
| 2026-07-24 | (JP Morgan) | LI | 2,980 | 47 react · 4 comments · 12 reposts | **(non-chart) Top performer of the period.** Document/carousel post "Patchmageddon": J.P. Morgan warning on exploitation of a massive unpatched surface. Snuck in off-schedule; commentary on someone else's report, not a CVEGraphs chart. 12 reposts is the standout signal. |
| 2026-07-22 | cna_burst | LI | 1,294 | 34 react · 1 repost | "The Biggest Single-Day CVE Batches by a CNA"; **Oracle set an all-time record: 1,097 CVEs in one day (Jul 21, its July CPU)**, ~55% over the prior record (ZDI 709); half the modern top 10 are from 2026. Volume/CNA-milestone, posted off-cadence. Underperformed vs the record hook (no comments); the record chart traveled less than the JP Morgan commentary. [LinkedIn](https://www.linkedin.com/feed/update/urn:li:share:7485710704637915136/) |
| 2026-07-21 | cvss_v4_adoption | LI | 1,249 | 31 react · 1 comment · 1 repost | "CVSS v4 Score Coverage by Year"; v4 up to 34.5% of 2026 CVEs but 71% is 3 CNAs (VulnCheck/VulDB/GitHub), and same-scorer v4-v3 nets to ~0; scoring lane (Tuesday). Two post-review rounds. Softer than the earlier scoring posts (cna_spread/ridgeline); denser/more caveated copy may have cost engagement. [LinkedIn](https://www.linkedin.com/posts/jgamblin_a-third-of-2026-cves-so-far-carry-a-cvss-share-7485328186415702016-61G0/) |
| 2026-07-16 | two_year_overtake | LI | 1,071 | 33 react · 1 comment · 3 reposts | "When a Year Overtakes Two Years Ago"; 2026 passed all of 2024 (39,952) on Jul 16, earliest in the modern series; volume lane. **First post under the "CVE Insights" brand** (eyebrow rename). |
| 2026-07-15 | daily_rate | LI | 497 | 7 react · 2 reposts | "CVEs Published Per Day in 2026"; 7-day rolling avg, ~203/day vs 132 in 2025; volume lane. **First post in the new Empirical-aligned house style** (Host Grotesk / Roboto / navy accent). [LinkedIn](https://www.linkedin.com/posts/jgamblin_vulnerabilitymanagement-cybersecurity-cve-share-7483152098591731712-M-FS/) |
| 2026-07-14 | kev_timing | LI | 1,388 | 34 react · 4 comments · 2 reposts | "How Old CVEs Are When CISA Adds Them to KEV"; age-at-KEV, fresh-plus-ancient-tail; exploitation lane |
| 2026-07-13 | product_id | LI · X | 2,086 | 18 react · 10 comments · 1 repost | "How 2026 CVEs Identify the Affected Product"; PURL failed to launch in the CVE/NVD pipeline (2%, no enrichment backfill); data-quality lane |
| 2026-07-12 | foxit_batch | LI | 554 | 8 react · 2 comments | Sunday curio; routine 2026.1.2 release, memory-safety batch |
| 2026-07-11 | kev_severity | LI | 2,778 | 61 react · 8 comments · 5 reposts | "How severe are the bugs that actually get exploited?" |
| 2026-07-11 | exploited_cwe | LI | 2,511 | 51 react · 10 comments · 5 reposts | "The bugs that get exploited are not the ones you see most"; Sasha Romanosky commented |
| 2026-07-10 | cwe_spread | LI | 1,022 | 22 react · 3 comments · 4 reposts | "Stop triaging by bug class" |
| 2026-07-09 | cna_spread | LI | 3,494 | 56 react · 17 comments · 5 reposts | **Top performer.** XSS CVSS spread by CNA; "opinion with a decimal point" |
| 2026-07-08 | ridgeline_severity | LI | 2,065 | 38 react · 11 comments · 1 repost | "How severe are CVEs, year by year?"; v3 vs v4, led to the v4 data fix |
| 2026-07-07 | cna_bump | LI | 1,397 | 24 react · 1 comment · 4 reposts | "GitHub and MITRE trade places" |
| 2026-07-06 | chrome_day | LI | 1,328 | 23 react · 4 comments · 1 repost | "Out with Patch Tuesday, in with Chrome Day" |

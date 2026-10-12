# Caption: Two panels, GitHub's advisory surge, output and catch-up (`ghsa_output`)

Image: `graphs/ghsa_output_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. CNA-volume lane. Copy drafted against
`~/Documents/Github/Blogs/humanize.md`. **Not scheduled; not yet through `/post-review`.**
Scope set by Jerry 2026-09-28: **GitHub's acceleration only. No other-CNA comparison in the
chart or the post.** Both panels are GitHub's own work.

Built 2026-09-28 in response to GitHub's post "Inside the Advisory Database and what
happens when vulnerability volume breaks records" (github.blog, supply-chain-security).
Data: `processed/ghsa_reviewed.parquet` from `scripts_precompute_ghsa_reviewed.py` (sparse
clone of `github/advisory-database`, reviewed tree only, commit ba52c14360, 2026-09-28
12:37 UTC) joined to `processed/cvelist_v5.parquet` (refreshed 2026-09-28, newest record
13:50 UTC). Newest review in the snapshot: Fri Sep 25 21:48 UTC. Numbers:
`python -c "from charts import ghsa_output as g; print(g.stats())"`.

**Attach the SQUARE.** Both panels and all 2026 labels read at phone width.

## What GitHub said (their numbers, not ours)
- 1,560 reviewed advisories in May 2026, "five times" typical, the highest in the database's
  history; about 270/month two years earlier.
- "More than 6,000 advisory decisions per month" March to May (includes rejections the
  database does not show).
- Private vulnerability reports about 550/week in January to 3,000+/week by May; repository
  advisories about 650/week to 5,000+/week; almost 4,000 CVE requests in May, "nearly 10x"
  year over year.
- Delays from mid-April, "first to about a week, then to multiple weeks for a meaningful
  share". Response: triage changes, more curation backend capacity, AI-assisted research
  tools, more automation.

## Finding (verified 2026-09-28)

| Month | Reviewed | vs 2025 avg | GitHub-CNA advisories | CVE record >7 days late |
|---|---|---|---|---|
| Jan 2026 | 497 | 1.4x | 309 | 1.3% |
| Feb | 784 | 2.2x | 459 | 0.4% |
| Mar | 1,615 | 4.6x | 923 | 0.8% |
| Apr | 1,493 | 4.3x | 861 | 19.2% |
| May | 1,608 | 4.6x | 1,006 | **58.7%** |
| Jun | 1,438 | 4.1x | 878 | 54.1% |
| Jul | 1,455 | 4.2x | 770 | 44.8% |
| Aug | 878 | 2.5x | 522 | 14.2% |
| Sep* | 1,049 | 3.0x | 563 | **2.1%** |

- **Top panel.** 2025 average **350 a month** (range 226 to 500). **March to July 2026: 1,522 a
  month, 4.3x, every month above 1,400.** \*September through the 25th: 1,049 in 19 of 22
  weekdays, **about 1,200 on a full-month pace (3.5x).**
- **Bottom panel.** Of reviewed advisories whose CVE GitHub assigned (GitHub_M), the share
  whose CVE record reached CVE List V5 more than 7 days after the advisory. 2025 ran 0% to
  5.4% every month. Same-day is the norm: the repo advisory and the CVE record normally go
  out together.
- **Late rule, conservative on purpose:** an advisory whose CVE is still not public 7+ days
  after review counts as late and as GitHub's (116 in 2026: Jun 34, Jul 34, Aug 16, Sep 12).
  Assigner unknown, but every one carries a repository-advisory reference, the GitHub-CNA
  pattern. Leaving them out would give September 0% instead of 2%. Rejected CVE aliases are
  excluded, not counted as pending.
- **Our May is 1,608 against GitHub's 1,560.** Close enough to trust the field. By our count
  **March (1,615) edges May**, so never write "May was the record" on our data; attribute it.
- **Worked example:** GHSA-4qpc-3hr4-r2p4 reviewed and published May 27 with alias
  CVE-2026-45304; the CVE record (GitHub_M, reserved May 11) reached CVE List July 14. OSV
  confirms the May 27 publish.

## Comment ammunition
- **GitHub's CVE-record output as a CNA held up through the catch-up:** 2025 average 239 a
  month; Mar 1,559, Apr 1,236, May 1,307, Jun 1,180, Jul 1,294, Aug 1,369, Sep 1,328 through
  the 25th. Part of August is the backlog of already-reviewed advisories going out.
- **Reservation to publication, GitHub_M CVEs, median by reservation month:** Mar 4.1 days,
  Apr 7.9, May 26.2, Jun 42.1, Jul 33.1, Aug 1.3.
- **Weekday-only since June** (weekend share 0.2% Jun, 0% Aug and Sep). Do **not** claim
  spring "surge hours": spring 2025 had the same weekend/pre-noon shape (Apr 2025 weekend
  13.9%), so it is seasonal or bulk-driven.
- Output is not capacity. The August dip can mean fewer inbound reports, more rejections, or
  people moved to the CVE side. The data cannot separate them.

## LinkedIn / Mastodon
Attach: `ghsa_output_square_<date>.png`.
```
GitHub went four times faster this spring and still fell behind. By September it had caught up.

Through 2025 GitHub reviewed about 350 advisories a month into its database. From March through July 2026 it averaged 1,522, and no month came in under 1,400. By GitHub's own account the inbound still outran that, and its CVE records show it: a GitHub-assigned CVE normally goes public the same day as its advisory, but in May 59% of them trailed the advisory by more than a week.

In September that's 2%. Review volume settled lower in August and September, still around three times last year, and the lag closed in the same stretch. The bottom panel is the part the top one hides.

If your scanner matches on CVE IDs rather than GHSA IDs, it spent the summer waiting weeks for records GitHub had already published. Did yours notice?

#vulnerabilitymanagement #opensource #supplychainsecurity #CVE
```

## X / Bluesky
```
GitHub went 4x faster this spring and still fell behind. By September it had caught up.

Reviewed advisories: 350 a month in 2025, 1,522 a month March to July 2026.
GitHub's CVE records more than a week behind their advisory: 59% in May, 2% in September.
```

## Alt text
```
Two-panel chart. Top panel, bar chart of advisories GitHub reviewed into the GitHub Advisory Database each month, January 2025 to September 2026. 2025 bars are pale, between 226 and 500, with a dashed line at the 2025 average of 350. 2026 bars are dark: January 497, February 784, March 1,615, April 1,493, May 1,608, June 1,438, July 1,455, August 878, and September 1,049 through September 25, marked partial. Bottom panel, red line of the share of GitHub-assigned advisories whose CVE record was published more than 7 days after the advisory. It stays between 0 and 5 percent from January 2025 to March 2026, rises to 19 percent in April, peaks at 59 percent in May, then falls to 54 percent in June, 45 in July, 14 in August and 2 percent in September. Footnote: reviews through September 25; a CVE still not public after 7 days counts as late. Source: GitHub Advisory Database, CVE List V5.
```

## Traps (do not ship these)
- **Credit, then consequence** (memory rule). GitHub published its numbers, did what it said,
  and the part it controls end to end recovered. The consequence line is about the reader's
  tooling, not about GitHub.
- **"Caught up" means the CVE-record lag, nothing wider.** Do not claim GitHub cleared every
  queue; the bottom panel measures one hand-off. The panel title says exactly which.
- **Never "because".** Lower output and the lag closing happened in the same months. Say
  "in the same stretch", not "the dip was the catch-up".
- **Never "May was the record" on our numbers** (March 1,615 vs May 1,608). Attribute it.
- **Don't say 3x advisories means 3x your alerts.** Alerts depend on your packages.
- **Don't compare to "6,000 decisions".** Rejections and duplicates leave no row.
- **The scanner line assumes CVE-keyed matching was worse off.** True when the tool waits on
  the CVE record (NVD, CVE List feeds). Tools that ingest GHSA or OSV directly had the
  advisory on day one. The copy says "if your scanner matches on CVE IDs", keep that
  conditional.
- **No other CNAs** (Jerry's scope call), including in comments unless asked directly.
- **September is partial.** 1,049 "through Sep 25" or "on pace for about 1,200"; the 2% can
  move as the last week's CVE records land.

## Review log
2026-09-28: first built as `ghsa_backlog` (other-CNA review lag vs GitHub's CVE-record lag).
Jerry re-scoped the same day to GitHub's acceleration only; rebuilt as monthly bars. Jerry
then read the bars-only render as "they got worse" (the August dip), which is a fair read of
output alone, so the CVE-record timeliness line was added as a bottom panel: it shows the
catch-up the bars cannot. Build fixes: late test switched from integer days to fractional
(integer floor gave May 54% not 59%); rejected CVE aliases loaded and excluded (they had
piled up as "pending", Mar 2025 read 18%); pending CVEs counted as late on purpose; wide
ratio given more header room. Earlier fixes kept: average label over May to Sep 2025, y ticks
every 500. Found while writing stats: March edges May; spring 2025 had the same
weekend/pre-noon pattern, so "surge hours" was dropped. LinkedIn copy 147 words, `tells.py` PASSED (sentence-length sd 11.5); X post 255 characters.

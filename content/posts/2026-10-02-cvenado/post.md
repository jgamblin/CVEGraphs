---
chart: cvenado
posted: 2026-10-02
platforms: LI
migrated: 2026-10-11
---
# Caption: CVE tornado (`cvenado`)

Media: `content/posts/2026-10-02-cvenado/cvenado.gif` (Slack, X) and `content/posts/2026-10-02-cvenado/cvenado.mp4` (LinkedIn; it flattens
GIFs to a still). Live page: `content/posts/2026-10-02-cvenado/cvenado.html`, parked unlinked at
rogolabs.net/tornado. House style: no em dashes; no "n="; factual Title-Case heading on
the page; post-date stamp. **Built 2026-10-02 at Jerry's request as a tongue-in-cheek
off-lane post.** Cap check: the Oct 1 month-close post (MonthlyCVEStats, external) is the
first post of the Mon Sep 28 week, so this is the second and the week is at the 2/week cap.

Chart: `src/cvegraphs/media/cvenado/template.html` is Ben Edwards' three.js spiral from
github.com/empiricalsec/cvenado (announced in #design 2026-09-30), restyled to the CVE
Insights look. `src/cvegraphs/media/cvenado/build.py` fills it from CVE List V5;
`src/cvegraphs/media/cvenado/record.py` drives it frame by frame in headless Chromium and encodes the
GIF and MP4. **Credit Ben by name every time this goes out; the geometry and the code are his. The cvenado repo is internal, so no link to it in public copy.**

How to read it: one turn is one calendar year (January at 12 o'clock), height is time,
radius is the 30-day centered average of CVEs published per day, **on a log scale**. Color
runs pale navy to alert red on the same log scale. The log radius makes the funnel kinder
than the numbers: 495 a day is 26 times 2016's 19, and the coil is only about twice as wide.

Data: `data.load_cvelist()` (CVE List V5), published and non-rejected, by publication
date, 2000-01-01 to 2026-10-01. Refreshed 2026-10-02 (newest record 14:13 UTC).

## Figures (verified 2026-10-02)

| Measure | Value |
|---|---|
| Published CVEs, 2000-01-01 to 2026-10-01 | 381,766 |
| Trailing 30-day average to Oct 1, 2016 | 19.4 / day (4,870 YTD) |
| Trailing 30-day average to Oct 1, 2021 | 61.8 / day (15,055 YTD) |
| Trailing 30-day average to Oct 1, 2025 | 149.3 / day (35,607 YTD) |
| Trailing 30-day average to Oct 1, 2026 | 495.4 / day (73,207 YTD) |
| Busiest single day | 2026-09-08, 1,563 (Patch Tuesday) |
| 2026 days at 500 or more | 32 (six at 1,000 or more) |
| 2000 to 2004 days with zero CVEs | 1,550 of 1,827 (bulk-dated era; the stem is spiky for that reason) |

The page's own readout shows 463.8/day on Oct 1 because its centered window shrinks at
the end of the series; the copy uses the trailing 30-day figure, which is the one a
reader can re-derive.

## Post copy (LinkedIn, 2026-10-02)

I've drawn CVE data as bars, ridgelines, waffles, calendars, strip plots and dot grids. Until this week I had never seen it drawn as a tornado.

Ben Edwards built the original. One turn is one calendar year, height is time, and the radius is how many CVEs were published per day. The 2000s are a narrow stem. By 2026 the top coil is 495 a day, averaged over the 30 days to October 1, against 19 on the same date in 2016 and 62 in 2021. The radius is on a log scale, so the picture is kinder than the numbers.

It tells you nothing a line chart wouldn't. It's just a lot more fun to watch spin. I restyled Ben's version and pointed it at the CVE List. Link to a live copy you can spin yourself is in the comments.

## First comment

Spin it yourself: rogolabs.net/tornado

Data: CVE List V5, published and non-rejected, by publication date, 2000-01-01 to 2026-10-01, 381,766 CVEs. Radius and color are a 30-day centered average on a log scale. The 2000 to 2004 stem is spiky because 1,550 of those 1,827 days have zero CVEs; publication dates from that era were bulk-assigned.

## Review log

- 2026-10-02: drafted under `Blogs/humanize.md`; tells linter passed. Jerry cut the repo link (internal repo); credit stays by name. Jerry moved the rogolabs.net/tornado link out of the body and into the first comment. `/post-review` not run (Jerry asked for a quick tongue-in-cheek post).

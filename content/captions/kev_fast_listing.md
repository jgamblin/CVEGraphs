# Caption: KEV additions per month, split by CVE age (`kev_fast_listing`)

Image: `graphs/kev_fast_listing_<ratio>_<date>.png`. House style: no em dashes; no "n=";
factual Title-Case heading; post-date stamp. Built 2026-09-24 from a September data scan
at Jerry's request ("check the CVE data from this month"). **Exploitation lane, Thursday,
on-lane.** Strongest when September closes, so the natural slot is **Thu Oct 1** with
the final count (re-render that morning; `stats()` prints every figure).

Chart: `charts/kev_fast_listing.py`. Stacked bars, one per month since the catalog
launched (Nov 2021; extended from a Jul 2022 start on 2026-09-24 at Jerry's request).
Bottom segment: entries added within 7 days of the CVE's V5 publication. The y-axis is
capped at 60; the three seeding months above it (Nov 2021 291, Mar 2022 226, May 2022
83) are drawn broken with their totals printed. `/post-review` not run.

## Finding (KEV catalog as of the Sep 22 addition, refreshed 2026-09-24)

| Measure | Value |
|---|---|
| September 2026 additions (through Sep 22) | **34**, the most of any month since the seeding ended (Jul 2022) |
| Previous post-seeding high | 32 (Mar 2025); 31 in Aug 2026 |
| All-time monthly high (seeding) | 291 (Nov 2021) |
| Average month since Jul 2022 | 18.0 |
| September additions within 7 days of publication | **20, the most of any month in the catalog's history** |
| Previous high for fresh listings | 14 (Mar 2025); seeding-era max 8; post-seeding average 7.3 |
| Median age at listing, September | 4 days (Aug 18, Apr 153) |
| September additions over a year old | 1 |

Mostly edge and appliance gear: Cisco 3, JFrog 3, Google 3 (Chromium V8 x2, Pixel), Linux
kernel 3, Check Point, MikroTik, SonicWall, Microsoft 2 each; plus Citrix NetScaler,
Fortinet, F5 BIG-IP APM, ConnectWise ScreenConnect, Zyxel, and an AI-stack cluster on Sep 2
(LiteLLM, Starlette, Kestra).

## Accuracy guards

- **KEV language rule.** "Added to KEV", never "exploited". KEV is a curated floor.
- **Date granularity.** KEV `dateAdded` is date-only, so V5 publication is floored to its
  UTC date first. Two September entries still land at -1 day (added the day before the V5
  record went public). They are counted as fresh; do not describe them as "before
  disclosure" without checking the vendor advisory dates.
- **Two different records.** The fresh-listing count (20) is all-time. The total (34)
  is only a record since mid-2022; the seeding months are far higher. Never write
  "most KEV additions ever".
- **Partial month.** The bar is starred on the axis and the footnote names the last
  addition. Do not say "record month" until Oct 1.
- **Not a CNA-mix claim.** This is a count of CISA's listings, not a rate. No
  mix-adjustment is needed because nothing is being compared against all CVEs.
- **What it does not show:** why. Faster listing could be faster exploitation, faster
  CISA, or more vendors disclosing in-the-wild use in the advisory itself. The data
  cannot separate those; the copy should not pick one.

## Draft copy (LinkedIn)

> The "you have time to patch" window is closing on the bugs CISA actually lists.
>
> 34 CVEs were added to KEV between Sep 1 and Sep 22, the most in any month since mid-2022.
> 20 of them were added within a week of the CVE being published. The previous monthly
> high for that was 14. Median age at listing: 4 days. Only one was more than a year old.
>
> Worth being precise: this is what CISA listed, not a full count of what got exploited,
> and it can't tell you whether attackers got faster or disclosure did. Either way, if your
> patch cycle is measured in weeks, 20 of this month's 34 were on the list before it came
> around once. What's your actual time-to-patch on an edge device?

Tells linter: run `python3 ~/Documents/Github/Blogs/scripts/tells.py` before posting.

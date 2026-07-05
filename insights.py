#!/usr/bin/env python3
"""
Insight miner — surface unique, share-worthy findings from the CVE dataset.

This is the deterministic half of the "what should I post?" problem. It computes
a broad battery of statistics and scores each candidate finding for
share-worthiness, then emits a ranked brief. A human (or Claude, via the
brand-voice skill) curates the top findings into posts; the LLM never has to
crunch 350k rows, only judge and phrase a short ranked list.

What makes a finding score high:
  * novelty   — records, firsts, rank flips, counterintuitive facts
  * magnitude — how far from the baseline (spikes, extremes)
  * relatability — exploitation (KEV/EPSS), recognizable names
  * recency   — happened in the current window

Outputs:
  content/insights_brief.md   human/Claude-readable ranked brief
  content/insights.json        structured findings for programmatic use

Usage:
  python insights.py            # print + write the brief
  python insights.py --top 20   # show more candidates
"""

import argparse
import json
from pathlib import Path

import pandas as pd

from data import load_cvelist, load_epss, load_nvd
from rolling_config import current_year, data_asof, elapsed_days, ytd_mask

HERE = Path(__file__).resolve().parent
CONTENT = HERE / "content"

# Chart in content/BACKLOG.md that best illustrates each category.
CHART_FOR = {
    "pace": "pace",
    "record": "pace",
    "exploitation": "epss_funnel",
    "kev": "kev",
    "mover": "cna",
    "product": "product",
    "curio": "rhythm",
}


def _finding(findings, *, cat, score, headline, detail, chart=None, **evidence):
    findings.append({
        "category": cat,
        "score": round(float(score), 1),
        "headline": headline,
        "detail": detail,
        "suggested_chart": chart or CHART_FOR.get(cat),
        "evidence": evidence,
    })


# =============================================================================
# SCANNERS
# =============================================================================
def scan_pace(f, nvd, asof, cur):
    ytd = int(ytd_mask(nvd, cur, asof).sum())
    days = elapsed_days(cur, asof)
    per_day = ytd / days
    minutes = 1440 / per_day
    prior = int(ytd_mask(nvd, cur - 1, asof).sum())
    yoy = (ytd - prior) / prior * 100 if prior else 0
    projected = round(per_day * 365, -2)
    _finding(
        f, cat="pace", score=72,
        headline=f"{ytd:,} CVEs published so far in {cur}, one every {minutes:.1f} minutes",
        detail=(f"{per_day:.0f}/day, {yoy:+.0f}% vs {cur-1} at the same point. "
                f"Straight-line run-rate lands near {int(projected):,} for the full year."),
        ytd=ytd, per_day=round(per_day, 1), minutes=round(minutes, 1),
        yoy_pct=round(yoy, 1), projected_year=int(projected),
    )


def scan_records(f, nvd, asof, cur):
    # YTD already exceeds which prior FULL years?
    full = nvd[(nvd["year"] < cur)].groupby("year").size()
    ytd = int(ytd_mask(nvd, cur, asof).sum())
    beaten = full[full < ytd]
    if len(beaten):
        highest_beaten = int(beaten.index.max())
        # "more than any full year before N": first year whose full total we do NOT beat
        not_beaten = full[full >= ytd]
        first_bigger = int(not_beaten.index.min()) if len(not_beaten) else cur
        _finding(
            f, cat="record", score=90,
            headline=(f"{cur} year-to-date ({ytd:,}) already exceeds every full year "
                      f"before {first_bigger}"),
            detail=(f"Six-plus months of {cur} outrank all of {highest_beaten} "
                    f"({int(full[highest_beaten]):,}) and every year prior."),
            ytd=ytd, highest_full_year_beaten=highest_beaten, first_year_still_bigger=first_bigger,
        )

    # Busiest calendar month ever.
    dt = pd.to_datetime(nvd["published"], utc=True, errors="coerce").dt.tz_convert(None)
    monthly = nvd.assign(ym=dt.dt.to_period("M")).groupby("ym").size().dropna()
    if len(monthly):
        top_month = monthly.idxmax()
        if top_month.year == cur:
            _finding(
                f, cat="record", score=88,
                headline=f"{top_month.strftime('%B %Y')} was the busiest CVE month ever: {int(monthly.max()):,}",
                detail="No calendar month in the program's history published more CVEs.",
                month=str(top_month), count=int(monthly.max()),
            )

    # All-time catalog total + distance to next round milestone.
    total = len(nvd)
    step = 10_000 if total > 100_000 else 5_000
    next_ms = ((total // step) + 1) * step
    per_day = ytd / elapsed_days(cur, asof)
    days_to = (next_ms - total) / per_day if per_day else None
    _finding(
        f, cat="record", score=68,
        headline=f"The CVE catalog is at {total:,}, {next_ms - total:,} short of {next_ms:,}",
        detail=(f"At the current rate it crosses {next_ms:,} in about "
                f"{days_to:.0f} days." if days_to else ""),
        total=total, next_milestone=next_ms, days_to_milestone=round(days_to) if days_to else None,
    )


def scan_exploitation(f, nvd_epss, kev_ids, kev_recent, kev_ransom, asof, cur):
    ytd = nvd_epss[ytd_mask(nvd_epss, cur, asof)]
    n = len(ytd)

    on_kev = ytd["cve_id"].isin(kev_ids).sum()
    _finding(
        f, cat="exploitation", score=92,
        headline=(f"Of {n:,} CVEs published in {cur}, only {on_kev} ({on_kev/n*100:.2f}%) "
                  f"are on CISA's KEV list so far"),
        detail=("A floor that rises as the cohort ages, not a final rate. Confirmed "
                "exploitation stays rare while volume climbs, the whole triage story."),
        ytd=n, on_kev=int(on_kev), kev_pct=round(on_kev / n * 100, 2),
    )

    # EPSS funnel (predicted exploitation) — pairs with KEV (confirmed).
    hi = int((ytd["epss"] >= 0.5).sum())
    med = int((ytd["epss"] >= 0.1).sum())
    _finding(
        f, cat="exploitation", score=87,
        headline=f"Only {hi} of {cur}'s {n:,} CVEs ({hi/n*100:.2f}%) score EPSS >= 0.5",
        detail=(f"{med:,} ({med/n*100:.1f}%) clear EPSS 0.1. Predicted exploitation is "
                f"as rare as confirmed: model {load_epss()['model_version'].iloc[0]}."),
        epss_ge_50=hi, epss_ge_10=med, ytd=n,
    )

    # Highest-EPSS CVE this year that is NOT yet on KEV (a watchlist headline).
    not_kev = ytd[~ytd["cve_id"].isin(kev_ids)].dropna(subset=["epss"])
    if len(not_kev):
        top = not_kev.loc[not_kev["epss"].idxmax()]
        _finding(
            f, cat="exploitation", score=80,
            headline=(f"{top['cve_id']} has the highest EPSS of {cur} not on KEV: "
                      f"{top['epss']:.3f}"),
            detail=(f"{(top.get('vendor') or 'unknown vendor')} / "
                    f"{(top.get('product') or 'n/a')}. High predicted risk the confirmed "
                    f"list hasn't caught up to."),
            cve=top["cve_id"], epss=round(float(top["epss"]), 4),
            vendor=top.get("vendor"), product=top.get("product"),
        )

    # Recent KEV activity.
    if kev_recent is not None:
        _finding(
            f, cat="kev", score=78,
            headline=f"CISA added {kev_recent} CVEs to KEV in the last 30 days, {kev_ransom} ransomware-linked",
            detail="Exploitation news travels; a fresh KEV batch is always timely.",
            kev_added_30d=kev_recent, ransomware_linked=kev_ransom,
        )


def scan_movers(f, cvelist, asof, cur):
    ytd = cvelist[ytd_mask(cvelist, cur, asof)]
    top = ytd["assigner_short_name"].value_counts()
    if len(top):
        lead, lead_n = top.index[0], int(top.iloc[0])
        share = lead_n / len(ytd) * 100
        _finding(
            f, cat="mover", score=76,
            headline=f"{lead} is {cur}'s top CVE issuer with {lead_n:,} ({share:.0f}% of all published)",
            detail="The CNA mix reflects who has scope, not who ships the worst code.",
            top_cna=lead, count=lead_n, share_pct=round(share, 1),
        )

    # This-month vs last-month CNA surge (from a single snapshot).
    dt = pd.to_datetime(ytd["date_published"], utc=True, errors="coerce").dt.tz_convert(None)
    this_m = asof.tz_convert(None).to_period("M")
    last_m = this_m - 1
    cur_counts = ytd[dt.dt.to_period("M") == this_m]["assigner_short_name"].value_counts()
    prev_counts = ytd[dt.dt.to_period("M") == last_m]["assigner_short_name"].value_counts()
    if len(cur_counts) and len(prev_counts):
        common = cur_counts.index.intersection(prev_counts.index)
        deltas = (cur_counts[common] - prev_counts[common]).sort_values(ascending=False)
        # Only flag a meaningful jump.
        big = deltas[deltas >= 100]
        if len(big):
            who, jump = big.index[0], int(big.iloc[0])
            _finding(
                f, cat="mover", score=70 + min(jump / 50, 20),
                headline=f"{who} published {jump:,} more CVEs this month than last",
                detail="A sharp month-over-month surge worth a closer look.",
                cna=who, month_over_month_delta=jump,
            )


def scan_curios(f, nvd, asof, cur):
    ytd = nvd[ytd_mask(nvd, cur, asof)]
    dt = pd.to_datetime(ytd["published"], utc=True, errors="coerce")
    dow = dt.dt.day_name().value_counts()
    if len(dow):
        lead = dow.index[0]
        second = dow.index[1] if len(dow) > 1 else None
        note = " (not Tuesday)" if lead != "Tuesday" else ""
        _finding(
            f, cat="curio", score=74 if lead != "Tuesday" else 60,
            headline=f"The busiest CVE weekday in {cur} is {lead}{note}",
            detail=(f"{lead}: {int(dow.iloc[0]):,} vs {second}: {int(dow.iloc[1]):,}. "
                    f"The 'Patch Tuesday' mental model does not match the data."
                    if second else ""),
            top_weekday=lead, counts={k: int(v) for k, v in dow.head(3).items()},
        )

    # Biggest single publishing day this year.
    daily = ytd.assign(d=dt.dt.date).groupby("d").size()
    if len(daily):
        peak_day, peak_n = daily.idxmax(), int(daily.max())
        _finding(
            f, cat="curio", score=66,
            headline=f"The single biggest CVE day of {cur}: {peak_day} with {peak_n:,}",
            detail="Batch publishing by high-volume CNAs drives these spikes.",
            peak_day=str(peak_day), peak_count=peak_n,
        )


# =============================================================================
# DRIVER
# =============================================================================
def gather():
    nvd = load_nvd(with_epss=True)
    cvelist = load_cvelist()
    asof = data_asof(nvd)
    cur = current_year(asof)

    kev = json.load(open(HERE / "processed" / "kev_catalog.json"))
    kv = kev.get("vulnerabilities", [])
    kev_ids = {e["cveID"] for e in kv}
    added = pd.to_datetime(pd.Series([e.get("dateAdded") for e in kv]), errors="coerce", utc=True)
    recent_mask = added >= (asof - pd.Timedelta(days=30))
    kev_recent = int(recent_mask.sum())
    kev_ransom = int(sum(
        1 for e, r in zip(kv, recent_mask)
        if r and e.get("knownRansomwareCampaignUse") == "Known"
    ))

    f = []
    scan_pace(f, nvd, asof, cur)
    scan_records(f, nvd, asof, cur)
    scan_exploitation(f, nvd, kev_ids, kev_recent, kev_ransom, asof, cur)
    scan_movers(f, cvelist, asof, cur)
    scan_curios(f, nvd, asof, cur)

    f.sort(key=lambda x: x["score"], reverse=True)
    return f, asof


def write_brief(findings, asof, top):
    CONTENT.mkdir(exist_ok=True)
    (CONTENT / "insights.json").write_text(json.dumps(
        {"as_of": asof.strftime("%Y-%m-%d"), "findings": findings}, indent=2))

    lines = [
        f"# Insight brief — as of {asof.strftime('%b %d, %Y')}",
        "",
        "Ranked share-worthiness candidates from the current data. Curate the top",
        "few into posts (pair each with `suggested_chart`). Scores are heuristic:",
        "records/flips and exploitation rank highest, routine stats lower.",
        "",
    ]
    for i, x in enumerate(findings[:top], 1):
        lines += [
            f"## {i}. [{x['score']:.0f}] {x['headline']}",
            f"- **why**: {x['detail']}",
            f"- **category**: {x['category']}  ·  **chart**: `{x['suggested_chart']}`",
            "",
        ]
    (CONTENT / "insights_brief.md").write_text("\n".join(lines))
    return CONTENT / "insights_brief.md"


def main():
    ap = argparse.ArgumentParser(description="Mine share-worthy CVE findings")
    ap.add_argument("--top", type=int, default=12, help="how many to show/write")
    args = ap.parse_args()

    findings, asof = gather()
    path = write_brief(findings, asof, args.top)

    print(f"Top {min(args.top, len(findings))} of {len(findings)} findings "
          f"(as of {asof.strftime('%b %d, %Y')}):\n")
    for i, x in enumerate(findings[:args.top], 1):
        print(f"{i:2d}. [{x['score']:>4.0f}] {x['headline']}")
    print(f"\nWrote {path} and content/insights.json")


if __name__ == "__main__":
    main()

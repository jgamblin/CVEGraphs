#!/usr/bin/env python3
"""
How many CVEs CISA adds to KEV each month, and how many of them are brand new.

One stacked bar per calendar month since the catalog launched in November 2021.
The bottom segment is the entries added within seven days of the CVE record's
publication; the top is everything older.

The 2021-22 seeding months (Nov 2021 alone carried 291 entries, Mar 2022 226,
May 2022 83) would flatten every later bar, so the y-axis is capped at CAP and
any bar above it is drawn broken, with its true total printed over it. The
fresh segment is never clipped: the tallest one in the seeding era is 8.

September 2026 is the finding: far more fresh listings than any month in the
catalog's history, 20 against a prior high of 14 (March 2025). Its 34 total is
also the most of any month since the seeding ended (prior high 32, Mar 2025),
but NOT an all-time total; the copy must say "since mid-2022" for that one.

Accuracy notes:

* KEV ``dateAdded`` is date-only, so the CVE publication timestamp is floored to
  its UTC calendar date before subtracting. Without that, a same-day listing
  reads as -1 day. Two September entries still come out at -1 (listed the day
  before the V5 record went public); they are counted as fresh, since "within
  a week of disclosure" is the claim and they are inside it.
* The newest month is partial. It is labelled as such on the axis and the
  footnote names the last catalog addition.

Data: processed/kev_catalog.json (CISA KEV) joined to CVE List V5 publication
dates. Every KEV entry resolves to a V5 record.
"""

import json

import matplotlib.pyplot as plt
import pandas as pd

from cvegraphs.data import load_cvelist
from cvegraphs.paths import OUTPUT, PROCESSED
from cvegraphs.style import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

DESCRIPTION = "Stacked bars: KEV additions per month since Jul 2022, split by whether the CVE was under a week old"

GRAPHS = OUTPUT

START = pd.Timestamp(2021, 11, 1)   # catalog launch (first entry Nov 3 2021)
SEEDING_END = pd.Period("2022-06", "M")  # last month of the bulk backfill
CAP = 60  # y-axis cap; only the three biggest seeding months exceed it
FRESH_DAYS = 7

SERIES = [
    ("fresh", f"Added Within {FRESH_DAYS} Days of Publication", COLORS["primary"]),
    ("older", "Older CVEs", COLORS["light"]),
]


def _load():
    """One row per KEV entry: date added, CVE publication date, age in days."""
    cat = json.load(open(PROCESSED / "kev_catalog.json"))
    k = pd.DataFrame(cat["vulnerabilities"])[["cveID", "vendorProject",
                                              "product", "dateAdded"]]
    k["added"] = pd.to_datetime(k["dateAdded"])
    cl = load_cvelist().drop_duplicates("cve_id")
    pub = (pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
             .dt.tz_localize(None).dt.normalize())
    k = k.merge(pd.DataFrame({"cveID": cl["cve_id"], "pub": pub}),
                on="cveID", how="left")
    k["age"] = (k["added"] - k["pub"]).dt.days
    return k


def _monthly(k):
    cur = k[k["added"] >= START].copy()
    cur["period"] = cur["added"].dt.to_period("M")
    cur["is_fresh"] = cur["age"] <= FRESH_DAYS
    t = (cur.groupby("period")["is_fresh"].agg(fresh="sum", total="size")
            .reindex(pd.period_range(START, cur["added"].max(), freq="M"),
                     fill_value=0))
    t["older"] = t["total"] - t["fresh"]
    return t


def render(nvd=None, ratios=DEFAULT_RATIOS):
    k = _load()
    t = _monthly(k)
    newest = k["added"].max()

    labels = []
    for i, p in enumerate(t.index):
        if i == len(t) - 1:
            labels.append(f"{p.strftime('%b')}*")
        elif p.month == 1:
            labels.append(f"Jan\n{p.year}")
        elif p.month == 7 and i < len(t) - 3:  # keep clear of the Sep* label
            labels.append("Jul")
        else:
            labels.append("")

    title = "CVEs Added to CISA KEV per Month"
    subtitle = (f"Dark segment: added within {FRESH_DAYS} days of the CVE's "
                "publication. Nov 2021 to date.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        x = list(range(len(t)))
        bottom = [0] * len(t)
        for key, label, color in SERIES:
            vals = [min(v, CAP - b) for v, b in zip(t[key].tolist(), bottom)]
            ax.bar(x, vals, bottom=bottom, color=color, label=label, width=0.78,
                   edgecolor="white", linewidth=0.5, zorder=3)
            bottom = [b + v for b, v in zip(bottom, vals)]

        # Broken bars: a white slash near the top and the true total above.
        for i, tot in enumerate(t["total"]):
            if tot <= CAP:
                continue
            ax.plot([i - 0.5, i + 0.5], [CAP * 0.90, CAP * 0.94], color="white",
                    lw={"wide": 3.0, "square": 2.4, "portrait": 2.4}[ratio],
                    zorder=4, solid_capstyle="butt")
            ax.annotate(f"{int(tot)}", (i, CAP), textcoords="offset points",
                        xytext=(0, 4), ha="center", va="bottom",
                        fontsize={"wide": 10, "square": 8.5, "portrait": 8.5}[ratio],
                        color=COLORS["secondary"], fontweight="bold", zorder=6)
        seed = [i for i, p in enumerate(t.index) if p <= SEEDING_END]
        ax.annotate("Catalog seeding", ((seed[0] + seed[-1]) / 2, CAP * 1.075),
                    ha="center", va="bottom",
                    fontsize={"wide": 10.5, "square": 9, "portrait": 9}[ratio],
                    color=COLORS["secondary"], zorder=6)

        # Label the newest month and the prior fresh-listing high only: those
        # two numbers are the comparison the post makes.
        last = len(t) - 1
        fs = {"wide": 12, "square": 10.5, "portrait": 10.5}[ratio]
        ax.annotate(f"{int(t['total'].iloc[-1])}", (last, t["total"].iloc[-1]),
                    textcoords="offset points", xytext=(0, 5), ha="center",
                    fontsize=fs, fontweight="bold", color=COLORS["text"],
                    zorder=6)
        # The fresh count sits left of the bar, level with its top: a bar is
        # too narrow at every ratio to hold two digits inside it.
        ax.annotate(f"{int(t['fresh'].iloc[-1])}",
                    (last - 0.45, t["fresh"].iloc[-1]),
                    textcoords="offset points", xytext=(-3, 0), ha="right",
                    va="center", fontsize=fs, fontweight="bold",
                    color=COLORS["primary"], zorder=6,
                    bbox=dict(facecolor="white", edgecolor="none", pad=1.0))
        prior = t.iloc[:-1]
        pi = int(prior["fresh"].to_numpy().argmax())
        ax.annotate(f"Prior high: {int(prior['fresh'].iloc[pi])}",
                    xy=(pi, prior["fresh"].iloc[pi]),
                    xytext=(pi, 40),
                    ha="center", va="bottom", fontsize=fs - 2,
                    color=COLORS["primary"], fontweight="bold", zorder=6,
                    arrowprops=dict(arrowstyle="-", color=COLORS["primary"],
                                    lw=1.0, shrinkA=2, shrinkB=2))

        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize={"wide": 10.5, "square": 9,
                                             "portrait": 9}[ratio])
        ax.tick_params(axis="x", length=0)
        ax.set_ylabel("KEV entries added", fontsize=12, fontweight="normal")
        ax.set_ylim(0, CAP * 1.16)
        ax.set_xlim(-0.8, len(t) - 0.2)
        ax.set_axisbelow(True)
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)

        leg = ax.legend(loc="upper center", bbox_to_anchor=(0.5, 1.0), frameon=False,
                        fontsize={"wide": 10.5, "square": 9.5,
                                  "portrait": 9.5}[ratio],
                        handlelength=1.4, labelspacing=0.45)
        for txt in leg.get_texts():
            txt.set_color(COLORS["secondary"])

        top = {"wide": 0.80, "square": 0.79, "portrait": 0.82}[ratio]
        bottom_m = {"wide": 0.17, "square": 0.16, "portrait": 0.13}[ratio]
        left_m = {"wide": 0.08, "square": 0.11, "portrait": 0.12}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom_m, left=left_m, right=0.965)
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="Exploitation",
                    title_size={"wide": 26, "square": 21, "portrait": 21}[ratio])

        foot = {"wide": 9.5, "square": 8.0, "portrait": 8.0}[ratio]
        fig.text(0.05, 0.055,
                 f"*Partial month, through {newest:%b %-d, %Y}. Axis capped at {CAP}; "
                 "broken bars show their totals. Source: CISA KEV, CVE List V5.",
                 fontsize=foot, color=COLORS["secondary"], ha="left",
                 va="bottom")

        path = GRAPHS / f"kev_fast_listing_{ratio}_{newest:%Y-%m-%d}.png"
        out.append(stamp_and_save(fig, path))
    return out


def stats():
    """Every figure the caption and copy quote, so none is retyped off the image."""
    k = _load()
    t = _monthly(k)
    last, prior = t.iloc[-1], t.iloc[:-1]
    post = prior[prior.index > SEEDING_END]
    cur = k[k["added"].dt.to_period("M") == t.index[-1]]
    ages = cur["age"].sort_values()
    return {
        "newest_add": k["added"].max().date(),
        "month": str(t.index[-1]),
        "month_total": int(last["total"]),
        "month_fresh": int(last["fresh"]),
        "month_median_age": float(ages.median()),
        "month_over_1y": int((ages > 365).sum()),
        "month_negative_age": int((ages < 0).sum()),
        "prior_total_max_post_seeding": int(post["total"].max()),
        "prior_total_month_post_seeding": str(post["total"].idxmax()),
        "all_time_total_max": int(prior["total"].max()),
        "all_time_total_month": str(prior["total"].idxmax()),
        "seeding_fresh_max": int(t[t.index <= SEEDING_END]["fresh"].max()),
        "prior_fresh_max": int(prior["fresh"].max()),
        "prior_fresh_month": str(prior["fresh"].idxmax()),
        "mean_per_month_post_seeding": round(float(post["total"].mean()), 1),
        "mean_fresh_per_month_post_seeding": round(float(post["fresh"].mean()), 1),
        "unmatched_pub": int(k["pub"].isna().sum()),
        "month_vendors": cur["vendorProject"].value_counts().head(8).to_dict(),
    }


if __name__ == "__main__":
    for key, val in stats().items():
        print(f"{key:>22}: {val}")
    for p in render():
        print(p)

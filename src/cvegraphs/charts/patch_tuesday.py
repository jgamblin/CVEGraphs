#!/usr/bin/env python3
"""
How big Patch Tuesday has become, and what changed inside it.

Every bar is a single calendar day: the second Tuesday of the month, the day
Microsoft ships its monthly security release. Two years of them, so the
September 2026 release has something to be measured against.

Two things happened at once and the stack separates them:

* Volume. September 8, 2026 carried 955 Microsoft-assigned CVEs. The previous
  high was 570 in July 2026, and before this year Microsoft had never published
  more than 167 CVEs in a day (October 2025).

* Composition. Memory-safety weaknesses were roughly half of a normal Microsoft
  release and are 76% of this one. Three CWEs account for most of it: heap
  overflow (CWE-122), use-after-free (CWE-416) and out-of-bounds read (CWE-125).
  Severity did not move with the count, which is the part worth arguing about:
  median CVSS v3 is 7.8, the same as every month since May.

Deliberately NOT plotted: whole-month totals. Patch Tuesday is 85-99% of
Microsoft's month, and a month bar for September would be partial while the
other 23 were complete. One day per bar, every bar the same kind of day.

Patch Tuesday is derived (second Tuesday of the month), not hand-listed. It is
also the busiest Microsoft publishing day in all 24 months plotted, so the
derivation is not quietly picking a slow day.

Data: CVE List V5, Microsoft-assigned CVEs by publication date, non-rejected.
"""

import calendar

import matplotlib.pyplot as plt
import pandas as pd

from cvegraphs.data import load_cvelist
from cvegraphs.paths import OUTPUT
from cvegraphs.rolling import data_asof
from cvegraphs.style import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

DESCRIPTION = "Stacked bars: CVEs on each of the last 24 Patch Tuesdays, memory safety vs everything else"

GRAPHS = OUTPUT

MONTHS = 24  # trailing Patch Tuesdays, so two years of baseline sit under the spike

# Memory-safety weaknesses, restricted to the ones that ARE a memory error rather
# than the arithmetic that can lead to one. CWE-190/191/197 (integer overflow,
# underflow, truncation) and CWE-362 (race) are deliberately excluded: they are
# frequent in Microsoft's records and counting them would inflate the share
# without being defensible. The list is printed on the chart.
MEM_CWES = {
    f"CWE-{n}" for n in (
        119, 120, 121, 122, 124, 125, 126, 127, 129, 131,
        415, 416, 476, 680, 786, 787, 788, 805, 822, 823, 824, 843, 908,
    )
}

# Stack order is bottom-up. Memory safety sits on the baseline so its height can
# be read directly off the axis; that share is the finding.
SERIES = [
    ("mem", "Memory Safety", COLORS["primary"]),
    ("other", "Everything Else", COLORS["light"]),
]


def patch_tuesday(year, month):
    """The second Tuesday of the month, as a date."""
    tuesdays = [
        d for d in calendar.Calendar(firstweekday=0).itermonthdates(year, month)
        if d.month == month and d.weekday() == calendar.TUESDAY
    ]
    return tuesdays[1]


def _table(cl, asof):
    """One row per trailing Patch Tuesday: memory-safety and other CVE counts."""
    ms = cl[cl["assigner_short_name"].str.lower() == "microsoft"].copy()
    ms["day"] = ms["pub"].dt.tz_convert("UTC").dt.date
    ms["mem"] = ms["cwe"].isin(MEM_CWES)

    end = asof.tz_localize(None).to_period("M")
    rows = []
    for period in pd.period_range(end - (MONTHS - 1), end, freq="M"):
        day = patch_tuesday(period.year, period.month)
        on_day = ms[ms["day"] == day]
        rows.append({
            "period": period,
            "day": day,
            "mem": int(on_day["mem"].sum()),
            "other": int((~on_day["mem"]).sum()),
        })
    t = pd.DataFrame(rows).set_index("period")
    t["total"] = t["mem"] + t["other"]
    return t


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist().drop_duplicates("cve_id")
    cl = cl.assign(pub=pd.to_datetime(cl["date_published"], utc=True,
                                      errors="coerce")).dropna(subset=["pub"])
    asof = data_asof(cl)
    t = _table(cl, asof)

    latest = t.iloc[-1]
    mem_pct = 100 * latest["mem"] / latest["total"]

    # Year marker on January and on the first bar, so the axis stays readable.
    labels = [
        f"{p.strftime('%b')}\n{p.year}" if p.month == 1 or i == 0 else p.strftime("%b")
        for i, p in enumerate(t.index)
    ]

    title = "Microsoft CVEs Published on Patch Tuesday"
    # One line at every ratio. The 955-against-570 comparison is already drawn by
    # the bars and their value labels, so saying it in prose was duplication.
    subtitle = "One bar per release, the second Tuesday of each month."

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        x = range(len(t))
        bottom = [0] * len(t)
        for key, label, color in SERIES:
            vals = t[key].tolist()
            ax.bar(x, vals, bottom=bottom, color=color, label=label, width=0.74,
                   edgecolor="white", linewidth=0.7, zorder=3)
            bottom = [b + v for b, v in zip(bottom, vals)]

        # Totals labelled on the three biggest releases only: that is the step
        # change. Labelling all 24 turns the stack into a table.
        for i in t["total"].reset_index(drop=True).nlargest(3).index:
            tot = int(t["total"].iloc[i])
            ax.annotate(f"{tot}", (i, tot), textcoords="offset points",
                        xytext=(0, 7), ha="center", fontsize=12.5,
                        fontweight="bold", color=COLORS["text"], zorder=6)

        # Memory-safety share of the newest release. Placed to the LEFT of the bar
        # with a leader: the bar is ~40px wide on the square canvas, so text set
        # inside it would be clipped by the figure edge.
        ax.annotate(f"{mem_pct:.0f}% memory safety",
                    xy=(len(t) - 1.4, latest["mem"]),
                    xytext=(len(t) - 4.4, latest["mem"]),
                    ha="right", va="center", fontsize=10.5, fontweight="bold",
                    color=COLORS["primary"], zorder=6,
                    arrowprops=dict(arrowstyle="-", color=COLORS["primary"],
                                    lw=1.2, shrinkA=3, shrinkB=0))

        ax.set_xticks(list(x))
        ax.set_xticklabels(labels, fontsize={"wide": 9.5, "square": 7.5,
                                             "portrait": 7.5}[ratio])
        # Short and unbolded: the full-height bold label collided with the
        # subtitle once the footnote pushed the axes down.
        ax.set_ylabel("CVEs published", fontsize=12, fontweight="normal")
        ax.set_ylim(0, t["total"].max() * 1.16)
        ax.set_xlim(-0.8, len(t) - 0.2)
        ax.set_axisbelow(True)
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)

        leg = ax.legend(loc="upper left", frameon=False, fontsize=10.5,
                        handlelength=1.6, labelspacing=0.5)
        leg.set_zorder(7)
        for s in leg.get_texts():
            s.set_color(COLORS["secondary"])

        top = {"wide": 0.80, "square": 0.79, "portrait": 0.82}[ratio]
        bottom_m = {"wide": 0.18, "square": 0.17, "portrait": 0.14}[ratio]
        left_m = {"wide": 0.11, "square": 0.135, "portrait": 0.135}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom_m, left=left_m,
                            right=0.965)
        t1 = {"wide": 26, "square": 20, "portrait": 20}[ratio]
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="CNA Volume",
                    title_size=t1)

        # House rule (Jerry, 2026-09-08): one footnote per chart, maximum, and it
        # has to fit on one line at every ratio. The memory-safety CWE list, the
        # baseline share and the severity check live in
        # content/captions/patch_tuesday.md for use in the copy and the comments.
        foot_size = {"wide": 9.5, "square": 8.5, "portrait": 8.5}[ratio]
        fig.text(0.05, 0.06,
                 "Source: CVE List V5, Microsoft-assigned non-rejected CVEs by "
                 f"publication date, through {asof.strftime('%b %-d, %Y')}.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left",
                 va="bottom")

        path = GRAPHS / f"patch_tuesday_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        out.append(stamp_and_save(fig, path))
    return out


def stats():
    """The comparison figures the chart no longer prints, for the caption copy.

    The baseline share is taken across the releases BEFORE the newest one, so it
    is a like-for-like Patch Tuesday figure and not an all-days average.
    """
    cl = load_cvelist().drop_duplicates("cve_id")
    cl = cl.assign(pub=pd.to_datetime(cl["date_published"], utc=True,
                                      errors="coerce")).dropna(subset=["pub"])
    t = _table(cl, data_asof(cl))
    latest, base = t.iloc[-1], t.iloc[:-1]
    return {
        "day": latest["day"],
        "total": int(latest["total"]),
        "mem": int(latest["mem"]),
        "mem_pct": round(100 * latest["mem"] / latest["total"], 1),
        "base_mem_pct": round(100 * base["mem"].sum() / base["total"].sum(), 1),
        "prior_max": int(base["total"].max()),
        "prior_day": base["day"][base["total"].idxmax()],
        "base_mean": round(base["total"].mean(), 1),
    }


if __name__ == "__main__":
    for k, v in stats().items():
        print(f"{k:14} {v}")
    for p in render():
        print(p)

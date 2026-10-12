#!/usr/bin/env python3
"""
How early in the year the running CVE count overtakes the FULL total from two
years earlier.

For each year Y we find the calendar day on which Y's cumulative non-rejected
CVE count first passes year (Y-2)'s full-year total. That day has crept earlier
and earlier: a milestone that landed in November a few years ago now lands in
late summer, and in 2026 around mid-July.

2018 is omitted on purpose: its two-years-earlier baseline is 2016, an
anomalously small year (~6,400 CVEs, a data-reboot artifact), so 2018 clears it
by May and would steal the headline for the wrong reason. The series starts at
2019, whose baseline (2017) is the first "normal" modern year.

Data: NVD (published date), non-rejected CVEs.
"""


import matplotlib.patheffects as pe
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from cvegraphs.data import load_nvd
from cvegraphs.paths import OUTPUT
from cvegraphs.rolling import current_year, data_asof
from cvegraphs.style import COLORS, DEFAULT_RATIOS, draw_header, figsize_for, stamp_and_save

DESCRIPTION = "Line: calendar day each year passes the full CVE total from two years earlier"

GRAPHS = OUTPUT

START_YEAR = 2019  # first year whose Y-2 baseline (2017) is a normal modern year

# Day-of-year for the first of each month (non-leap); good enough for y labels.
_MONTH_DOY = {"Jul": 182, "Aug": 213, "Sep": 244, "Oct": 274, "Nov": 305, "Dec": 335}


def _crossing_doy(cum_by_doy, target):
    """First day-of-year where the cumulative count reaches ``target`` (or None)."""
    hit = cum_by_doy[cum_by_doy >= target]
    return int(hit.index[0]) if len(hit) else None


def render(nvd=None, ratios=DEFAULT_RATIOS):
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)
    cur = current_year(asof)

    pub = pd.to_datetime(nvd["published"], utc=True, errors="coerce")
    d = nvd.assign(pub=pub)
    d = d[nvd["is_rejected"] != True].dropna(subset=["pub"])
    d = d.assign(year=d["pub"].dt.year, doy=d["pub"].dt.dayofyear)

    totals = d.groupby("year").size()

    years, doys, dates = [], [], []
    for y in range(START_YEAR, cur + 1):
        target = int(totals.get(y - 2, 0))
        if not target:
            continue
        cum = d[d["year"] == y].groupby("doy").size().sort_index().cumsum()
        c = _crossing_doy(cum, target)
        if c is None:
            continue  # this year has not overtaken its Y-2 baseline yet
        years.append(y)
        doys.append(c)
        dates.append((pd.Timestamp(f"{y}-01-01") + pd.Timedelta(days=c - 1)))

    title1 = "When a Year Overtakes Two Years Ago"
    title2 = ("Calendar day the running CVE count passes the full-year total "
              "from two years before.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        x = np.arange(len(years))

        # connecting line + markers; the final (record) year in alert red.
        ax.plot(x, doys, color=COLORS["primary"], lw=2.4, zorder=2)
        for xi, y, dy, dt in zip(x, years, doys, dates):
            last = y == years[-1]
            ax.scatter(xi, dy, s=150 if last else 90,
                       color=COLORS["alert"] if last else COLORS["primary"],
                       edgecolors="white", linewidths=1.4, zorder=4)
            # Label above each marker in screen space (robust to the inverted axis);
            # a white halo keeps it legible where the connecting line passes close.
            ax.annotate(dt.strftime("%b %-d"), (xi, dy), textcoords="offset points",
                        xytext=(0, 15 if last else 12), ha="center", va="bottom",
                        fontsize=11 if last else 9.5,
                        fontweight="bold" if last else "normal",
                        color=COLORS["alert"] if last else COLORS["secondary"], zorder=5,
                        path_effects=[pe.withStroke(linewidth=3, foreground="white")])

        ax.set_xticks(x)
        ax.set_xticklabels([str(y) for y in years], fontsize=11, color=COLORS["text"])
        ax.set_xlim(-0.5, len(years) - 0.5)

        lo = min(doys) - 36  # extra headroom above the top gridline for the cue
        hi = max(doys) + 24
        ax.set_ylim(hi, lo)  # invert: earlier dates sit HIGHER, so the record is at the top
        yt = [v for v in _MONTH_DOY.values() if lo <= v <= hi]
        ax.set_yticks(yt)
        ax.set_yticklabels([m for m, v in _MONTH_DOY.items() if lo <= v <= hi],
                           fontsize=10.5, color=COLORS["secondary"])

        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])
        ax.tick_params(axis="both", length=0)
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        # Directional cue: the axis is inverted, so up = sooner in the calendar.
        # Sits in the headroom band above the top gridline, clear of the month ticks.
        ax.text(0.012, 0.955, "↑ earlier in the year", transform=ax.transAxes,
                fontsize=9.5, fontweight="bold", color=COLORS["neutral"],
                ha="left", va="center")

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05,
                 "Non-rejected CVEs by NVD publication date. 2018 omitted (its 2016 "
                 "baseline is an anomalously small year). Source: NVD.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom")

        top_m = {"wide": 0.78, "square": 0.81, "portrait": 0.85}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.15, left=0.09, right=0.96)
        draw_header(fig, title1, title2, ratio=ratio, eyebrow_suffix="VOLUME")

        path = GRAPHS / f"two_year_overtake_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

#!/usr/bin/env python3
"""
CVEs published per day this year, as a seven-day rolling average.

The daily rate is noisy (Patch-Tuesday spikes, weekend lulls), so a 7-day mean
shows the trend. Within 2026 it climbs from ~100/day in the January lull to a
June peak, well above the prior-year average drawn for reference: the growth is
not just year-over-year, it is happening inside the year.

Data: NVD (published date), non-rejected CVEs.
"""

from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from data import load_nvd
from rolling_config import current_year, data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"


def render(nvd=None, ratios=DEFAULT_RATIOS):
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)
    year = current_year(asof)

    pub = pd.to_datetime(nvd["published"], utc=True, errors="coerce")
    d = nvd.assign(day=pub.dt.floor("D"))
    daily = d[nvd["is_rejected"] != True].dropna(subset=["day"]).groupby("day").size()

    idx = pd.date_range(pd.Timestamp(year, 1, 1, tz="UTC"), asof, freq="D", tz="UTC")
    dd = daily.reindex(idx, fill_value=0)
    roll = dd.rolling(7).mean()
    year_avg = dd.mean()  # this year's average CVEs per day, to date

    x = roll.index.tz_localize(None)
    y = roll.values
    cur = y[-1]
    ymax = np.nanmax(y)

    title1 = f"CVEs Published Per Day in {year}"
    title2 = (f"Seven-day rolling average of non-rejected CVEs, with the {year} daily "
              f"average for reference.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        ax.fill_between(x, y, color=COLORS["primary"], alpha=0.10, zorder=2)
        ax.plot(x, y, color=COLORS["primary"], lw=2.6, zorder=3)

        # this-year average reference (line sits above the January data on the left)
        ax.axhline(year_avg, color=COLORS["neutral"], ls="--", lw=1.6, zorder=1)
        ax.text(x[3], year_avg + ymax * 0.015, f"{year} average: {year_avg:.0f} per day",
                fontsize=9.5, fontweight="bold", color=COLORS["secondary"],
                ha="left", va="bottom")

        # current value
        ax.plot(x[-1], cur, "o", color=COLORS["primary"], markersize=7, zorder=4)
        ax.text(x[-1], cur + ymax * 0.03, f"{cur:.0f}", ha="right", va="bottom",
                fontsize=12, fontweight="bold", color=COLORS["primary"])

        ax.set_ylim(0, ymax * 1.15)
        ax.set_yticks(np.arange(0, ymax * 1.15, 50))
        ax.set_yticklabels([f"{v:.0f}" for v in np.arange(0, ymax * 1.15, 50)],
                           fontsize=10, color=COLORS["secondary"])
        ax.xaxis.set_major_locator(mdates.MonthLocator())
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
        ax.tick_params(axis="x", labelsize=11, colors=COLORS["text"], length=0)
        ax.tick_params(axis="y", length=0)
        ax.margins(x=0.01)
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05,
                 f"Seven-day rolling average of CVEs by NVD publication date, non-rejected, "
                 f"{year} to date. Source: NVD.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom")

        top_m = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        t1 = {"wide": 20, "square": 17, "portrait": 17}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.15, left=0.08, right=0.96)
        fig.text(0.05, 0.965, title1, fontsize=t1, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.915, title2, fontsize=10.5, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"daily_rate_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

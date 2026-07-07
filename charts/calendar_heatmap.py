#!/usr/bin/env python3
"""
A year of vulnerability disclosure — calendar heatmap.

GitHub-contribution-style grid: every day of the current year as a cell shaded
by how many CVEs were published that day. Shows the workday rhythm (pale
weekends), the Patch-Tuesday cadence, and the Chrome mega-days as near-black
outliers, all in one image.
"""

import datetime as dt
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap, PowerNorm

from data import load_nvd
from rolling_config import current_year, data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def render(nvd=None, ratios=DEFAULT_RATIOS):
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)
    cur = current_year(asof)
    pub = pd.to_datetime(nvd["published"], utc=True, errors="coerce").dt.tz_convert(None)
    daily = nvd[pub.dt.year == cur].assign(d=pub.dt.date).groupby("d").size()
    counts = {d: int(c) for d, c in daily.items()}

    start = dt.date(cur, 1, 1)
    last = asof.tz_convert(None).date()
    n_days = (last - start).days + 1
    first_wd = start.weekday()
    n_weeks = (first_wd + n_days + 6) // 7

    mat = np.full((7, n_weeks), np.nan)
    for i in range(n_days):
        day = start + dt.timedelta(days=i)
        mat[day.weekday(), (first_wd + i) // 7] = counts.get(day, 0)

    vmax = float(np.nanmax(mat))
    busiest_day = max(counts, key=counts.get)
    cmap = LinearSegmentedColormap.from_list("cve", ["#eef2f7", COLORS["accent"], COLORS["primary"]])
    cmap.set_bad("white")

    # Month label positions: column of the first day of each month.
    month_cols = {}
    for m in range(1, 13):
        d = dt.date(cur, m, 1)
        if start <= d <= last:
            month_cols[(first_wd + (d - start).days) // 7] = d.strftime("%b")

    title1 = f"A year of vulnerability disclosure"
    title2 = (f"{int(daily.sum()):,} CVEs across {cur} so far. Busiest day: "
              f"{busiest_day.strftime('%b %-d')} ({counts[busiest_day]:,}).")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        ax.pcolormesh(mat, cmap=cmap, norm=PowerNorm(0.55, vmin=0, vmax=vmax),
                      edgecolors="white", linewidth=1.2)
        # No forced-equal aspect: let cells fill the canvas so the grid does not
        # float in a band with the footer crashing into the month labels.
        ax.invert_yaxis()
        ax.set_yticks(np.arange(7) + 0.5)
        ax.set_yticklabels(WEEKDAYS, fontsize=10)
        ax.set_xticks([c + 0.5 for c in month_cols])
        ax.set_xticklabels(list(month_cols.values()), fontsize=10)
        ax.tick_params(length=0)
        for s in ax.spines.values():
            s.set_visible(False)
        ax.grid(False)

        # Legend strip: a manual "less -> more" gradient hint.
        ax.text(0.0, -0.22,
                "Each cell = one day, shaded by CVEs published (paler = fewer, darker = more).\n"
                f"{cur} year-to-date. Source: NVD.",
                transform=ax.transAxes, fontsize=10, color=COLORS["neutral"],
                va="top", linespacing=1.5)

        top = {"wide": 0.80, "square": 0.72, "portrait": 0.66}[ratio]
        fig.subplots_adjust(top=top, bottom=0.28, left=0.08, right=0.97)
        fig.text(0.05, 0.965, title1, fontsize=20, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.918, title2, fontsize=12.5, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"calendar_heatmap_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

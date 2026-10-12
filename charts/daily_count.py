#!/usr/bin/env python3
"""
CVEs published each day this year, with the seven-day rolling average on top.

Companion to daily_rate (rolling average only): here the raw daily counts stay
visible as bars, so the Patch-Tuesday spikes and weekend lulls the average
smooths away are on the page next to the trend.

The as-of day is usually partial, so the series ends on the last complete day.

Data: NVD (published date), non-rejected CVEs.
"""

from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from data import load_nvd
from rolling_config import current_year, data_asof
from style_social import (COLORS, DEFAULT_RATIOS, draw_header, figsize_for,
                          stamp_and_save)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"


def series(nvd):
    """Daily counts and 7-day rolling mean, Jan 1 to the last complete day."""
    asof = data_asof(nvd)
    year = current_year(asof)
    last = asof.floor("D") - pd.Timedelta(days=1)

    pub = pd.to_datetime(nvd["published"], utc=True, errors="coerce")
    keep = (nvd["is_rejected"] != True) & pub.notna()
    daily = pub[keep].dt.floor("D").value_counts()

    idx = pd.date_range(pd.Timestamp(year, 1, 1, tz="UTC"), last, freq="D")
    dd = daily.reindex(idx, fill_value=0).sort_index()
    return year, last, dd, dd.rolling(7).mean()


def render(nvd=None, ratios=DEFAULT_RATIOS):
    if nvd is None:
        nvd = load_nvd()
    year, last, dd, roll = series(nvd)

    x = dd.index.tz_localize(None)
    cur = roll.iloc[-1]
    ymax = dd.max()
    step = 200 if ymax > 1000 else 100 if ymax > 400 else 50

    title1 = f"CVEs Published Per Day in {year}"
    title2 = f"Daily count (bars) and seven-day rolling average (line), Jan 1 to {last:%b} {last.day}."

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        ax.bar(x, dd.values, width=0.85, color=COLORS["neutral"], alpha=0.45,
               lw=0, zorder=2)
        ax.plot(x, roll.values, color=COLORS["primary"], lw=2.6, zorder=3)

        # latest rolling value at the line's end
        ax.scatter([x[-1]], [cur], s=28, color=COLORS["primary"], zorder=4)
        ax.annotate(f"{cur:.0f}/day", (x[-1], cur), xytext=(6, 0),
                    textcoords="offset points", fontsize=10, fontweight="bold",
                    color=COLORS["primary"], ha="left", va="center")

        top = ymax * 1.08
        ticks = np.arange(0, top, step)
        ax.set_ylim(0, top)
        ax.set_yticks(ticks)
        ax.set_yticklabels([f"{v:,.0f}" for v in ticks], fontsize=10,
                           color=COLORS["secondary"])
        ax.xaxis.set_major_locator(mdates.MonthLocator())
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%b"))
        ax.tick_params(axis="x", labelsize=11, colors=COLORS["text"], length=0)
        ax.tick_params(axis="y", length=0)
        ax.set_xlim(x[0] - pd.Timedelta(days=1), x[-1] + pd.Timedelta(days=12))
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05,
                 "Non-rejected CVEs by NVD publication date (UTC). Source: NVD.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom")

        top_m = {"wide": 0.80, "square": 0.83, "portrait": 0.86}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.15, left=0.08, right=0.94)
        draw_header(fig, title1, title2, ratio=ratio, eyebrow_suffix="VOLUME")

        path = GRAPHS / f"daily_count_{ratio}_{last.strftime('%Y-%m-%d')}.png"
        out.append(stamp_and_save(fig, path))
        plt.close(fig)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

#!/usr/bin/env python3
"""
The biggest year-over-year jumps in monthly CVE publishing.

Each bar is one calendar month, measured against the same month a year earlier.
July 2026 is the largest on record: 3,776 to 9,775, up 159 percent.

Restricted to months whose PRIOR-YEAR base was at least 1,000 CVEs. Without that
floor the ranking is meaningless: August 2001 went from 3 CVEs to 205, a 6,733
percent "increase" that says nothing about the modern program. The floor is a
chosen threshold and is disclosed on the chart.

Complete months only; the current partial month is excluded.

Data: NVD (published date), non-rejected CVEs.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from data import load_nvd
from rolling_config import data_asof
from style_social import (COLORS, DEFAULT_RATIOS, draw_header, figsize_for,
                          stamp_and_save)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

MIN_BASE = 1000  # prior-year floor; below this the percentage is noise
TOP_N = 12


def render(nvd=None, ratios=DEFAULT_RATIOS):
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)

    pub = pd.to_datetime(nvd["published"], utc=True, errors="coerce")
    d = nvd.assign(pub=pub)
    d = d[nvd["is_rejected"] != True].dropna(subset=["pub"])
    m = d.groupby(d["pub"].dt.tz_localize(None).dt.to_period("M")).size().sort_index()

    # complete months only
    full = m[m.index < pd.Period(asof, freq="M")]
    t = pd.DataFrame({"n": full})
    t["prev"] = [full.get(p - 12, float("nan")) for p in full.index]
    t = t.dropna()
    t["pct"] = 100 * (t["n"] / t["prev"] - 1)
    t = t[t["prev"] >= MIN_BASE].sort_values("pct", ascending=False).head(TOP_N)
    t = t.iloc[::-1]  # ascending, so the largest lands at the top

    labels = [p.strftime("%b %Y") for p in t.index]
    pcts = t["pct"].tolist()
    prevs = t["prev"].tolist()
    nows = t["n"].tolist()
    top = t.index[-1]
    is_top = [p == top for p in t.index]

    title1 = "The Biggest Year-Over-Year Jumps in Monthly CVEs"
    title2 = (f"Each month against the same month a year earlier. Months whose "
              f"prior-year total was at least {MIN_BASE:,}.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        y = np.arange(len(pcts))

        colors = [COLORS["alert"] if t_ else COLORS["primary"] for t_ in is_top]
        ax.barh(y, pcts, color=colors, edgecolor=COLORS["neutral"], linewidth=0.8,
                zorder=3)

        xmax = max(pcts)
        for yi, p, pr, nw, t_ in zip(y, pcts, prevs, nows, is_top):
            ax.text(p + xmax * 0.015, yi, f"+{p:.0f}%", va="center", ha="left",
                    fontsize=11.5 if t_ else 10.5, fontweight="bold",
                    color=COLORS["alert"] if t_ else COLORS["text"])

        # Two-line left labels: month (bold) over the actual counts.
        for yi, lab, pr, nw, t_ in zip(y, labels, prevs, nows, is_top):
            ax.text(-0.015, yi + 0.20, lab, transform=ax.get_yaxis_transform(),
                    ha="right", va="center", fontsize=11,
                    fontweight="bold", color=COLORS["text"])
            ax.text(-0.015, yi - 0.24, f"{int(pr):,} to {int(nw):,}",
                    transform=ax.get_yaxis_transform(), ha="right", va="center",
                    fontsize=8.5, color=COLORS["secondary"])

        ax.set_yticks([])
        ax.set_ylim(-0.6, len(pcts) - 0.4)
        ax.set_xlim(0, xmax * 1.14)
        ax.set_xticks(np.arange(0, xmax * 1.14, 40))
        ax.xaxis.set_major_formatter(lambda v, _: f"+{v:.0f}%")
        ax.tick_params(axis="x", labelsize=10, colors=COLORS["secondary"], length=0)
        ax.tick_params(axis="y", length=0)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05,
                 f"Complete months only, by NVD publication date, non-rejected. Months "
                 f"with a prior-year total below {MIN_BASE:,} are excluded: in the "
                 f"program's\nearly years a jump from 3 CVEs to 205 outranks everything "
                 f"modern. Source: NVD.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom",
                 linespacing=1.3)

        top_m = {"wide": 0.80, "square": 0.83, "portrait": 0.86}[ratio]
        left_m = {"wide": 0.17, "square": 0.21, "portrait": 0.23}[ratio]
        t1 = {"wide": 21, "square": 18, "portrait": 17}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.17, left=left_m, right=0.95)
        draw_header(fig, title1, title2, ratio=ratio, eyebrow_suffix="VOLUME",
                    title_size=t1)

        path = GRAPHS / f"yoy_month_growth_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

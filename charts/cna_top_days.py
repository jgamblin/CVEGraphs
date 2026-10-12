#!/usr/bin/env python3
"""
The biggest single-CNA publishing days, ranked.

Companion to ``cna_peak_day`` (one bar per CNA). Here a bar is one CNA on one
calendar day, so a CNA can appear several times. No highlight: the rank labels and
dates carry the "where does this week's batch land" reading on their own.

Data: CVE List V5 (assigner short name + publication date), non-rejected,
de-duplicated by CVE id.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from charts.cna_peak_day import CNA_NAMES, START_YEAR
from data import load_cvelist, load_nvd
from rolling_config import data_asof
from style_social import (COLORS, DEFAULT_RATIOS, draw_header, figsize_for,
                          stamp_and_save)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

TOP_N = 15


def _days(cl):
    pub = pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
    cl = cl.assign(pub=pub).dropna(subset=["pub"])
    cl = cl[cl["pub"].dt.year >= START_YEAR]
    cl["day"] = cl["pub"].dt.normalize()
    g = cl.groupby(["assigner_short_name", "day"]).size().reset_index(name="n")
    g = g.sort_values(["n", "day"], ascending=[False, True]).reset_index(drop=True)
    g["rank"] = np.arange(1, len(g) + 1)
    return g


def stats():
    """The ranked table plus the rank of every top-15 bar from the last 7 days."""
    cl = load_cvelist().drop_duplicates("cve_id")
    asof = data_asof(cl)
    g = _days(cl)
    week = g[(g["day"] >= asof - pd.Timedelta(days=6)) & (g["rank"] <= TOP_N)]
    return {
        "asof": asof.strftime("%Y-%m-%d"),
        "last_7_days_in_top": [(a, int(n), d.strftime("%Y-%m-%d"), int(r))
                               for a, n, d, r in zip(week["assigner_short_name"], week["n"],
                                                     week["day"], week["rank"])],
        "top": [(a, int(n), d.strftime("%Y-%m-%d"))
                for a, n, d in zip(g["assigner_short_name"].head(TOP_N),
                                   g["n"].head(TOP_N), g["day"].head(TOP_N))],
    }


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist().drop_duplicates("cve_id")
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(cl)

    g = _days(cl).head(TOP_N).iloc[::-1]
    counts = g["n"].tolist()
    cnas = [CNA_NAMES.get(a, a) for a in g["assigner_short_name"]]
    dates = list(g["day"])
    ranks = g["rank"].tolist()

    title1 = "The Biggest Single-Day CVE Batches by One CNA"
    title2 = f"Top {TOP_N} days one CNA published the most CVEs, 2017 to date."

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        y = np.arange(len(counts))
        ax.barh(y, counts, color=COLORS["primary"], edgecolor=COLORS["neutral"],
                linewidth=0.8, zorder=3)

        xmax = max(counts)
        count_texts = []
        for yi, c in zip(y, counts):
            count_texts.append(ax.annotate(
                f"{c:,}", xy=(c, yi), xytext=(5, 0), textcoords="offset points",
                va="center", ha="left", fontsize=11, fontweight="bold",
                color=COLORS["text"]))
        # An annotation anchored in data coords reports a 1px box until the figure
        # has been drawn once, so draw, then measure, then place the dates.
        fig.canvas.draw()
        for t, yi, c, d in zip(count_texts, y, counts, dates):
            w_pts = t.get_window_extent().width / fig.dpi * 72
            ax.annotate(d.strftime("%b %-d, %Y"), xy=(c, yi), xytext=(5 + w_pts + 6, 0),
                        textcoords="offset points", va="center", ha="left",
                        fontsize=9, color=COLORS["secondary"])

        for yi, r, name in zip(y, ranks, cnas):
            ax.text(-0.015, yi, f"#{r}  {name}", transform=ax.get_yaxis_transform(),
                    ha="right", va="center", fontsize=11, fontweight="bold",
                    color=COLORS["text"])

        ax.set_yticks([])
        ax.set_ylim(-0.6, len(counts) - 0.4)
        xtop = (int(xmax // 200) + 1) * 200
        ax.set_xlim(0, xtop * 1.12)
        ax.set_xticks(np.arange(0, xtop + 1, 200))
        ax.tick_params(axis="x", labelsize=10, colors=COLORS["secondary"], length=0)
        ax.tick_params(axis="y", length=0)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05,
                 f"Source: CVE List V5, non-rejected CVEs, data as of "
                 f"{asof.strftime('%b %-d, %Y')}.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom")

        top_m = {"wide": 0.80, "square": 0.83, "portrait": 0.86}[ratio]
        left_m = {"wide": 0.17, "square": 0.22, "portrait": 0.24}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.12, left=left_m, right=0.96)
        t1 = {"wide": 23, "square": 20, "portrait": 19}[ratio]
        draw_header(fig, title1, title2, ratio=ratio, eyebrow_suffix="CNA VOLUME",
                    title_size=t1)

        path = GRAPHS / f"cna_top_days_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    import pprint
    pprint.pprint(stats(), sort_dicts=False)
    for p in render():
        print(p)

#!/usr/bin/env python3
"""
The biggest single-day CVE batches from one CNA (modern era).

Ranks the largest number of CVEs a single CNA published on one calendar day
(by CVE.org publication date), 2017 to now. Oracle's July 2026 Critical Patch
Update set the record at 1,097 in one day. Half of the top ten single-day batches
are from 2026 and nine of ten are since 2024: single-CNA mega-batches (Oracle, Linux,
ZDI, Microsoft, Chrome) are a recent phenomenon and accelerating. Bars are colored
by era (2024 to date vs 2017-2023).

Data: CVE List V5 (assigner short name + publication date), non-rejected,
de-duplicated by CVE id.
"""


import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D

from cvegraphs.data import load_cvelist, load_nvd
from cvegraphs.paths import OUTPUT
from cvegraphs.rolling import data_asof
from cvegraphs.style import COLORS, DEFAULT_RATIOS, draw_header, figsize_for, stamp_and_save

DESCRIPTION = "Ranked bars: biggest single-day CVE batches by one CNA (modern era)"

GRAPHS = OUTPUT

START_YEAR = 2017  # "modern era"; earlier bursts are MITRE sole-assigner backfill
TOP_N = 10
# Fill for the pre-2024 "rare exception" bars. Darker than COLORS["light"] so it clears
# WCAG 3:1 on white (3.21:1) while staying distinct from the navy primary; set locally so
# other charts that share the global "light" token are unaffected.
PRE2024_FILL = "#7b91b4"

CNA_NAMES = {
    "zdi": "ZDI", "Linux": "Linux", "microsoft": "Microsoft", "Chrome": "Chrome",
    "mitre": "MITRE", "mozilla": "Mozilla", "Patchstack": "Patchstack",
    "@huntr_ai": "huntr", "GitHub_M": "GitHub", "oracle": "Oracle",
}


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist().drop_duplicates("cve_id")
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)

    pub = pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
    cl = cl.assign(pub=pub).dropna(subset=["pub"])
    cl["day"] = cl["pub"].dt.normalize()

    g = cl.groupby(["assigner_short_name", "day"]).size().reset_index(name="n")
    g = g[g["day"].dt.year >= START_YEAR].sort_values("n", ascending=False).head(TOP_N)
    g = g.iloc[::-1]  # ascending, so the largest ends up at the TOP after plotting

    counts = g["n"].tolist()
    cnas = [CNA_NAMES.get(a, a) for a in g["assigner_short_name"]]
    dates = list(g["day"])
    recent = [d.year >= 2024 for d in dates]  # the surge; pre-2024 is the rare exception

    title1 = "The Biggest Single-Day CVE Batches by a CNA"
    title2 = ("Most CVEs one CNA published in a single day, 2017 to date, by CVE.org "
              "publication date.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        y = np.arange(len(counts))

        colors = [COLORS["primary"] if r else PRE2024_FILL for r in recent]
        ax.barh(y, counts, color=colors, edgecolor=COLORS["neutral"], linewidth=0.8,
                zorder=3)

        xmax = max(counts)
        for yi, c in zip(y, counts):
            ax.text(c + xmax * 0.015, yi, f"{c}", va="center", ha="left",
                    fontsize=11, fontweight="bold", color=COLORS["text"])

        # Two-line left labels: CNA (bold) over the date (muted).
        for yi, name, d in zip(y, cnas, dates):
            ax.text(-0.015, yi + 0.18, name, transform=ax.get_yaxis_transform(),
                    ha="right", va="center", fontsize=11, fontweight="bold",
                    color=COLORS["text"])
            ax.text(-0.015, yi - 0.22, d.strftime("%b %-d, %Y"),
                    transform=ax.get_yaxis_transform(), ha="right", va="center",
                    fontsize=9, color=COLORS["secondary"])

        ax.set_yticks([])
        ax.set_ylim(-0.6, len(counts) - 0.4)
        xtop = (int(xmax // 200) + 1) * 200  # next 200 above the max, so bars sit in-scale
        ax.set_xlim(0, xtop * 1.03)
        ax.set_xticks(np.arange(0, xtop + 1, 200))
        ax.tick_params(axis="x", labelsize=10, colors=COLORS["secondary"], length=0)
        ax.tick_params(axis="y", length=0)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        # Legend: the color encodes the era (matches the headline "since 2024").
        ax.legend(handles=[
            Line2D([0], [0], marker="s", color="none", markerfacecolor=COLORS["primary"],
                   markeredgecolor="white", markersize=12, label="2024 to Date"),
            Line2D([0], [0], marker="s", color="none", markerfacecolor=PRE2024_FILL,
                   markeredgecolor="white", markersize=12, label="2017 to 2023")],
            loc="lower right", frameon=False, fontsize=10, handletextpad=0.4,
            labelspacing=0.5)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05,
                 "CVEs published by one CNA on one calendar day, non-rejected, 2017 to "
                 "date. Source: CVE List V5.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom")

        top_m = {"wide": 0.80, "square": 0.83, "portrait": 0.86}[ratio]
        left_m = {"wide": 0.16, "square": 0.20, "portrait": 0.22}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.13, left=left_m, right=0.96)
        t1 = {"wide": 23, "square": 20, "portrait": 19}[ratio]
        draw_header(fig, title1, title2, ratio=ratio, eyebrow_suffix="CNA VOLUME",
                    title_size=t1)

        path = GRAPHS / f"cna_burst_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

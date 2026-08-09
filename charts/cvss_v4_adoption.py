#!/usr/bin/env python3
"""
CVSS v4 adoption, and who is actually driving it.

Share of each year's CVEs that carry a CVSS v4 base score (read from CVE List,
the CNA's own vectors), stacked by who assigned it: the three heavy adopters
(VulnCheck, VulDB, GitHub) vs every other CNA. v4 shipped Nov 2023, so the series
starts at 2024 (its first full year); adoption looks broad, climbing from ~9% in
2024 to a third of all CVEs in 2026, but the long tail of CNAs grows only from ~4%
to ~10% and the whole rise is those three organizations.

v4 is read from CVE List, not the NVD feed, so the score reflects the CNA that
actually chose v4. Holding the scorer fixed (same record scored both ways), the
v4-v3 shift nets to about zero, so this is an adoption story, not a "v4 is
harsher/softer" story.

Data: CVE List V5 (published date, CNA CVSS vectors), non-rejected.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D

from data import load_cvelist, load_nvd
from rolling_config import data_asof
from style_social import (COLORS, DEFAULT_RATIOS, draw_header, figsize_for,
                          stamp_and_save)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

START_YEAR = 2024  # v4 shipped Nov 2023, so 2024 is its first full year; 2023 was ~0
TOP3 = ["VulnCheck", "VulDB", "GitHub_M"]
TOP3_LABEL = "VulnCheck, VulDB, GitHub"


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist().drop_duplicates("cve_id")
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)
    cur = asof.year

    pub = pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
    cl = cl.assign(pub=pub).dropna(subset=["pub"])
    cl["year"] = cl["pub"].dt.year

    years = list(range(START_YEAR, cur + 1))
    top3_pct, rest_pct = [], []
    for y in years:
        s = cl[cl["year"] == y]
        n = len(s)
        v4 = s[s["cvss_v4"].notna()]
        t3 = int(v4["assigner_short_name"].isin(TOP3).sum())
        top3_pct.append(100 * t3 / n)
        rest_pct.append(100 * (len(v4) - t3) / n)
    totals = [a + b for a, b in zip(top3_pct, rest_pct)]

    title1 = "CVSS v4 Score Coverage by Year"
    title2 = ("Share of each year's CVEs with a CVSS v4 score: the three heaviest "
              "adopters vs. all other CNAs.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        x = np.arange(len(years))
        w = 0.62

        ax.bar(x, top3_pct, w, color=COLORS["primary"], edgecolor=COLORS["neutral"],
               linewidth=0.9, zorder=3, label=f"{TOP3_LABEL} (3 CNAs)")
        ax.bar(x, rest_pct, w, bottom=top3_pct, color=COLORS["light"],
               edgecolor=COLORS["neutral"], linewidth=0.9, zorder=3, label="All other CNAs")

        lab_floor = max(totals) * 0.07  # only label a segment tall enough to hold text
        for xi, t3, rest, tot in zip(x, top3_pct, rest_pct, totals):
            # Reconcile the labels so the two segments sum to the bold total: keep the
            # emphasized 3-CNA number exact and let the light segment absorb the 0.1.
            tot_d = round(tot, 1)
            t3_d = round(t3, 1)
            rest_d = round(tot_d - t3_d, 1)
            ax.text(xi, tot + max(totals) * 0.02, f"{tot_d:.1f}%", ha="center",
                    va="bottom", fontsize=12, fontweight="bold", color=COLORS["text"])
            if t3 > lab_floor:  # 3-CNA share, inside the dark segment
                ax.text(xi, t3 / 2, f"{t3_d:.1f}%", ha="center", va="center",
                        fontsize=10, fontweight="bold", color="white")
            if rest > lab_floor:  # all-other share, inside the light segment
                ax.text(xi, t3 + rest / 2, f"{rest_d:.1f}%", ha="center", va="center",
                        fontsize=10, fontweight="bold", color=COLORS["text"])

        ax.set_xticks(x)
        xlabels = [str(y) for y in years]
        if years[-1] == cur:  # current year is partial
            xlabels[-1] = f"{cur} YTD"
        ax.set_xticklabels(xlabels, fontsize=12, color=COLORS["text"])
        ax.set_xlim(-0.6, len(years) - 0.4)
        ax.set_ylim(0, max(totals) * 1.18)
        ax.set_yticks(np.arange(0, max(totals) * 1.18, 10))
        ax.set_yticklabels([f"{v:.0f}%" for v in np.arange(0, max(totals) * 1.18, 10)],
                           fontsize=10, color=COLORS["secondary"])

        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])
        ax.tick_params(axis="both", length=0)
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        ax.legend(handles=[
            Line2D([0], [0], marker="s", color="none", markerfacecolor=COLORS["primary"],
                   markeredgecolor="white", markersize=13, label=f"{TOP3_LABEL} (3 CNAs)"),
            Line2D([0], [0], marker="s", color="none", markerfacecolor=COLORS["light"],
                   markeredgecolor="white", markersize=13, label="All other CNAs (200+)")],
            loc="upper left", bbox_to_anchor=(0.02, 0.98), frameon=False,
            fontsize=10.5, handletextpad=0.4, labelspacing=0.6)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05,
                 "CVSS v4 published Nov 2023. Score present on the CVE List record (CNA "
                 "vectors), non-rejected, by publication year. Source: CVE List V5.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom")

        top_m = {"wide": 0.80, "square": 0.83, "portrait": 0.86}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.15, left=0.08, right=0.96)
        draw_header(fig, title1, title2, ratio=ratio, eyebrow_suffix="SCORING")

        path = GRAPHS / f"cvss_v4_adoption_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

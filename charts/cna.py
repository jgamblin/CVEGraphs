#!/usr/bin/env python3
"""
CNA leaderboard — who publishes this year's CVEs.

Top CVE Numbering Authorities by count for the current year-to-date. High counts
reflect scope (platforms, ecosystems, research CNAs), not padding, so the
caption should say so.
"""

from pathlib import Path

import matplotlib.pyplot as plt

from data import load_cvelist
from rolling_config import current_year, data_asof, ytd_mask
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save, thousands_formatter

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
TOP_N = 12


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cve = load_cvelist()
    asof = data_asof(cve)
    asof_str = asof.strftime("%b %d, %Y")
    cur = current_year(asof)

    ytd = cve[ytd_mask(cve, cur, asof)]
    counts = ytd["assigner_short_name"].replace("", "unknown").value_counts().head(TOP_N)
    total = len(ytd)
    lead, lead_n = counts.index[0], int(counts.iloc[0])

    title1 = f"Who publishes {cur}'s CVEs"
    title2 = f"{lead} leads with {lead_n:,} ({lead_n/total*100:.0f}% of all published)"
    sub = "Top CVE Numbering Authorities year-to-date. High counts reflect scope, not padding."

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        names = list(counts.index)[::-1]
        vals = list(counts.values)[::-1]
        y = range(len(names))
        colors = [COLORS["alert"] if n == lead else COLORS["primary"] for n in names]
        ax.barh(list(y), vals, color=colors, edgecolor="white", height=0.74)
        for yi, v in zip(y, vals):
            ax.text(v + total * 0.006, yi, f"{v:,}", va="center", ha="left",
                    fontsize=12.5, fontweight="bold", color=COLORS["text"])

        ax.set_yticks(list(y))
        ax.set_yticklabels(names, fontsize=12.5, fontweight="bold")
        ax.xaxis.set_major_formatter(thousands_formatter())
        ax.set_xlim(0, max(vals) * 1.15)
        ax.grid(True, axis="x")
        ax.grid(False, axis="y")

        ax.text(0.0, -0.12,
                f"{cur} year-to-date through {asof.strftime('%b %d')}. Source: CVE List V5.",
                transform=ax.transAxes, fontsize=10.5, color=COLORS["neutral"], va="top")

        left = {"wide": 0.16, "square": 0.24, "portrait": 0.24}[ratio]
        top = {"wide": 0.80, "square": 0.84, "portrait": 0.86}[ratio]
        fig.subplots_adjust(top=top, bottom=0.13, left=left, right=0.95)
        if ratio == "wide":
            fig.text(0.04, 0.95, f"{title1}: {title2}", fontsize=18, fontweight="bold",
                     color=COLORS["text"], ha="left", va="top")
            fig.text(0.04, 0.88, sub, fontsize=12, color=COLORS["secondary"], ha="left", va="top")
        else:
            fig.text(0.05, 0.965, title1, fontsize=20, fontweight="bold",
                     color=COLORS["text"], ha="left", va="top")
            fig.text(0.05, 0.918, title2, fontsize=13.5, fontweight="bold",
                     color=COLORS["secondary"], ha="left", va="top")
            fig.text(0.05, 0.882, sub, fontsize=11, color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"cna_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof_str)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

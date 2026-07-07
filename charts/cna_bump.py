#!/usr/bin/env python3
"""
Who leads CVE issuance, month by month — a bump (rank-flow) chart.

Each line is a top CNA; its vertical position is its rank that month (1 = most
CVEs). Lines crossing show the issuer mix reshuffling. Rare on LinkedIn.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from data import load_cvelist
from rolling_config import data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
MONTHS = 7
TOP_N = 7
HIGHLIGHT = {"GitHub_M": COLORS["alert"], "VulnCheck": COLORS["primary"]}


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cve = load_cvelist()
    cpub = pd.to_datetime(cve["date_published"], utc=True, errors="coerce").dt.tz_convert(None)
    asof = data_asof(cve)

    last_complete = asof.tz_convert(None).to_period("M") - 1
    periods = [last_complete - i for i in range(MONTHS)][::-1]
    m = cpub.dt.to_period("M")

    # Rank CNAs within each month; keep the ones that ever crack the top TOP_N.
    per_month = {}
    for p in periods:
        vc = cve[m == p]["assigner_short_name"].replace("", "unknown").value_counts()
        per_month[p] = {name: rank + 1 for rank, name in enumerate(vc.index)}
    tracked = set()
    for p in periods:
        tracked.update([n for n, r in per_month[p].items() if r <= TOP_N])

    title1 = "Who assigns the CVEs keeps changing"
    title2 = f"Monthly rank of the top CVE issuers. Rank 1 = most CVEs published that month."
    labels = [p.strftime("%b") for p in periods]

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        x = list(range(len(periods)))
        for name in tracked:
            ys = [per_month[p].get(name) for p in periods]
            xs = [xi for xi, y in zip(x, ys) if y is not None and y <= TOP_N + 1]
            yy = [y for y in ys if y is not None and y <= TOP_N + 1]
            if len(yy) < 2:
                continue
            color = HIGHLIGHT.get(name, COLORS["light"])
            lw = 3.2 if name in HIGHLIGHT else 1.6
            z = 5 if name in HIGHLIGHT else 2
            ax.plot(xs, yy, "-o", color=color, lw=lw, markersize=7 if name in HIGHLIGHT else 5,
                    zorder=z, markerfacecolor=color, markeredgecolor="white")
            # Label at the right end.
            if ys[-1] is not None and ys[-1] <= TOP_N:
                ax.text(x[-1] + 0.12, ys[-1], name,
                        fontsize=10.5 if name in HIGHLIGHT else 9.5,
                        fontweight="bold" if name in HIGHLIGHT else "normal",
                        color=color if name in HIGHLIGHT else COLORS["secondary"],
                        va="center", ha="left", zorder=z)

        ax.set_ylim(TOP_N + 0.6, 0.4)  # rank 1 at top
        ax.set_yticks(range(1, TOP_N + 1))
        ax.set_yticklabels([f"#{i}" for i in range(1, TOP_N + 1)], fontsize=10)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=11)
        ax.set_xlim(-0.3, len(periods) + 1.3)
        for s in ("right", "top"):
            ax.spines[s].set_visible(False)
        ax.grid(True, axis="y", alpha=0.4)

        ax.text(0.0, -0.13, f"Top-{TOP_N} CNA rank by month. Source: CVE List V5.",
                transform=ax.transAxes, fontsize=10, color=COLORS["neutral"], va="top")

        top = {"wide": 0.82, "square": 0.86, "portrait": 0.88}[ratio]
        fig.subplots_adjust(top=top, bottom=0.13, left=0.09, right=0.90)
        fig.text(0.05, 0.965, title1, fontsize=20, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.918, title2, fontsize=11.5, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"cna_bump_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

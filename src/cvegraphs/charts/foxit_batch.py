#!/usr/bin/env python3
"""
Sunday curio: Foxit PDF Editor's 28-CVE release batch (2026-07-08), as a CVSS dot-plot.

Each CVE is a dot placed at its CVSS v3 score and colored by weakness family
(use-after-free / other memory-safety / everything else). Two things pop out: the
batch is nearly all memory-safety (the classes that dominate real-world
exploitation, see `exploited_cwe`), and 20 of the 28 land on the exact same score,
7.8, a tall single tower.

Data: CVE List V5 (Foxit-assigned CVEs for the target product/date).
"""

from collections import defaultdict

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D

from cvegraphs.data import load_cvelist
from cvegraphs.paths import OUTPUT
from cvegraphs.style import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

DESCRIPTION = "CVSS dot-plot (one-off): Foxit PDF Editor's 28-CVE single-day memory-safety batch"

GRAPHS = OUTPUT

ASSIGNER = "Foxit"
PRODUCT = "Foxit PDF Editor"
DAY = "2026-07-08"

UAF = "CWE-416"
MEM = {"CWE-416", "CWE-125", "CWE-787", "CWE-843", "CWE-763", "CWE-129",
       "CWE-120", "CWE-119", "CWE-824", "CWE-822", "CWE-476"}
PALETTE = [COLORS["primary"], COLORS["accent"], COLORS["light"]]  # uaf / other-mem / else


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist()
    d = pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
    f = cl[(cl["assigner_short_name"] == ASSIGNER) & (cl["product"] == PRODUCT)
           & (d.dt.date == pd.Timestamp(DAY).date())]
    n = len(f)
    n_uaf = int((f["cwe"] == UAF).sum())
    n_mem = int(f["cwe"].isin(MEM).sum())
    asof = pd.Timestamp(DAY, tz="UTC")

    def cat(c):
        return 0 if c == UAF else 1 if c in MEM else 2

    stacks = defaultdict(list)
    for score, cwe in zip(f["cvss_v3"], f["cwe"]):
        if pd.notna(score):
            stacks[round(float(score), 1)].append(cat(cwe))
    for s in stacks:
        stacks[s].sort()  # uaf at the bottom of each column
    tallest = max(len(v) for v in stacks.values())
    top_score = max(stacks, key=lambda s: len(stacks[s]))

    title1 = f"Foxit disclosed {n} PDF Editor CVEs in one release"
    title2 = (f"Nearly all are memory-safety bugs, and {len(stacks[top_score])} of the "
              f"{n} land on the exact same CVSS score: {top_score}.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        for s in sorted(stacks):
            col = stacks[s]
            for level, ct in enumerate(col):
                ax.scatter(s, level, s=330, color=PALETTE[ct], edgecolors="white",
                           linewidths=1.2, zorder=3)
            ax.text(s, len(col) + 0.6, str(len(col)), fontsize=9.5, fontweight="bold",
                    color=COLORS["text"], ha="center", va="bottom")

        ax.set_xlim(min(stacks) - 0.7, max(stacks) + 0.7)
        ax.set_ylim(-1.0, tallest + 2.0)
        ax.set_xlabel("CVSS v3 base score")
        ax.set_yticks([])
        ax.set_xticks(np.arange(5.5, 9.0, 0.5))
        for sp in ("left", "right", "top"):
            ax.spines[sp].set_visible(False)
        ax.tick_params(axis="y", length=0)
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.7)
        ax.set_axisbelow(True)

        ax.legend(handles=[
            Line2D([0], [0], marker="o", color="none", markerfacecolor=COLORS["primary"],
                   markeredgecolor="white", markersize=12, label=f"Use-after-free ({n_uaf})"),
            Line2D([0], [0], marker="o", color="none", markerfacecolor=COLORS["accent"],
                   markeredgecolor="white", markersize=12, label=f"Other memory-safety ({n_mem - n_uaf})"),
            Line2D([0], [0], marker="o", color="none", markerfacecolor=COLORS["light"],
                   markeredgecolor="white", markersize=12, label=f"Everything else ({n - n_mem})")],
            loc="upper left", bbox_to_anchor=(0.02, 0.98), frameon=False,
            fontsize=10, handletextpad=0.4, labelspacing=0.7)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        ax.text(0.0, -0.16, f"Each dot is one Foxit PDF Editor CVE published {DAY}, "
                "placed at its CVSS v3 score. Source: CVE List V5.",
                transform=ax.transAxes, fontsize=foot_size, color=COLORS["neutral"], va="top")

        top = {"wide": 0.84, "square": 0.86, "portrait": 0.88}[ratio]
        t1 = {"wide": 21, "square": 19, "portrait": 18}[ratio]
        fig.subplots_adjust(top=top, bottom=0.20, left=0.06, right=0.96)
        fig.text(0.05, 0.965, title1, fontsize=t1, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.915, title2, fontsize=11, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"foxit_batch_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

#!/usr/bin/env python3
"""
Sunday curio: Foxit PDF Editor shipped 28 CVEs in one day, nearly all memory-safety.

A 28-tile grid of the CVEs Foxit disclosed for PDF Editor on 2026-07-08, colored by
whether each is a use-after-free, another memory-safety bug, or something else. The
point, and the tie to the `exploited_cwe` post: 26 of 28 are memory-safety and 15 are
use-after-free, exactly the classes that dominate real-world exploitation.

Data: CVE List V5 (Foxit-assigned CVEs for the target product/date).
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D
from matplotlib.patches import Rectangle

from data import load_cvelist
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

ASSIGNER = "Foxit"
PRODUCT = "Foxit PDF Editor"
DAY = "2026-07-08"
COLS = 7

UAF = "CWE-416"
MEM = {"CWE-416", "CWE-125", "CWE-787", "CWE-843", "CWE-763", "CWE-129",
       "CWE-120", "CWE-119", "CWE-824", "CWE-822", "CWE-476"}  # memory-safety CWEs


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist()
    d = pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
    f = cl[(cl["assigner_short_name"] == ASSIGNER) & (cl["product"] == PRODUCT)
           & (d.dt.date == pd.Timestamp(DAY).date())]
    n = len(f)
    n_uaf = int((f["cwe"] == UAF).sum())
    n_mem = int(f["cwe"].isin(MEM).sum())
    n_other = n - n_mem
    asof = pd.Timestamp(DAY, tz="UTC")

    # One tile per CVE: use-after-free, other memory-safety, then everything else.
    tiles = ([COLORS["primary"]] * n_uaf
             + [COLORS["accent"]] * (n_mem - n_uaf)
             + [COLORS["light"]] * n_other)

    title1 = f"Foxit disclosed {n} PDF Editor CVEs in a single day"
    title2 = (f"{n_mem} of the {n} are memory-safety bugs. {n_uaf} are use-after-free, "
              "one of the classes attackers exploit most.")

    rows_grid = int(np.ceil(n / COLS))
    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        ax.set_aspect("equal")
        ax.axis("off")
        gap = 0.12
        for i, color in enumerate(tiles):
            r, c = divmod(i, COLS)
            y = rows_grid - 1 - r
            ax.add_patch(Rectangle((c + gap / 2, y + gap / 2), 1 - gap, 1 - gap,
                                   facecolor=color, edgecolor="white", linewidth=1.5))
        ax.set_xlim(-0.3, COLS + 0.3)
        ax.set_ylim(-1.4, rows_grid + 0.3)

        ax.legend(handles=[
            Line2D([0], [0], marker="s", color="none", markerfacecolor=COLORS["primary"],
                   markersize=13, label=f"Use-after-free ({n_uaf})"),
            Line2D([0], [0], marker="s", color="none", markerfacecolor=COLORS["accent"],
                   markersize=13, label=f"Other memory-safety ({n_mem - n_uaf})"),
            Line2D([0], [0], marker="s", color="none", markerfacecolor=COLORS["light"],
                   markersize=13, label=f"Everything else ({n_other})")],
            loc="upper center", bbox_to_anchor=(0.5, 0.02), ncol=3, frameon=False,
            fontsize=10.5, handletextpad=0.5, columnspacing=2.0)

        ax.text(COLS / 2, -1.32, f"Foxit PDF Editor CVEs published {DAY}. "
                "Each tile is one CVE. Source: CVE List V5.",
                fontsize=8.5, color=COLORS["neutral"], ha="center", va="center")

        top = {"wide": 0.86, "square": 0.88, "portrait": 0.89}[ratio]
        t1 = {"wide": 21, "square": 19, "portrait": 18}[ratio]
        fig.subplots_adjust(top=top, bottom=0.06, left=0.05, right=0.95)
        fig.text(0.05, 0.965, title1, fontsize=t1, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.915, title2, fontsize=11, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"foxit_batch_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

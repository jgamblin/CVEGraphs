#!/usr/bin/env python3
"""
Ridgeline (joyplot) of CVSS severity by year.

One filled density ridge per year, stacked and overlapping, showing how the
distribution of CVSS scores has shifted over time. Rarely seen on LinkedIn.

Uses the best-available CVSS base score per CVE (v4 when assigned, else v3) so
coverage stays near 100% every year; a v3-only view would drop the fast-growing
share of v4-scored CVEs and bias the trend.
"""

from pathlib import Path

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D

from data import load_nvd
from rolling_config import current_year, data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
N_YEARS = 9


def _smooth_density(vals, bins=60, rng=(0, 10)):
    h, edges = np.histogram(vals, bins=bins, range=rng, density=True)
    k = np.array([0.05, 0.24, 0.42, 0.24, 0.05])  # small gaussian-ish smoother
    h = np.convolve(h, k, mode="same")
    centers = (edges[:-1] + edges[1:]) / 2
    return centers, h


def render(nvd=None, ratios=DEFAULT_RATIOS):
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)
    cur = current_year(asof)
    years = list(range(cur - N_YEARS + 1, cur + 1))

    # Split CVSS v3 and v4 into their own ridges for years where v4 has taken
    # hold (>= ~a few hundred scores, i.e. 2024 on). Earlier years are v3 only.
    # Color encodes the version, so you can see v4 scoring lower than v3.
    VER = {"v3": COLORS["primary"], "v4": "#8fb0d4"}  # navy vs steel blue
    rows = []  # (label, values, ver)
    for y in years:
        d = nvd[nvd["year"] == y]
        v3 = d["cvss_v3"].dropna().values
        v4 = d["cvss_v4"].dropna().values
        if len(v4) >= 200:
            rows.append((f"{y} v3", v3, "v3"))
            rows.append((f"{y} v4", v4, "v4"))
        elif len(v3) > 50:
            rows.append((str(y), v3, "v3"))

    ridges = []
    for label, vals, ver in rows:
        x, d = _smooth_density(vals)
        ridges.append((label, x, d, float(np.mean(vals)), ver))
    dmax = max(d.max() for _, _, d, _, _ in ridges)
    overlap = 1.7  # >1 makes ridges overlap like a proper joyplot

    title1 = "How severe are CVEs, year by year?"
    title2 = "From 2024, CVSS v3 and v4 are shown separately. v4 has been scoring lower."

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        n = len(ridges)
        for i, (label, x, d, mean_cvss, ver) in enumerate(ridges):
            base = (n - 1 - i)  # newest at top
            yv = base + d / dmax * overlap
            ax.fill_between(x, base, yv, color=VER[ver], alpha=0.9, zorder=i, lw=0)
            ax.plot(x, yv, color="white", lw=1.0, zorder=i)
            ax.text(-0.2, base + 0.1, label, fontsize=9.5, fontweight="bold",
                    color=COLORS["text"], ha="right", va="bottom")
            # Average marker: solid red vertical line at this ridge's mean, so
            # the shift between v3 and v4 (and across years) stands out.
            dm = float(np.interp(mean_cvss, x, d))
            ax.plot([mean_cvss, mean_cvss], [base, base + dm / dmax * overlap],
                    color=COLORS["alert"], lw=2.0, solid_capstyle="round", zorder=100)

        ax.legend(handles=[mpatches.Patch(color=VER["v3"], label="CVSS v3"),
                           mpatches.Patch(color=VER["v4"], label="CVSS v4"),
                           Line2D([0], [0], color=COLORS["alert"], lw=2.0, label="Yearly average")],
                  loc="upper right", frameon=False, fontsize=10.5)

        ax.set_xlim(0, 10)
        ax.set_ylim(-0.3, n + overlap)
        ax.set_xlabel("CVSS base score")
        ax.set_yticks([])
        ax.set_xticks(range(0, 11, 2))
        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.grid(False)

        ax.text(0.0, -0.13,
                f"CVSS base score by year. v3 and v4 split out from 2024. Source: NVD.",
                transform=ax.transAxes, fontsize=10, color=COLORS["neutral"], va="top")

        top = {"wide": 0.82, "square": 0.86, "portrait": 0.88}[ratio]
        fig.subplots_adjust(top=top, bottom=0.14, left=0.17, right=0.96)
        fig.text(0.05, 0.965, title1, fontsize=20, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.918, title2, fontsize=11.5, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"ridgeline_severity_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

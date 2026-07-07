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

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

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

    # Best-available CVSS base score: v4 when present, else v3. Using both keeps
    # coverage near 100% every year; v3-only silently drops the growing share of
    # v4-scored CVEs (35% in 2026), which would bias the trend.
    score = nvd["cvss_v4"].where(nvd["cvss_v4"].notna(), nvd["cvss_v3"])
    nvd = nvd.assign(_cvss=score)

    ridges = []
    for y in years:
        v = nvd[(nvd["year"] == y)]["_cvss"].dropna().values
        if len(v) > 50:
            x, d = _smooth_density(v)
            ridges.append((y, x, d, float(np.mean(v))))
    dmax = max(d.max() for _, _, d, _ in ridges)
    overlap = 1.9  # >1 makes ridges overlap like a proper joyplot

    title1 = "How severe are CVEs, year by year?"
    title2 = "CVSS distribution by year. The dashed line marks each year's average."

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        n = len(ridges)
        for i, (y, x, d, mean_cvss) in enumerate(ridges):
            base = (n - 1 - i)  # newest at top
            yv = base + d / dmax * overlap
            shade = plt.cm.Blues(0.35 + 0.5 * i / max(n - 1, 1))
            ax.fill_between(x, base, yv, color=shade, alpha=0.9, zorder=i, lw=0)
            ax.plot(x, yv, color="white", lw=1.0, zorder=i)
            ax.text(-0.15, base + 0.1, str(y), fontsize=11, fontweight="bold",
                    color=COLORS["text"], ha="right", va="bottom")
            # Average marker: a dashed vertical line at the year's mean CVSS,
            # drawn on top so the rightward drift of the center is visible.
            dm = float(np.interp(mean_cvss, x, d))
            ax.plot([mean_cvss, mean_cvss], [base, base + dm / dmax * overlap],
                    color=COLORS["text"], lw=1.2, ls=(0, (2, 1.5)), alpha=0.8, zorder=100)

        ax.set_xlim(0, 10)
        ax.set_ylim(-0.3, n + overlap)
        ax.set_xlabel("CVSS base score")
        ax.set_yticks([])
        ax.set_xticks(range(0, 11, 2))
        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.grid(False)

        ax.text(0.0, -0.13,
                f"CVSS base score (v3, or v4 when that is what was assigned), through {cur}. "
                f"Source: NVD.",
                transform=ax.transAxes, fontsize=10, color=COLORS["neutral"], va="top")

        top = {"wide": 0.82, "square": 0.86, "portrait": 0.88}[ratio]
        fig.subplots_adjust(top=top, bottom=0.14, left=0.12, right=0.96)
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

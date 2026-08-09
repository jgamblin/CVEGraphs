#!/usr/bin/env python3
"""
The share of CVEs whose CVE.org record credits who found or reported the bug.

For years, crediting was rare; it has climbed from ~2% of CVEs in the late 2010s
to about half in 2025. This is the precondition for any "reporters per CVE"
analysis: before ~2021 the record almost never said who found the bug, so the
signal simply did not exist in the data.

Reads processed/credits_flags.parquet (built by scripts_precompute_credits.py).
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from style_social import (COLORS, DEFAULT_RATIOS, draw_header, figsize_for,
                          stamp_and_save)
from rolling_config import today_utc

PROCESSED = Path(__file__).resolve().parent.parent / "processed"
GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

FIRST_YEAR = 2016
LAST_YEAR = 2025  # full years only; the current partial year is noted in copy


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cr = pd.read_parquet(PROCESSED / "credits_flags.parquet")
    cr = cr[(cr["year"] >= FIRST_YEAR) & (cr["year"] <= LAST_YEAR)]
    share = cr.assign(has=cr["n_finder"] > 0).groupby("year")["has"].mean() * 100
    years = list(share.index)
    vals = list(share.values)
    stamp = today_utc()

    title1 = "The Share of CVEs That Name Who Found the Bug"
    title2 = ("CVEs whose CVE.org record credits a finder or reporter, by CVE ID "
              "year.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        for xi, (y, v) in enumerate(zip(years, vals)):
            last = y == LAST_YEAR
            ax.bar(xi, v, width=0.74, color=COLORS["alert"] if last else COLORS["primary"],
                   edgecolor="white", linewidth=1.0, zorder=3)
            ax.text(xi, v + 1.0, f"{v:.0f}%", ha="center", va="bottom",
                    fontsize=10.5 if last else 9.5,
                    fontweight="bold" if last else "normal",
                    color=COLORS["alert"] if last else COLORS["text"])

        ax.set_xticks(range(len(years)))
        ax.set_xticklabels([str(y) for y in years], fontsize=10.5, color=COLORS["text"])
        ax.set_xlim(-0.6, len(years) - 0.4)
        ax.set_ylim(0, max(vals) * 1.2)
        ax.set_yticks([])
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])
        ax.tick_params(axis="both", length=0)
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05,
                 "Credit = a finder or reporter entry in the CVE.org (CNA) record. "
                 "Non-rejected CVEs by ID year. Source: CVE List V5.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom")

        top_m = {"wide": 0.80, "square": 0.83, "portrait": 0.86}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.15, left=0.07, right=0.96)
        draw_header(fig, title1, title2, ratio=ratio, eyebrow_suffix="DISCLOSURE")

        path = GRAPHS / f"credit_rise_{ratio}_{stamp.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

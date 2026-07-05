#!/usr/bin/env python3
"""
Pace Tracker — the evergreen weekly workhorse.

CVEs published year-to-date, measured over the SAME elapsed window (Jan 1
through today's month/day) in every year, so the bars are apples-to-apples even
though the current year is still open. The current year is highlighted; the
headline is the takeaway, not a chart label ("one new CVE every N minutes").

Renders one PNG per aspect ratio into ``graphs/``.
"""

from pathlib import Path

import matplotlib.pyplot as plt

from data import load_nvd
from rolling_config import current_year, data_asof, elapsed_days, ytd_mask
from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    figsize_for,
    stamp_and_save,
    thousands_formatter,
)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
YEARS_SHOWN = 11  # trailing window; reads cleanly on a phone


def _series(nvd, asof):
    """YTD count per year over the trailing window, apples-to-apples."""
    cur = current_year(asof)
    years = list(range(cur - YEARS_SHOWN + 1, cur + 1))
    counts = {y: int(ytd_mask(nvd, y, asof).sum()) for y in years}
    return years, counts, cur


def _headline(counts, cur, asof):
    """Return (title, subtitle) strings built from the live numbers."""
    n = counts[cur]
    days = elapsed_days(cur, asof)
    per_day = n / days if days else 0
    minutes = (24 * 60) / per_day if per_day else 0
    prior = counts.get(cur - 1, 0)
    yoy = ((n - prior) / prior * 100) if prior else 0
    title = f"{n:,} CVEs published so far in {cur}"
    sub = (
        f"One new CVE every {minutes:.1f} minutes  ·  {per_day:.0f}/day  ·  "
        f"{yoy:+.0f}% vs {cur - 1} at the same point"
    )
    return title, sub


def render(nvd=None, ratios=DEFAULT_RATIOS):
    """Render the Pace Tracker for each ratio. Returns list of output paths."""
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)
    asof_str = asof.strftime("%b %d, %Y")
    years, counts, cur = _series(nvd, asof)
    title, sub = _headline(counts, cur, asof)

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        vals = [counts[y] for y in years]
        colors = [COLORS["alert"] if y == cur else COLORS["primary"] for y in years]
        bars = ax.bar(years, vals, color=colors, edgecolor="white", linewidth=0.8)

        # Label the current-year bar prominently.
        for y, b in zip(years, bars):
            if y == cur:
                ax.text(
                    b.get_x() + b.get_width() / 2, b.get_height(),
                    f"{counts[y]:,}",
                    ha="center", va="bottom",
                    fontsize=16, fontweight="bold", color=COLORS["alert"],
                )

        ax.set_xticks(years)
        ax.set_xticklabels([str(y) for y in years], rotation=0)
        ax.yaxis.set_major_formatter(thousands_formatter())
        ax.margins(y=0.20)
        # Elapsed-window caption keeps the comparison honest.
        ax.text(
            0.0, -0.13,
            f"Year-to-date through {asof.strftime('%b %d')} in each year "
            f"({elapsed_days(cur, asof)} days). Source: NVD.",
            transform=ax.transAxes, fontsize=11, color=COLORS["neutral"], va="top",
        )

        # Header lives in the reserved top margin (figure coords) so it never
        # collides with the plot regardless of aspect ratio.
        top = {"wide": 0.80, "square": 0.85, "portrait": 0.87}[ratio]
        fig.subplots_adjust(top=top, bottom=0.15, left=0.11, right=0.96)
        fig.text(0.06, 0.965, title, fontsize=21, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.06, 0.905, sub, fontsize=13, color=COLORS["secondary"],
                 ha="left", va="top")

        path = GRAPHS / f"pace_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof_str)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

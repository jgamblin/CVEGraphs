#!/usr/bin/env python3
"""
Pace Tracker — the evergreen weekly workhorse.

CVEs published year-to-date, measured over the SAME elapsed window (Jan 1
through today's month/day) in every year, so the bars are apples-to-apples even
though the current year is still open. The current year is highlighted.

A dashed reference line marks the PRIOR year's FULL-year total. That line is the
milestone the feed actually cares about: the day the current year's partial count
passes last year's complete one. Drawing it every render means the chart carries
its own headline on the day the crossing happens, and shows the remaining gap on
every other day.

Data: CVE List V5 (published, non-rejected, by publication date). This is the
same table the per-CNA copy is written from, so the chart and the post never
disagree; NVD lags it by a few dozen records.

Renders one PNG per aspect ratio into ``graphs/``.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from data import load_cvelist
from rolling_config import (
    current_year,
    data_asof,
    elapsed_days,
    recent_mask,
    ytd_mask,
)
from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
    thousands_formatter,
)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
YEARS_SHOWN = 11  # trailing window; reads cleanly on a phone
RATE_WINDOW = 30  # days, for the "per day" figure in the subtitle


def _load():
    """CVE List V5, published and non-rejected, with a publish-date column."""
    df = load_cvelist()
    if "is_published" in df.columns:
        df = df[df["is_published"]]
    return df


def _series(df, asof):
    """YTD count per year over the trailing window, apples-to-apples."""
    cur = current_year(asof)
    years = list(range(cur - YEARS_SHOWN + 1, cur + 1))
    counts = {y: int(ytd_mask(df, y, asof).sum()) for y in years}
    return years, counts, cur


def _prior_full_total(df, cur):
    """Full-calendar-year published total for ``cur - 1``."""
    dates = pd.to_datetime(df["date_published"], utc=True, errors="coerce")
    return int((dates.dt.year == cur - 1).sum())


def _headline(df, counts, cur, asof, prior_full):
    """Return (title, [subtitle parts]). Title Case per the house heading rule."""
    n = counts[cur]
    per_day = int(recent_mask(df, RATE_WINDOW, asof).sum()) / RATE_WINDOW
    prior_ytd = counts.get(cur - 1, 0)
    yoy = ((n - prior_ytd) / prior_ytd * 100) if prior_ytd else 0

    if n >= prior_full:
        title = f"{cur} Has Published More CVEs Than All of {cur - 1}"
        lead = f"{n:,} year to date, past the {prior_full:,} full-year {cur - 1} total"
    else:
        title = f"{n:,} CVEs Published So Far in {cur}"
        lead = f"{prior_full - n:,} short of the {prior_full:,} full-year {cur - 1} total"

    parts = [
        lead,
        f"{per_day:.0f}/day over the last {RATE_WINDOW} days",
        f"{yoy:+.0f}% vs {cur - 1} at the same point",
    ]
    return title, parts


def render(nvd=None, ratios=DEFAULT_RATIOS):
    """Render the Pace Tracker for each ratio. Returns list of output paths.

    ``nvd`` is accepted for the shared make.py dispatch signature and ignored:
    this chart reads CVE List V5 so its totals match the per-CNA numbers the
    post copy is written from.
    """
    df = _load()
    asof = data_asof(df)
    years, counts, cur = _series(df, asof)
    prior_full = _prior_full_total(df, cur)
    title, sub_parts = _headline(df, counts, cur, asof, prior_full)
    days = elapsed_days(cur, asof)

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        vals = [counts[y] for y in years]
        colors = [COLORS["alert"] if y == cur else COLORS["primary"] for y in years]
        # zorder=4 so the current-year bar is drawn OVER the reference line. With
        # the line on top, a sub-pixel margin reads as the bar stopping AT the
        # line, i.e. the chart showing the milestone not happening.
        bars = ax.bar(years, vals, color=colors, edgecolor="white", linewidth=0.8,
                      zorder=4)
        # Bars sit above the hairline grid; otherwise the gridlines band the
        # current-year bar and read as segments on a post about decomposition.
        ax.set_axisbelow(True)

        # Headroom for the reference line and its label, measured against the
        # taller of (current bar, prior-year full total).
        ax.set_ylim(0, max(max(vals), prior_full) * 1.12)

        # The milestone itself: last year's FULL total, which the YTD bars are
        # racing. Label right-anchored over the short early-year bars.
        ax.axhline(prior_full, color=COLORS["primary"], linestyle=(0, (6, 4)),
                   linewidth=1.8, zorder=2)
        ax.text(
            years[0] - 0.4, prior_full, f"All of {cur - 1}: {prior_full:,}",
            ha="left", va="bottom", fontsize=12, fontweight="bold",
            color=COLORS["primary"], zorder=5,
        )

        # Label the current-year bar. State the margin explicitly: on the day of
        # a crossing it is a fraction of a pixel, so the bar geometry can never
        # show it on its own.
        margin = counts[cur] - prior_full
        for y, b in zip(years, bars):
            if y == cur:
                label = f"{counts[y]:,}"
                if margin >= 0:
                    label += f"   +{margin:,}"
                ax.text(
                    b.get_x() + b.get_width() / 2, b.get_height(),
                    label,
                    ha="center", va="bottom",
                    fontsize=15, fontweight="bold", color=COLORS["alert"],
                    zorder=5,
                )

        ax.set_xticks(years)
        ax.set_xticklabels([str(y) for y in years], rotation=0)
        ax.yaxis.set_major_formatter(thousands_formatter())

        # Wide fits the subtitle on one line; the narrow ratios need two.
        sub = ("  ·  ".join(sub_parts) if ratio == "wide"
               else f"{sub_parts[0]}\n{sub_parts[1]}  ·  {sub_parts[2]}")

        top = {"wide": 0.78, "square": 0.79, "portrait": 0.81}[ratio]
        # Wide is short, so its tick labels and footnote need proportionally
        # more room between them than the tall ratios do.
        bottom = {"wide": 0.24, "square": 0.20, "portrait": 0.17}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom, left=0.11, right=0.96)
        t1 = {"wide": 26, "square": 19, "portrait": 19}[ratio]
        draw_header(fig, title, sub, ratio, eyebrow_suffix="Volume", title_size=t1)

        # Footnote in FIGURE coords so it hangs on the header's left margin
        # rather than the axes' (which created a third left edge). Wrapped so it
        # never runs under the corner stamp.
        foot_size = {"wide": 9.5, "square": 8.5, "portrait": 8.5}[ratio]
        fig.text(
            0.05, 0.045,
            f"Bars run Jan 1 through {asof.strftime('%b %-d')} in each year; "
            f"the dashed line is all of {cur - 1}.\n"
            "Source: CVE List V5, published and non-rejected, by publication date.",
            fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom",
            linespacing=1.5,
        )

        path = GRAPHS / f"pace_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

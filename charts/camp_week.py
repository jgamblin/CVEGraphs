#!/usr/bin/env python3
"""
Does CVE publishing slow down during "hacker summer camp" week?

Folklore says the CVE feed goes quiet the week the industry decamps to Las Vegas
for BSidesLV, Black Hat USA and DEF CON. It does not. For each year 2016-2025 we
take the Monday-Sunday week containing DEF CON and compare its CVE count with the
twelve nearby weeks (six before, six after) in the same year. The conference week
lands below its local median in six of ten years and above it in four, averaging
rank 6.3 of 13 where a randomly chosen week would average 7.0. That is noise.

Conference week is defined by DEF CON because it is the anchor: the Mon-Sun week
containing DEF CON also contains the Black Hat USA briefings (Wed-Thu) and
BSidesLV (Tue-Wed) in all ten years.

The clock here is CVE List V5 ``date_published`` (the CNA's own publication
timestamp), not NVD's ``published``. NVD's is the wrong instrument for this
question: it records NVD ingestion, and it has hard multi-day zero gaps (for
example Aug 9-11, 2024) that would read as a conference-week shutdown that never
happened.

Data: CVE List V5 (CNA publication date), non-rejected, published records.
"""

import textwrap
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from data import load_cvelist
from rolling_config import data_asof
from style_social import (COLORS, DEFAULT_RATIOS, MONO_FONT, RATIOS, SAVE_DPI,
                          draw_header, figsize_for, stamp_and_save)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

# DEF CON start date (Thursday) by year. Verified against defcon.org's archives
# and the DEF CON Wikipedia table. DEF CON 28 (2020) ran virtually as "Safe Mode"
# on its scheduled dates, which is why 2020 is kept but flagged in the footnote.
DEFCON_START = {
    2016: "2016-08-04",  # DC 24, Paris / Bally's
    2017: "2017-07-27",  # DC 25, Caesars Palace (the only July year in the set)
    2018: "2018-08-09",  # DC 26
    2019: "2019-08-08",  # DC 27
    2020: "2020-08-06",  # DC 28, virtual
    2021: "2021-08-05",  # DC 29
    2022: "2022-08-11",  # DC 30
    2023: "2023-08-10",  # DC 31
    2024: "2024-08-08",  # DC 32
    2025: "2025-08-07",  # DC 33
}

OFFSETS = range(-6, 7)  # weeks either side of conference week


def _weekly_series(cl):
    """Daily CVE counts by CNA publication date, gap-filled with zeros."""
    day = (pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
           .dt.tz_localize(None).dt.normalize())
    daily = day.value_counts().sort_index()
    idx = pd.date_range("2015-01-01", daily.index.max(), freq="D")
    return daily.reindex(idx, fill_value=0)


def compute(cl=None):
    """Per-year weekly counts around conference week, plus the summary stats."""
    if cl is None:
        cl = load_cvelist()
    cl = cl[cl["is_published"] == True]  # noqa: E712 - explicit, matches house style
    daily = _weekly_series(cl)

    rows = []
    for year, start in DEFCON_START.items():
        dc = pd.Timestamp(start)
        w0 = dc - pd.Timedelta(days=dc.weekday())  # Monday of conference week
        weeks = {}
        for k in OFFSETS:
            a = w0 + pd.Timedelta(weeks=k)
            weeks[k] = int(daily.loc[a:a + pd.Timedelta(days=6)].sum())
        near = [v for k, v in weeks.items() if k != 0]
        conf = weeks[0]
        med = float(np.median(near))
        rows.append(dict(
            year=year, week_start=w0, defcon=dc, weeks=weeks, conf=conf,
            median_near=med,
            pct=100 * (conf / med - 1) if med else np.nan,
            rank=int(sum(1 for v in near if v < conf)) + 1,
        ))
    return rows


def summary(rows):
    pct = np.array([r["pct"] for r in rows])
    rank = np.array([r["rank"] for r in rows])
    # Pooled conference-week position, as a ratio to each year's typical week.
    # Median (not mean) so 2016's small-denominator 3.6x cannot drag the summary.
    ratios = np.array([r["conf"] / r["median_near"] for r in rows])
    return dict(
        n=len(rows), median_pct=float(np.median(pct)),
        below=int((pct < 0).sum()), mean_rank=float(rank.mean()),
        expected_rank=(len(OFFSETS) + 1) / 2,
        median_ratio=float(np.median(ratios)),
        q1_ratio=float(np.percentile(ratios, 25)),
        q3_ratio=float(np.percentile(ratios, 75)),
    )


def render(nvd=None, cl=None, ratios=DEFAULT_RATIOS):
    # This chart is CNA-clock only; `nvd` is accepted so make.py can pass its
    # shared frame, but it is deliberately unused.
    if cl is None:
        cl = load_cvelist()
    asof = data_asof(cl)
    rows = compute(cl)
    s = summary(rows)

    title1 = "CVE Volume in Hacker Summer Camp Week"
    # One line only. Everything else the reader needs is an encoding, not a
    # sentence: dot position against the 1x reference carries the magnitude, so
    # the chart does not need a delta column or a paragraph explaining one.
    title2 = ("Red tents are conference week. Pale dots are the six weeks either side, "
              "same year.")

    method = (
        "Conference week is the Monday-Sunday week containing DEF CON, BSidesLV and the Black "
        "Hat USA briefings. Counts by CVE List V5 publication date, non-rejected. "
        "Source: CVE List V5.")
    verdict = (f"Conference week averages rank {s['mean_rank']:.1f} of 13 nearby weeks, against "
               f"{s['expected_rank']:.1f} for a random week. Less than one rank.")

    # Character budgets per ratio for hand-wrapped footnote text (canvas width
    # minus margins, divided by the average glyph width at the footnote size).
    WRAP = {"wide": 155, "square": 108, "portrait": 108}
    FOOT = {"wide": 9, "square": 8, "portrait": 8}

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        n = len(rows)
        # x is a RATIO to each year's local median, on a log scale. A ratio keeps
        # every year on one axis despite 7x growth in volume, and the log keeps
        # 2016 (whose weeks run 0.34x to 4.27x off a 68-CVE median) from
        # flattening the other nine years.
        XLO, XHI = 0.30, 4.8
        TICKS = [(0.5, "0.5x"), (1.0, "1x"), (2.0, "2x"), (4.0, "4x")]

        # Pooled summary sits below the ten year rows, past a separator.
        sep_y = -(n - 1) - 0.85
        sum_y = -(n - 1) - 1.75

        ax.set_xscale("log")
        ax.set_xlim(XLO, XHI)
        ax.set_ylim(sum_y - 0.80, 0.85)

        # reference gridlines, then the 1x reference the whole chart hangs on
        for xv, _ in TICKS:
            if xv != 1.0:
                ax.axvline(xv, color=COLORS["grid"], lw=0.9, zorder=1)
        ax.axvline(1.0, color=COLORS["text"], ls=(0, (4, 3)), lw=1.3, zorder=2)

        # x in axes fraction, y in data coords: lets the label columns sit
        # outside the log axis without inventing fake data positions.
        tr = ax.get_yaxis_transform()

        for i, r in enumerate(rows):
            y0 = -i
            med = r["median_near"]
            ax.plot([XLO, XHI], [y0, y0], color=COLORS["grid"], lw=0.7, zorder=1)

            near = [r["weeks"][k] / med for k in OFFSETS if k != 0]
            ax.scatter(near, [y0] * len(near), s=34, facecolor=COLORS["accent"],
                       edgecolor="white", linewidth=0.7, alpha=0.9, zorder=4)
            # Conference week breaks the house palette on purpose: a red triangle
            # reads as a tent, and shape plus colour means the highlight survives
            # both a thumbnail and colour-vision deficiency.
            ax.scatter([r["conf"] / med], [y0], s=150, marker="^",
                       facecolor=COLORS["alert"], edgecolor="white", linewidth=1.2,
                       zorder=6)

            ax.text(-0.030, y0, str(r["year"]), fontfamily=MONO_FONT, fontsize=12,
                    fontweight="bold", color=COLORS["text"], ha="right", va="center",
                    transform=tr, clip_on=False)

        # ---- pooled summary: where conference week lands across all ten years ----
        ax.plot([XLO, XHI], [sep_y] * 2, color=COLORS["grid"], lw=1.2, zorder=1)
        ax.plot([s["q1_ratio"], s["q3_ratio"]], [sum_y] * 2, color=COLORS["neutral"],
                lw=3.4, solid_capstyle="round", zorder=4)
        ax.scatter([s["median_ratio"]], [sum_y], s=210, marker="^",
                   facecolor=COLORS["alert"], edgecolor="white", linewidth=1.4,
                   zorder=6)
        ax.text(-0.030, sum_y, "10-YEAR\nMEDIAN", fontfamily=MONO_FONT, fontsize=9.5,
                fontweight="bold", color=COLORS["text"], ha="right", va="center",
                transform=tr, clip_on=False, linespacing=1.35)
        ax.text(s["median_ratio"], sum_y - 0.42,
                f"{s['median_pct']:+.0f}%".replace("+", "+").replace("-", "−"),
                fontfamily=MONO_FONT, fontsize=12, fontweight="bold",
                color=COLORS["alert"], ha="center", va="top")
        ax.text(s["q3_ratio"] * 1.09, sum_y, "middle half of the ten years",
                fontsize=8.5, color=COLORS["secondary"], ha="left", va="center")

        # Labels the 1x REFERENCE, not the navy dots: the dashed line is the
        # typical nearby week, and calling it "conference week" would invert the
        # whole encoding.
        ax.text(1.0, 0.50, "TYPICAL WEEK", fontfamily=MONO_FONT, fontsize=9,
                fontweight="bold", color=COLORS["text"], ha="center", va="bottom",
                bbox=dict(facecolor="white", edgecolor="none", pad=2.5), zorder=8)

        ax.set_xticks([t[0] for t in TICKS])
        ax.set_xticklabels([t[1] for t in TICKS], fontsize=10.5,
                           color=COLORS["secondary"])
        ax.set_xticks([], minor=True)
        ax.tick_params(axis="x", length=0, pad=6)
        ax.set_yticks([])
        ax.grid(False)
        for sp in ax.spines.values():
            sp.set_visible(False)
        ax.set_xlabel("Weekly CVE Count vs That Year's Typical Week",
                      fontsize=10, fontweight="bold", color=COLORS["text"],
                      labelpad=10)

        fs = FOOT[ratio]
        fig_h_pt = RATIOS[ratio][1] / SAVE_DPI * 72
        pad = 7 / fig_h_pt  # inter-block gap, in figure units

        # Stack the footer blocks upward from the stamp and MEASURE each one
        # rather than predicting its height: matplotlib's `linespacing` is
        # relative to font metrics, not point size, so estimated line heights
        # run ~30% short and the blocks silently overlap.
        def _place(text, y, size, weight, color):
            t = fig.text(0.05, y, textwrap.fill(text, WRAP[ratio]), fontsize=size,
                         fontweight=weight, color=color, ha="left", va="bottom",
                         linespacing=1.55)
            fig.canvas.draw()
            bb = t.get_window_extent(renderer=fig.canvas.get_renderer())
            return bb.y1 / fig.bbox.height  # top of the block, figure fraction

        m_top = _place(method, 0.038, fs, "normal", COLORS["secondary"])
        v_top = _place(verdict, m_top + pad, fs + 0.5, "bold", COLORS["text"])

        # Room below the axes for the tick labels, labelpad and x-axis label.
        axis_space = 56 / fig_h_pt
        bot_m = v_top + pad + axis_space
        top_m = {"wide": 0.775, "square": 0.790, "portrait": 0.818}[ratio]
        fig.subplots_adjust(top=top_m, bottom=bot_m, left=0.105, right=0.955)
        draw_header(fig, title1, title2, ratio=ratio, eyebrow_suffix="VOLUME",
                    title_size={"wide": 25, "square": 21, "portrait": 21}[ratio])

        path = GRAPHS / f"camp_week_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        out.append(stamp_and_save(fig, path))
    return out


if __name__ == "__main__":
    for r in compute():
        print(f"{r['year']}  conf={r['conf']:5d}  median_near={r['median_near']:7.1f}  "
              f"pct={r['pct']:+7.1f}  rank={r['rank']:2d}/13")
    print(summary(compute()))
    for p in render():
        print(p)

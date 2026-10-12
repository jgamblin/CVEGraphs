#!/usr/bin/env python3
"""
Who publishes CVEs on weekends: a timesheet grid of the biggest CNAs.

One row per CNA (the 16 largest by 2026 volume), one column per weekday, each
cell the number of CVEs that CNA published on that day of the week this year.
Weekday cells are flat grey; weekend cells share one navy log scale across
all rows, so darker always means more. Zeros print as a muted "0". The right-hand
column is the CNA's weekend share. Rows sort by weekend share, so the weekend
crew sits on top and the Monday-to-Friday vendors sink to the bottom.

Accuracy notes:

* Days are UTC calendar days (CVE.org ``datePublished``). A US CNA publishing
  Friday evening lands on Saturday UTC: most of Wordfence's Saturday volume is
  01:00-08:00 UTC, i.e. Friday night US Eastern. ``stats()`` prints a
  "core weekend" count (Sat 12:00 to Sun 12:00 UTC, weekend in every time
  zone) so the copy never overstates who is literally working Saturday.
* MITRE is excluded: its records bypass the publishing API and many carry
  date-only timestamps (see memory: mitre-direct-publish-timestamps).
* The window ends on the last complete UTC day; a partial "today" is dropped.

Data: CVE List V5 (assigner short name + publication date), non-rejected.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap, to_rgb

from data import load_cvelist
from rolling_config import current_year, today_utc
from style_social import (COLORS, DEFAULT_RATIOS, draw_header, figsize_for,
                          stamp_and_save)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

TOP_N = 16
EXCLUDE = ("mitre",)
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

NAMES = {
    "GitHub_M": "GitHub", "Linux": "Linux Kernel", "VulnCheck": "VulnCheck",
    "VulDB": "VulDB", "Patchstack": "Patchstack", "Wordfence": "Wordfence",
    "Chrome": "Chrome", "oracle": "Oracle", "microsoft": "Microsoft",
    "WPScan": "WPScan", "ibm": "IBM", "redhat": "Red Hat", "apache": "Apache",
    "adobe": "Adobe", "apple": "Apple", "mozilla": "Mozilla", "dell": "Dell",
    "cisco": "Cisco", "icscert": "CISA ICS",
}

NAVY = LinearSegmentedColormap.from_list("navy", ["#ffffff", COLORS["primary"]])
WEEKDAY_FILL = "#eef0f3"
ZERO_INK = "#5f6b7a"  # muted, still 4.5:1 on white


def _ink(face):
    """Dark ink on light fills, white on dark, by relative luminance."""
    r, g, b = [x if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4
               for x in to_rgb(face)]
    return "white" if 0.2126 * r + 0.7152 * g + 0.0722 * b < 0.30 else COLORS["text"]


def _frame():
    """This year's non-rejected CVEs through the last complete UTC day."""
    cl = load_cvelist()
    pub = pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
    end = today_utc()
    start = pd.Timestamp(current_year(end), 1, 1, tz="UTC")
    cl = cl.assign(pub=pub)
    cl = cl[(cl["pub"] >= start) & (cl["pub"] < end)]
    cl = cl.drop_duplicates("cve_id")
    cl["dow"] = cl["pub"].dt.dayofweek
    return cl, start, end - pd.Timedelta(days=1)


def _grid(cl):
    """Rows: top CNAs by volume, sorted by weekend share. Columns: Mon..Sun."""
    cl = cl[~cl["assigner_short_name"].isin(EXCLUDE)]
    top = cl["assigner_short_name"].value_counts().head(TOP_N).index
    g = (cl[cl["assigner_short_name"].isin(top)]
         .groupby(["assigner_short_name", "dow"]).size()
         .unstack(fill_value=0).reindex(columns=range(7), fill_value=0))
    total = g.sum(axis=1)
    share = g[[5, 6]].sum(axis=1) / total
    order = pd.DataFrame({"share": share, "total": total}).sort_values(
        ["share", "total"], ascending=[False, False]).index
    return g.loc[order], share.loc[order], total.loc[order]


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl, start, last = _frame()
    g, share, total = _grid(cl)

    title = "Who Publishes CVEs on the Weekend"
    subtitle = (f"CVEs by day of week and share on weekends, {TOP_N} largest CNAs, "
                f"{start:%b %-d} to {last:%b %-d, %Y}")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        nrow = len(g)
        # One log scale shared by every weekend cell, so a darker cell is
        # always a bigger count, down a column or across a row.
        vmax = np.log1p(g[[5, 6]].values.max())
        fs = {"wide": 10.5, "square": 10, "portrait": 10.5}[ratio]

        for r in range(nrow):
            for c in range(7):
                v = int(g.iat[r, c])
                weekend = c >= 5
                if weekend and v:
                    face = NAVY(0.04 + 0.96 * np.log1p(v) / vmax)
                elif weekend:
                    face = "white"
                else:
                    face = WEEKDAY_FILL
                ax.add_patch(plt.Rectangle((c + 0.04, r + 0.06), 0.92, 0.88,
                                           facecolor=face, edgecolor=COLORS["grid"]
                                           if weekend and not v else "none",
                                           lw=0.8))
                ink = ZERO_INK if v == 0 else _ink(face)
                ax.text(c + 0.5, r + 0.5, f"{v:,}", ha="center", va="center",
                        fontsize=fs, color=ink,
                        fontweight="bold" if weekend and v else "normal")

            # Weekend share column.
            s = share.iloc[r]
            ax.text(7.78, r + 0.5, f"{s:.0%}" if s >= 0.005 or s == 0 else "<1%",
                    ha="right", va="center",
                    fontsize={"wide": 13, "square": 12, "portrait": 12.5}[ratio],
                    fontweight="bold",
                    color=COLORS["primary"] if s >= 0.10 else COLORS["secondary"])

        lfs = {"wide": 11.5, "square": 10.5, "portrait": 11}[ratio]
        ax.set_yticks(np.arange(nrow) + 0.5)
        ax.set_yticklabels([NAMES.get(k, k) for k in g.index], fontsize=lfs)
        ax.tick_params(axis="y", length=0, pad=6)
        ax.xaxis.set_ticks_position("top")
        ax.set_xticks(np.arange(7) + 0.5)
        ax.set_xticklabels(DAYS, fontsize=lfs)
        for lbl in ax.get_xticklabels()[5:]:
            lbl.set_color(COLORS["primary"])
            lbl.set_fontweight("bold")
        ax.text(7.78, -0.12, "Weekend\nShare", ha="right", va="bottom",
                fontsize=lfs, fontweight="bold", color=COLORS["primary"],
                linespacing=1.1)
        ax.tick_params(axis="x", length=0, pad=4)
        ax.set_xlim(0, 7.85)
        ax.set_ylim(nrow, 0)
        for sp in ax.spines.values():
            sp.set_visible(False)
        ax.grid(False)

        top_m = {"wide": 0.73, "square": 0.75, "portrait": 0.79}[ratio]
        bottom_m = {"wide": 0.09, "square": 0.08, "portrait": 0.07}[ratio]
        left_m = {"wide": 0.12, "square": 0.16, "portrait": 0.16}[ratio]
        fig.subplots_adjust(top=top_m, bottom=bottom_m, left=left_m, right=0.965)
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="Publishing")

        foot = {"wide": 9.5, "square": 8.0, "portrait": 8.0}[ratio]
        fig.text(0.05, 0.035,
                 "Days in UTC; MITRE excluded (date-only timestamps). "
                 "Source: CVE List V5.",
                 fontsize=foot, color=COLORS["secondary"], ha="left",
                 va="bottom")

        path = GRAPHS / f"cna_weekend_{ratio}_{last:%Y-%m-%d}.png"
        out.append(stamp_and_save(fig, path))
    return out


def stats():
    """Every figure the caption and copy quote, so none is retyped off the image."""
    cl, start, last = _frame()
    g, share, total = _grid(cl)
    we = cl[cl["dow"] >= 5]
    by_cna = cl.groupby("assigner_short_name").agg(
        n=("cve_id", "size"), we=("dow", lambda s: int((s >= 5).sum())))
    top5 = by_cna["we"].sort_values(ascending=False).head(5)
    hrs = cl["pub"].dt.dayofweek * 24 + cl["pub"].dt.hour
    core = cl[(hrs >= 5 * 24 + 12) & (hrs < 6 * 24 + 12)]
    core_by = core["assigner_short_name"].value_counts().head(6)
    return {
        "window": f"{start:%Y-%m-%d} to {last:%Y-%m-%d}",
        "cves": len(cl),
        "weekend_cves": len(we),
        "weekend_share": round(len(we) / len(cl), 3),
        "cnas_publishing": len(by_cna),
        "cnas_with_any_weekend": int((by_cna["we"] > 0).sum()),
        "top5_weekend": top5.to_dict(),
        "top5_weekend_share_of_weekend": round(top5.sum() / len(we), 3),
        "core_weekend_cves(Sat12-Sun12 UTC)": len(core),
        "core_weekend_top": core_by.to_dict(),
        "grid_weekend_share": share.round(3).to_dict(),
        "grid_totals": total.to_dict(),
    }


if __name__ == "__main__":
    for key, val in stats().items():
        print(f"{key:>36}: {val}")
    for p in render():
        print(p)

#!/usr/bin/env python3
"""
Who attaches a CVE's weakness class, tracked over time by CNA.

The aggregate share of CVEs carrying a CNA-supplied CWE has climbed steeply since
2019. This chart shows that the climb is not a slow industry-wide drift: individual
CNAs sit at 0% or near 100% and move between them abruptly, when someone turns the
field on. Every CNA above the volume floor is drawn as a faint grey line so the
bimodal shape is visible, with the all-CVE baseline and three exemplar CNAs named:

* Microsoft, the cleanest switch-flip (0% every year through 2022, 82% in 2023,
  100% in 2024-25 and 99.7% in 2026).
* Oracle, which has never attached one, across every year and every volume.

There is deliberately NO "turned it off" exemplar. An earlier build used WPScan for
that role, citing 99% in 2021 falling to 0% from 2023. That was false: it was an
artifact of the CWE parser reading only the optional `cweId` key, which WPScan does
not set (it declares the class in `description` text). WPScan actually runs 100%,
99%, 100%, 100%, 100%, 100% across 2021-2026. Checked properly, NO CNA with volume
moved down by 25 points or more in the last two years; all eight movers went up. Do
not reintroduce a regression exemplar unless one genuinely appears.

A previous version of this chart compared the KEV cohort against all CVEs. That was
dropped: KEV is ~1,665 CVEs against 376,000+, its per-year cohorts are 118-213, and
the KEV-vs-baseline gap turned out to be a CNA-composition artifact rather than a
finding (KEV over-indexes on MITRE/Microsoft/Apple/Chrome, which published 0% CWE
coverage across ALL their output in 2021). Comparing CNAs directly avoids the
confound entirely because the CNA is the unit of analysis rather than a lurking
variable.

Companion to `cwe_cna_rank` (the same metric ranked, current year only).

Data: CVE List V5, published and non-rejected, by publication date.
"""

from pathlib import Path

import matplotlib.patheffects as pe
import matplotlib.pyplot as plt
import pandas as pd

from data import load_cvelist
from rolling_config import current_year, data_asof
from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

FIRST_YEAR = 2019
# Volume floor for a CNA-year to be drawn at all. Below this a single batch swings
# the rate, which would draw noise as though it were behaviour.
MIN_CVES = 250

# The named exemplars, in draw order. Chosen to span the three behaviours the grey
# lines show en masse: turned it on, turned it off, never turned it on.
# Two exemplars only: turned it on, and never turned it on. Chrome would be a decent
# third (28% -> 67%) but falls under MIN_CVES in 2025, so its line would draw with a
# hole in it. The one-directional finding belongs in the copy, not in a gapped series.
HIGHLIGHTS = [
    ("microsoft", "Microsoft", COLORS["primary"], "solid"),
    ("oracle", "Oracle", COLORS["alert"], "solid"),
]


def _load():
    df = load_cvelist()
    if "is_published" in df.columns:
        df = df[df["is_published"]]
    return df


def _tables(df, asof):
    """Return (per-CNA rate table, per-CNA count table, baseline series, years).

    Rates are masked to NaN below the volume floor, which both drops noise and
    breaks each grey line over the years a CNA was not really publishing.
    """
    last = current_year(asof)
    years = list(range(FIRST_YEAR, last + 1))

    d = df.copy()
    d["year"] = pd.to_datetime(d["date_published"], utc=True,
                               errors="coerce").dt.year
    d = d[d["year"].between(FIRST_YEAR, last)]
    d["has"] = d["cwe_count"].fillna(0) > 0

    rate = d.pivot_table(index="assigner_short_name", columns="year",
                         values="has", aggfunc="mean") * 100
    cnt = d.pivot_table(index="assigner_short_name", columns="year",
                        values="has", aggfunc="size")
    rate = rate.reindex(columns=years)
    cnt = cnt.reindex(columns=years)
    rate = rate.where(cnt >= MIN_CVES)

    baseline = [100 * d.loc[d["year"] == y, "has"].mean() for y in years]
    return rate, cnt, baseline, years


def render(nvd=None, ratios=DEFAULT_RATIOS):
    df = _load()
    asof = data_asof(df)
    rate, cnt, baseline, years = _tables(df, asof)

    drawn = rate.dropna(how="all")
    cur = years[-1]
    cur_counts = cnt[cur].fillna(0)

    title = "Who Attaches a CVE's Weakness Class"
    sub_parts = [
        "Share of each CNA's CVEs carrying a CNA-supplied CWE, by publication year.",
        f"Grey lines are the {len(drawn)} CNAs with {MIN_CVES}+ CVEs in a year. "
        f"{cur} is year to date.",
    ]

    out = []
    for ratio in ratios:
        subtitle = "\n".join(sub_parts)
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        # Every qualifying CNA as faint texture: this is what shows that the space
        # between 0 and 100 is mostly empty.
        for name, row in drawn.iterrows():
            ax.plot(years, row.values, color=COLORS["neutral"], lw=1.0,
                    alpha=0.45, zorder=2, solid_capstyle="round")

        ax.plot(years, baseline, color=COLORS["text"], lw=3.2, zorder=5,
                label="All published CVEs")

        for key, label, color, style in HIGHLIGHTS:
            if key not in drawn.index:
                continue
            ax.plot(years, drawn.loc[key].values, color=color, lw=2.6,
                    linestyle=style, zorder=4, marker="o", markersize=5,
                    markerfacecolor="white", markeredgewidth=1.8, label=label)

        # Baseline endpoints, which the copy quotes.
        for x, y, ha, off in ((years[0], baseline[0], "left", (10, 9)),
                              (years[-1], baseline[-1], "right", (4, 11))):
            ax.annotate(f"{y:.0f}%", (x, y), textcoords="offset points",
                        xytext=off, fontsize=13, fontweight="bold",
                        color=COLORS["text"], ha=ha, zorder=6,
                        path_effects=[pe.withStroke(linewidth=3,
                                                    foreground="white")])

        ax.set_ylim(0, 108)
        ax.set_yticks(range(0, 101, 20))
        ax.set_xlim(years[0] - 0.35, years[-1] + 0.55)
        ax.set_xticks(years)
        ax.set_xticklabels([f"{y} YTD" if y == years[-1] else str(y)
                            for y in years])
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
        ax.set_axisbelow(True)
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)

        # Legend sits ABOVE the axes, not inside them: in-axes placement covered
        # the dense 100% cluster of grey lines, which is the evidence the chart
        # exists to show. Per-CNA volumes move to the footnote to keep it to one row.
        ncol = 3 if ratio == "wide" else 2
        leg = ax.legend(loc="lower left", bbox_to_anchor=(0, 1.01, 1, 0.09),
                        mode="expand", ncol=ncol, frameon=False, fontsize=9.5,
                        handlelength=3.2, borderpad=0.2, columnspacing=1.4,
                        labelspacing=0.4)
        leg.set_zorder(7)
        for t in leg.get_texts():
            t.set_color(COLORS["secondary"])

        # Tops are low: the legend band sits above the axes and must clear the
        # two- or three-line subtitle.
        top = {"wide": 0.72, "square": 0.72, "portrait": 0.75}[ratio]
        bottom = {"wide": 0.27, "square": 0.24, "portrait": 0.20}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom, left=0.11, right=0.95)
        t1 = {"wide": 26, "square": 19, "portrait": 19}[ratio]
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="Data Quality",
                    title_size=t1)

        foot_size = {"wide": 9.5, "square": 8.5, "portrait": 8.5}[ratio]
        vols = ", ".join(f"{label} {int(cur_counts.get(key, 0)):,}"
                         for key, label, _, _ in HIGHLIGHTS
                         if key in drawn.index)
        s = [
            f"A CNA-year is plotted only at {MIN_CVES}+ CVEs, so a line starts "
            "when that CNA reaches real volume.",
            f"{cur} CVE counts: {vols}. Measured on the current record, which a "
            "CNA can update after publication.",
            "Source: CVE List V5, published and non-rejected. NVD and CISA "
            "classify many of these separately.",
        ]
        foot = "\n".join(s)
        fig.text(0.05, 0.045, foot, fontsize=foot_size,
                 color=COLORS["secondary"], ha="left", va="bottom",
                 linespacing=1.5)

        path = GRAPHS / f"cwe_provenance_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

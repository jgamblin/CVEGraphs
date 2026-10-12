#!/usr/bin/env python3
"""
Which CNAs attach a weakness class, and which never do. Ranked, current year.

The aggregate CWE-coverage number for a year is close to meaningless as a
description of any actual CNA, because the distribution is not a gradient, it is a
switch. Among the CNAs publishing real volume this year, most sit at or near 100%
and a hard core sits at exactly 0.0%, with almost nobody in between. The dashed
reference line is the all-CVE average, and it lands in the empty gap where hardly
any CNA lives.

Companion to `cwe_provenance` (the same metric over time). Zero-coverage CNAs are
drawn in the alert colour because "never attaches one" is a distinct category, not
a low score on a continuum.

Data: CVE List V5, published and non-rejected, current year to date.
"""

from pathlib import Path

import matplotlib.patheffects as pe
import matplotlib.pyplot as plt
import pandas as pd

from data import load_cvelist
from rolling_config import current_year, data_asof, ytd_mask
from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

# Volume floor for inclusion. High enough that a CNA with a handful of CVEs cannot
# take the top or bottom slot on noise, low enough to still cover most of the year.
MIN_CVES = 250

CNA_NAMES = {
    "GitHub_M": "GitHub", "VulnCheck": "VulnCheck", "VulDB": "VulDB",
    "Patchstack": "Patchstack", "Wordfence": "Wordfence", "microsoft": "Microsoft",
    "mitre": "MITRE", "Chrome": "Chrome", "oracle": "Oracle", "Linux": "Linux",
    "apple": "Apple", "mozilla": "Mozilla", "WPScan": "WPScan", "adobe": "Adobe",
    "GitLab": "GitLab", "redhat": "Red Hat", "ibm": "IBM", "apache": "Apache",
    "icscert": "ICS-CERT", "zdi": "ZDI", "@huntr_ai": "huntr",
}


def _load():
    df = load_cvelist()
    if "is_published" in df.columns:
        df = df[df["is_published"]]
    return df


def _rows(df, asof):
    """Per-CNA CWE coverage for the current year to date, above the volume floor."""
    cur = current_year(asof)
    d = df[ytd_mask(df, cur, asof)].copy()
    d["has"] = d["cwe_count"].fillna(0) > 0

    g = d.groupby("assigner_short_name").agg(n=("cve_id", "size"),
                                             rate=("has", "mean"))
    g["rate"] = 100 * g["rate"]
    # Sort by rate then volume: nine CNAs tie at 100.0%, and a bare sort on rate
    # alone is not stable across refreshes (quicksort put Adobe first, mergesort
    # GitHub). The tie-break also puts the largest CNA at the head of each block.
    g = g[g["n"] >= MIN_CVES].sort_values(["rate", "n"], ascending=[False, False])

    rows = [{"cna": CNA_NAMES.get(i, i), "rate": r["rate"], "n": int(r["n"])}
            for i, r in g.iterrows()]
    overall = 100 * d["has"].mean()
    return rows, overall, len(d), int(g["n"].sum()), cur


def render(nvd=None, ratios=DEFAULT_RATIOS):
    df = _load()
    asof = data_asof(df)
    rows, overall, total, covered, cur = _rows(df, asof)

    zeros = [r for r in rows if r["rate"] < 0.05]
    # House rule: the heading states what the chart shows.
    title = f"CWE Coverage by CNA, {cur} to Date"
    sub_parts = [
        f"Share of each CNA's {cur} CVEs that carry a CNA-supplied weakness class.",
        f"{len(rows)} CNAs published {MIN_CVES}+ CVEs this year; they are "
        f"{100 * covered / total:.0f}% of all volume.",
    ]

    out = []
    for ratio in ratios:
        subtitle = (f"{sub_parts[0]}\n{sub_parts[1]}" if ratio == "wide"
                    else f"{sub_parts[0]}\n{sub_parts[1]}")
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        n = len(rows)
        name_size = {"wide": 10, "square": 8.5, "portrait": 9}[ratio]
        val_size = {"wide": 9.5, "square": 8, "portrait": 8.5}[ratio]

        for i, r in enumerate(rows):
            y = n - 1 - i  # best at the top
            zero = r["rate"] < 0.05
            color = COLORS["alert"] if zero else COLORS["primary"]
            ax.barh(y, r["rate"], height=0.66, color=color, edgecolor="white",
                    linewidth=0.9, zorder=3)
            if zero:
                # A zero-length bar draws nothing, so five blank rows read as
                # missing data rather than as a measured zero. Cap the baseline.
                ax.plot([0, 0], [y - 0.33, y + 0.33], color=COLORS["alert"],
                        lw=3.2, solid_capstyle="butt", zorder=4)
            # A zero bar has no length to label, so the number is placed just off
            # the axis instead of at the (nonexistent) bar end.
            ax.text(r["rate"] + 1.4 if not zero else 1.4, y,
                    f"{r['rate']:.1f}%", fontsize=val_size, fontweight="bold",
                    color=color, ha="left", va="center", zorder=4)
            ax.text(-0.012, y, r["cna"], transform=ax.get_yaxis_transform(),
                    fontsize=name_size, fontweight="bold", color=COLORS["text"],
                    ha="right", va="center")
            ax.text(1.005, y, f"{r['n']:,}", transform=ax.get_yaxis_transform(),
                    fontsize=val_size, color=COLORS["secondary"], ha="left",
                    va="center")

        # The average, drawn where it actually falls: in the gap. Deliberately ON
        # TOP of the bars (unlike pace.py, which puts the bar over its reference
        # line): the whole point is where this line lands relative to every CNA, so
        # it has to be followable across the full height rather than showing up as
        # specks between bars.
        ax.axvline(overall, color=COLORS["secondary"], linestyle=(0, (5, 4)),
                   linewidth=1.6, zorder=5, alpha=0.95,
                   path_effects=[pe.withStroke(linewidth=4.0, foreground="white")])
        # Label goes INSIDE the axes, on the lowest non-zero row, where the space
        # right of the short bars is empty. Above the axes it overprinted the
        # subtitle on the square ratio and smeared two different percentages
        # together.
        ax.text(overall + 1.8, max(len(zeros), 0.5),
                f"All {cur} CVEs: {overall:.0f}%",
                fontsize=val_size + 0.5, fontweight="bold",
                color=COLORS["secondary"], ha="left", va="center", zorder=6,
                bbox=dict(facecolor="white", edgecolor="none", pad=1.6))

        ax.set_xlim(0, 118)
        ax.set_ylim(-0.7, n - 0.05)
        ax.set_yticks([])
        ax.set_xticks(range(0, 101, 20))
        ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="y", length=0)
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.grid(axis="y", visible=False)
        ax.set_axisbelow(True)

        top = {"wide": 0.76, "square": 0.80, "portrait": 0.82}[ratio]
        bottom = {"wide": 0.17, "square": 0.13, "portrait": 0.115}[ratio]
        left = {"wide": 0.15, "square": 0.17, "portrait": 0.16}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom, left=left, right=0.88)
        t1 = {"wide": 26, "square": 19, "portrait": 20}[ratio]
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="Data Quality",
                    title_size=t1)

        foot_size = {"wide": 9.5, "square": 8, "portrait": 8.5}[ratio]
        zero_note = (f"{len(zeros)} CNAs sit at exactly 0.0% (red). "
                     if zeros else "")
        fig.text(
            0.05, 0.035,
            f"{zero_note}Right column is each CNA's {cur} CVE count.\n"
            "Source: CVE List V5, published and non-rejected, by publication date. "
            "NVD and CISA classify many of these separately.",
            fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom",
            linespacing=1.5,
        )

        path = GRAPHS / f"cwe_cna_rank_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

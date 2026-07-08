#!/usr/bin/env python3
"""
Dumbbell: who scores a CVE moves CVSS more than which version.

For each weakness class (CWE), we take the SAME organization scoring the SAME bug
with both CVSS v3 and v4 on its own CVE-List record, then plot the mean v4 - v3
shift for the two highest-volume dual-scorers (VulDB, VulnCheck). Same bug class,
scorer held fixed, yet the two disagree, sometimes on direction (SQLi, XSS flip
sign). The takeaway: the v3/v4 gap is a property of the scorer, not the version.

Uses CVE-List V5 (the CNA's own vectors) deliberately: the NVD-feed cvss_v4 is
pulled low by the extractor, so a clean v4 comparison must read v4 from CVE-List.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D

from data import load_cvelist, load_nvd
from rolling_config import data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

# The two highest-volume CNAs that score their own CVEs with both v3 and v4.
SCORERS = [("VulDB", COLORS["primary"]), ("VulnCheck", COLORS["alert"])]
MIN_N = {"VulDB": 100, "VulnCheck": 60}  # per-CWE floor so a point is stable

CWE_NAMES = {
    "CWE-79": "XSS", "CWE-89": "SQLi", "CWE-352": "CSRF", "CWE-120": "Buffer Copy",
    "CWE-434": "File Upload", "CWE-121": "Stack Overflow", "CWE-918": "SSRF",
    "CWE-22": "Path Traversal", "CWE-78": "OS Cmd Inj",
}


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist()
    # Stamp with the NVD as-of date so this shares one date with the rest of the
    # posting set (the data itself is CVE List; the date just anchors the shelf).
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)

    b = cl[cl["cvss_v3"].notna() & cl["cvss_v4"].notna() & cl["cwe"].notna()].copy()
    b["d"] = b["cvss_v4"] - b["cvss_v3"]
    names = [s for s, _ in SCORERS]
    sub = b[b["assigner_short_name"].isin(names)]
    mean = sub.pivot_table(index="cwe", columns="assigner_short_name", values="d", aggfunc="mean")
    n = sub.pivot_table(index="cwe", columns="assigner_short_name", values="d", aggfunc="size")
    keep = np.ones(len(mean), dtype=bool)
    for s in names:
        keep &= (n[s] >= MIN_N[s]).reindex(mean.index).fillna(False).values
    t = mean[keep].dropna().copy()
    t["spread"] = (t[names[0]] - t[names[1]]).abs()
    t = t.sort_values("spread")  # biggest disagreement ends up on top (last row)

    rows = list(t.index)
    ypos = np.arange(len(rows))

    title1 = "Who scores a CVE moves it more than which CVSS version"
    title2 = ("Same weakness, same CNA scoring both v3 and v4 on its own bugs. "
              "Two big scorers disagree, often on direction.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        # Connecting line per CWE, then a dot for each scorer.
        for y, cwe in zip(ypos, rows):
            x0, x1 = t.loc[cwe, names[0]], t.loc[cwe, names[1]]
            ax.plot([x0, x1], [y, y], color=COLORS["neutral"], lw=2.0, zorder=1,
                    solid_capstyle="round")
        for s, c in SCORERS:
            ax.scatter(t[s].values, ypos, s=190, color=c, zorder=3,
                       edgecolor="white", linewidth=1.5)

        # Zero reference: v4 == v3.
        ax.axvline(0, color=COLORS["text"], lw=1.2, ls=(0, (4, 3)), zorder=2, alpha=0.7)

        ax.set_yticks(ypos)
        ax.set_yticklabels([f"{CWE_NAMES.get(c, c)}" for c in rows],
                           fontsize=12.5, fontweight="bold")
        ax.set_xlabel("Mean CVSS v4 base score minus v3, same bug")

        xmax = float(np.ceil(np.abs(t[names].values).max() * 2) / 2) + 0.2
        ax.set_xlim(-xmax, xmax)
        ax.set_ylim(-0.7, len(rows) - 0.3)

        # Directional cue under the axis.
        ax.text(-xmax * 0.98, len(rows) - 0.35, "← v4 scores lower",
                fontsize=10.5, color=COLORS["secondary"], fontweight="bold",
                ha="left", va="center")
        ax.text(xmax * 0.98, len(rows) - 0.35, "v4 scores higher →",
                fontsize=10.5, color=COLORS["secondary"], fontweight="bold",
                ha="right", va="center")

        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="y", length=0)
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        ax.legend(handles=[Line2D([0], [0], marker="o", color="none", label=nm,
                                  markerfacecolor=cc, markeredgecolor="white",
                                  markersize=12) for nm, cc in SCORERS],
                  loc="upper center", bbox_to_anchor=(0.5, -0.12), ncol=2,
                  frameon=False, fontsize=11, handletextpad=0.4, columnspacing=2.2)

        ax.text(0.0, -0.205,
                "CVSS v4 - v3 on the same CVE, same CNA scoring both. VulDB and "
                "VulnCheck, the two highest-volume dual-scorers. Source: CVE List V5.",
                transform=ax.transAxes, fontsize=9.5, color=COLORS["neutral"], va="top")

        top = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        fig.subplots_adjust(top=top, bottom=0.20, left=0.20, right=0.95)
        fig.text(0.05, 0.965, title1, fontsize=19, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.918, title2, fontsize=11, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"scorer_divergence_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

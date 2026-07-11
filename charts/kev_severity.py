#!/usr/bin/env python3
"""
How severe are the bugs that actually get exploited? CVSS spread of CISA KEV.

For each weakness class on CISA's Known Exploited Vulnerabilities list, a bubble at
every distinct CVSS v3 score its exploited CVEs carry, sized by how many share that
score. A range/median chart is misleading here (these distributions pile at the
ceiling, so the median sits at the edge); the bubble strip shows the full spread
honestly. The x-axis is zoomed to the populated range (4+), with the handful of
sub-4 outliers noted rather than shown. Exploited bugs cluster high, and the
auth/injection/deserialization classes pile hardest at 9.8.

Data: processed/kev_catalog.json (CISA KEV cwes) joined to CVSS v3 (NVD, CVE List).
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.lines import Line2D

from data import load_cvelist, load_nvd
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
PROCESSED = Path(__file__).resolve().parent.parent / "processed"

MIN_KEV = 30
TOP_N = 12
XMIN = 4.0  # zoom: populated range; sub-4 outliers are noted, not shown

CWE_NAMES = {
    "CWE-94": "Code injection", "CWE-89": "SQL injection", "CWE-78": "OS command inj.",
    "CWE-502": "Deserialization", "CWE-287": "Improper auth", "CWE-306": "Missing auth",
    "CWE-843": "Type confusion", "CWE-119": "Memory buffer error", "CWE-416": "Use-after-free",
    "CWE-284": "Improper access ctrl", "CWE-20": "Input validation", "CWE-22": "Path traversal",
    "CWE-787": "Out-of-bounds write", "CWE-79": "XSS", "CWE-434": "File upload",
    "CWE-77": "Command injection", "CWE-122": "Heap overflow", "CWE-125": "Out-of-bounds read",
}


def _color(score):
    return COLORS["primary"] if score >= 9 else COLORS["accent"] if score >= 7 else COLORS["neutral"]


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist()
    if nvd is None:
        nvd = load_nvd()
    kev = json.load(open(PROCESSED / "kev_catalog.json"))
    asof = pd.to_datetime(kev.get("dateReleased"), utc=True)

    rows = [{"cve_id": v["cveID"], "cwe": w}
            for v in kev.get("vulnerabilities", []) for w in (v.get("cwes") or [])]
    k = pd.DataFrame(rows)
    nvd_s = nvd.dropna(subset=["cvss_v3"]).drop_duplicates("cve_id").set_index("cve_id")["cvss_v3"]
    cl_s = cl.dropna(subset=["cvss_v3"]).drop_duplicates("cve_id").set_index("cve_id")["cvss_v3"]
    k["cvss"] = k["cve_id"].map(nvd_s).fillna(k["cve_id"].map(cl_s))
    k = k.dropna(subset=["cvss"])

    counts = k["cwe"].value_counts()
    keep = list(counts[counts >= MIN_KEV].head(TOP_N).index)
    stats = {c: k[k["cwe"] == c]["cvss"] for c in keep}
    # Sort by MEDIAN (the honest center for ceiling-piled data), mean as tiebreak.
    order = sorted(keep, key=lambda c: (stats[c].median(), stats[c].mean()))
    ns = {c: len(stats[c]) for c in keep}
    kept = k[k["cwe"].isin(keep)]["cvss"]
    below = int((kept < XMIN).sum())
    gmin = float(kept.min())

    title1 = "How severe are the bugs that actually get exploited?"
    title2 = ("CVSS v3 score of each exploited (KEV) CVE in the 12 most-exploited "
              "weakness classes. Bubble size = number of CVEs.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        for y, c in enumerate(order):
            vc = stats[c][stats[c] >= XMIN].value_counts()
            for score, cnt in vc.items():
                ax.scatter(score, y, s=30 + cnt * 15, color=_color(score), alpha=0.85,
                           edgecolors="white", linewidths=1.0, zorder=3)
            # Class median: a red diamond at its position + the value in the right margin.
            med = float(stats[c].median())
            ax.scatter(med, y - 0.34, marker="D", s=32, color=COLORS["alert"],
                       edgecolors="white", linewidths=0.7, zorder=6)
            ax.text(1.04, y, f"{med:.1f}", transform=ax.get_yaxis_transform(),
                    fontsize=8.5, fontweight="bold", color=COLORS["text"], ha="center", va="center")
            ax.text(-0.03, y + 0.24, CWE_NAMES.get(c, c), transform=ax.get_yaxis_transform(),
                    fontsize=11, fontweight="bold", color=COLORS["text"], ha="right", va="center")
            ax.text(-0.03, y - 0.28, f"{c} · {ns[c]} exploited", transform=ax.get_yaxis_transform(),
                    fontsize=7.5, color=COLORS["neutral"], ha="right", va="center")

        # Header for the right-margin median column.
        ax.text(1.04, 1.008, "Median", transform=ax.transAxes, fontsize=8.5,
                fontweight="bold", color=COLORS["secondary"], ha="center", va="bottom")

        ax.set_yticks([])
        ax.set_xlim(XMIN - 0.3, 10.3)
        ax.set_ylim(-0.7, len(order) - 0.3)
        ax.set_xlabel("CVSS v3 base score")
        ax.set_xticks(np.arange(4, 10.5, 1))
        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="y", length=0)
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        ax.legend(handles=[
            Line2D([0], [0], marker="o", color="none", markerfacecolor=COLORS["primary"],
                   markeredgecolor="white", markersize=11, label="Critical (9.0-10.0)"),
            Line2D([0], [0], marker="o", color="none", markerfacecolor=COLORS["accent"],
                   markeredgecolor="white", markersize=11, label="High (7.0-8.9)"),
            Line2D([0], [0], marker="o", color="none", markerfacecolor=COLORS["neutral"],
                   markeredgecolor="white", markersize=11, label="Medium (4.0-6.9)")],
            loc="upper center", bbox_to_anchor=(0.5, -0.15), ncol=3, frameon=False,
            fontsize=9.5, handletextpad=0.4, columnspacing=2.0)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        ax.text(0.0, -0.25,
                f"CISA KEV CVEs, {MIN_KEV}+ exploited per class. CVSS v3, blended NVD and CVE List; "
                "red diamond marks each class median.\n"
                f"Not shown: {below} CVEs below {XMIN:.1f} (min {gmin:.1f}). "
                "Source: CISA KEV + NVD/CVE List.",
                transform=ax.transAxes, fontsize=foot_size, color=COLORS["neutral"], va="top")

        top_m = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        t1 = {"wide": 19, "square": 17, "portrait": 17}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.27, left=0.24, right=0.93)
        fig.text(0.05, 0.965, title1, fontsize=t1, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.918, title2, fontsize=11, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"kev_severity_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

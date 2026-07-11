#!/usr/bin/env python3
"""
Which weakness classes actually get exploited? KEV rate by CWE.

Companion to `cwe_spread` (which shows CVSS severity by weakness class). For the
same 10 most common CWEs, this shows the share of each class's CVEs that have
landed on CISA's Known Exploited Vulnerabilities (KEV) list, sorted by that
exploited rate, with each class's median CVSS alongside. The point: severity and
real-world exploitation are related but not the same. XSS is the most common
class yet near the bottom for exploitation; SQL injection scores high but is
rarely exploited; command injection leads.

Data: CVE List V5 (CWE + CVSS v3) joined to processed/kev_catalog.json (CISA KEV).
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from data import load_cvelist, load_nvd
from rolling_config import data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
PROCESSED = Path(__file__).resolve().parent.parent / "processed"
TOP_N = 10

CWE_NAMES = {
    "CWE-79": "XSS", "CWE-89": "SQL injection", "CWE-862": "Missing authz",
    "CWE-352": "CSRF", "CWE-22": "Path traversal", "CWE-20": "Input validation",
    "CWE-125": "Out-of-bounds read", "CWE-78": "OS command inj.",
    "CWE-200": "Info exposure", "CWE-121": "Stack overflow",
}


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist()
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)

    kev = json.load(open(PROCESSED / "kev_catalog.json"))
    kevids = {v.get("cveID") for v in kev.get("vulnerabilities", [])}

    d = cl[cl["cwe"].notna()].copy()
    d["in_kev"] = d["cve_id"].isin(kevids)
    # Same 10 classes as cwe_spread: top by CVSS-v3-scored volume.
    top = list(cl[cl["cvss_v3"].notna() & cl["cwe"].notna()]["cwe"].value_counts().head(TOP_N).index)

    rows = []
    for c in top:
        s = d[d["cwe"] == c]
        med = s[s["cvss_v3"].notna()]["cvss_v3"].median()
        rows.append({"cwe": c, "rate": 100 * s["in_kev"].mean(),
                     "med": float(med), "n": len(s)})
    rows.sort(key=lambda r: r["rate"], reverse=True)  # most-exploited on top

    rates = [r["rate"] for r in rows]
    labels = [CWE_NAMES.get(r["cwe"], r["cwe"]) for r in rows]

    title1 = "Do the highest-scoring bugs get exploited most?"
    title2 = ("KEV rate for the 10 most common weakness classes. The CVSS medians "
              "(right) fall out of order, so severity does not predict it.")

    xmax = max(rates) * 1.25

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        for i, r in enumerate(rows):
            y = len(rows) - 1 - i  # rows[0] (most exploited) at the top
            ax.barh(y, r["rate"], height=0.62, color=COLORS["primary"],
                    edgecolor="white", linewidth=1.0, zorder=2)
            ax.text(r["rate"] + xmax * 0.015, y, f"{r['rate']:.2f}%", fontsize=9.5,
                    fontweight="bold", color=COLORS["text"], ha="left", va="center")
            # name + CWE id (two lines), like cwe_spread
            ax.text(-0.015, y + 0.12, labels[i], transform=ax.get_yaxis_transform(),
                    fontsize=11, fontweight="bold", color=COLORS["text"], ha="right", va="center")
            ax.text(-0.015, y - 0.17, r["cwe"], transform=ax.get_yaxis_transform(),
                    fontsize=7.5, color=COLORS["neutral"], ha="right", va="center")
            # median CVSS in a right-hand column (out of order = the point)
            ax.text(1.03, y, f"CVSS {r['med']:.1f}", transform=ax.get_yaxis_transform(),
                    fontsize=8.5, color=COLORS["secondary"], ha="left", va="center")

        ax.set_yticks([])
        ax.set_xlim(0, xmax)
        ax.set_ylim(-0.7, len(rows) - 0.3)
        ax.set_xlabel("Share of the class's CVEs on CISA's KEV list")
        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="y", length=0)
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)
        ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.1f}%"))

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        ax.text(0.0, -0.205,
                f"Top {TOP_N} CWEs by volume (~10% of KEV; 64% of KEV CVEs have no CWE). "
                "KEV = CISA Known Exploited Vulnerabilities. Source: CVE List V5 + CISA KEV.",
                transform=ax.transAxes, fontsize=foot_size, color=COLORS["neutral"], va="top")

        top_m = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        t1 = {"wide": 20, "square": 18, "portrait": 18}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.18, left=0.22, right=0.86)
        fig.text(0.05, 0.965, title1, fontsize=t1, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.915, title2, fontsize=10.5, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"cwe_kev_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

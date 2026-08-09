#!/usr/bin/env python3
"""
The largest single-second CVE publishing bursts.

On 2026-07-13 at 08:41:24 UTC, Patchstack published 66 CVEs in one second, with 22
in the second before and 61 in the second after: 149 CVEs across 136 distinct
products in three seconds. That is the largest verifiable single second in the CVE
record; the previous high was google_android at 31 (2019-09-27).

Two exclusions, both about comparability rather than tidiness:

  1. MITRE is dropped entirely. MITRE publishes directly to the CVE List instead
     of submitting through the API, so its timestamps reflect a different
     mechanism and are not comparable to an API submission burst. Left in, its
     date-only records also pile at midnight and fake a "480 in one second".
  2. Only records whose timestamp carries a non-zero seconds field are eligible
     (~76% of the post-MITRE remainder, ~59% of the full catalog). Filtering only
     on-the-hour is NOT enough: Oracle and Apple have minute-truncated rows that
     fake a 234-in-one-second. Date-only and minute-truncated records both pile
     at :00.

So this is the largest VERIFIABLE API-submitted single second, not a claim about
every record ever written.

This measures publication mechanics (a bulk API submission), not discovery: the
underlying research happened over weeks.

Data: CVE List V5 (assigner short name + publication timestamp).
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from data import load_cvelist, load_nvd
from rolling_config import data_asof
from style_social import (COLORS, DEFAULT_RATIOS, draw_header, figsize_for,
                          stamp_and_save)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
TOP_N = 8   # 8 rows so the two-line row labels get enough vertical space

CNA_NAMES = {
    "Patchstack": "Patchstack", "google_android": "Google Android",
    "apple": "Apple", "mitre": "MITRE", "oracle": "Oracle",
    "hackerone": "HackerOne", "Chrome": "Chrome", "VulDB": "VulDB",
    "jenkins": "Jenkins", "talos": "Cisco Talos", "microsoft": "Microsoft",
    "redhat": "Red Hat", "google": "Google", "adobe": "Adobe", "ibm": "IBM",
}


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist().drop_duplicates("cve_id")
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)

    pub = pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
    cl = cl.assign(pub=pub).dropna(subset=["pub"])
    # MITRE publishes direct to the CVE List rather than via the API, so its
    # timestamps are not a comparable measure of a submission burst.
    cl = cl[cl["assigner_short_name"] != "mitre"]
    # Only timestamps with genuine second-level precision. Date-only and
    # minute-truncated records pile at :00 and would fake enormous bursts.
    real = cl[cl["pub"].dt.second != 0]
    share = 100 * len(real) / len(cl)

    # Count per clock second, then keep only each CNA's single biggest second per
    # day. Without this, one Android upload (18:05:14 to 18:05:18) occupies five
    # rows and reads as five separate competitors.
    per_sec = (real.groupby([real["assigner_short_name"], real["pub"].dt.floor("s")])
                   .size().reset_index(name="n"))
    per_sec.columns = ["cna", "ts", "n"]
    per_sec["day"] = per_sec["ts"].dt.date
    g = (per_sec.sort_values("n", ascending=False)
                .drop_duplicates(subset=["cna", "day"], keep="first")
                .head(TOP_N)[["cna", "ts", "n"]])
    g = g.iloc[::-1]  # ascending so the largest lands at the top

    counts = g["n"].tolist()
    names = [CNA_NAMES.get(c, c) for c in g["cna"]]
    stamps = list(g["ts"])
    top = max(counts)
    is_rec = [c >= 60 for c in counts]   # the two record-setting seconds

    title1 = "Largest Verifiable Single-Second CVE Bursts"
    title2 = ("Most CVEs published in one second. Measures publishing, not "
              "discovery.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        y = np.arange(len(counts))

        colors = [COLORS["primary"] if r else COLORS["light"] for r in is_rec]
        ax.barh(y, counts, color=colors, edgecolor=COLORS["neutral"],
                linewidth=0.8, zorder=3)
        for yi, c in zip(y, counts):
            ax.text(c + top * 0.015, yi, f"{c}", va="center", ha="left",
                    fontsize=11.5, fontweight="bold", color=COLORS["text"])

        # Two-line row label. The gap has to clear descenders on names like
        # "Google Android", so name and timestamp sit well apart within the row.
        for yi, nm, ts in zip(y, names, stamps):
            ax.text(-0.015, yi + 0.21, nm, transform=ax.get_yaxis_transform(),
                    ha="right", va="center", fontsize=11, fontweight="bold",
                    color=COLORS["text"])
            ax.text(-0.015, yi - 0.23, ts.strftime("%b %-d, %Y  %H:%M:%S"),
                    transform=ax.get_yaxis_transform(), ha="right", va="center",
                    fontsize=8.5, color="#556A82")   # ~5:1 on white; #8DA0B5 was 2.68:1

        ax.set_yticks([])
        ax.set_ylim(-0.6, len(counts) - 0.4)
        xtop = (int(top // 20) + 1) * 20
        ax.set_xlim(0, xtop)
        ax.set_xticks(np.arange(0, xtop + 1, 20))
        ax.set_xlabel("CVEs Published in a Single Second", fontsize=11,
                      color=COLORS["secondary"], labelpad=6)
        ax.tick_params(axis="x", labelsize=10, colors=COLORS["secondary"], length=0)
        ax.tick_params(axis="y", length=0)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        foot_size = {"wide": 8, "square": 7, "portrait": 7}[ratio]
        fig.text(0.05, 0.055,
                 f"MITRE excluded: it publishes direct to the CVE List, not via the API, "
                 f"so its timestamps are not comparable.\nEligible records need a non-zero "
                 f"seconds field ({share:.0f}% of the rest). Source: CVE List V5.",
                 fontsize=foot_size, color="#556A82", ha="left",
                 va="bottom", linespacing=1.6)

        top_m = {"wide": 0.80, "square": 0.81, "portrait": 0.83}[ratio]
        left_m = {"wide": 0.20, "square": 0.24, "portrait": 0.26}[ratio]
        t1 = {"wide": 23, "square": 19, "portrait": 18}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.25, left=left_m, right=0.96)
        draw_header(fig, title1, title2, ratio=ratio, eyebrow_suffix="ODDITY",
                    title_size=t1)

        path = GRAPHS / f"second_burst_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

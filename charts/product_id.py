#!/usr/bin/env python3
"""
How do CVEs say what software they affect? CPE vs PURL vs nothing machine-readable.

For the current year, the share of published CVEs that carry a standard product
identifier in the CNA container as authored: CPE (the nearly-two-decade-old identifier
scanners use), PURL (the package-native newcomer), or neither (a record whose product
is named only in free-text vendor/product fields, with no standardized cross-reference
ID). Most CVEs still ship without a standard ID; NVD backfills CPE downstream, and PURL
is only now appearing at all.

Data: processed/product_id_coverage.parquet (per-year scan of the CVE List V5
clone, written by scripts_precompute_product_id.py) + NVD for enriched CPE coverage.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from data import load_nvd
from rolling_config import current_year, data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
PROCESSED = Path(__file__).resolve().parent.parent / "processed"


def render(nvd=None, ratios=DEFAULT_RATIOS):
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)
    cur = current_year(asof)

    cov = pd.read_parquet(PROCESSED / "product_id_coverage.parquet")
    row = cov[cov["year"] == cur].iloc[0]
    base = cov[cov["year"] == cov["year"].min()].iloc[0]
    n = int(row["records"])

    def pct(r, col):
        return 100.0 * r[col] / r["records"]

    # A true partition of every record (priority CPE > package > none), so the
    # segments sum to exactly 100 and a reader can add them up.
    bare_now, bare_then = pct(row, "bare"), pct(base, "bare")
    cpe_now = pct(row, "cpe")                       # has a CPE (may also list a PURL)
    pkg_only = 100.0 - bare_now - cpe_now           # a package id but no CPE
    purl_now = pct(row, "purl")                     # PURL share (cross-cuts CPE), a callout

    # NVD's enriched CPE coverage for the same year (the downstream backfill).
    pub = pd.to_datetime(nvd["published"], utc=True, errors="coerce")
    y = nvd[(pub.dt.year == cur) & (nvd["is_rejected"] != True)]
    nvd_cpe = 100.0 * y["has_cpe"].mean()

    # First year PURL reaches a non-trivial share (>=0.1%), not a stray record.
    share = cov.assign(ps=cov["purl"] / cov["records"])
    purl_years = share[share["ps"] >= 0.001]["year"]
    purl_first = int(purl_years.min()) if len(purl_years) else cur

    # Left -> right along one 100% bar; lead with the problem (no id).
    segs = [
        ("No standard ID", bare_now, COLORS["neutral"], "white"),
        ("CPE", cpe_now, COLORS["accent"], "white"),
        ("Package ID, no CPE", pkg_only, COLORS["light"], COLORS["text"]),
    ]

    title1 = "Most CVEs ship without a standard product ID at publication"
    title2 = (f"How every {cur} CVE identifies the affected product, as the assigning CNA "
              f"writes it. Every CVE falls in exactly one group.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        left = 0.0
        for name, val, color, txtcolor in segs:
            ax.barh(0, val, left=left, height=0.5, color=color, edgecolor="white",
                    linewidth=1.5, zorder=2)
            mid = left + val / 2
            if val >= 14:  # label inside wide segments
                ax.text(mid, 0, f"{name}\n{val:.0f}%", fontsize=11, fontweight="bold",
                        color=txtcolor, ha="center", va="center", zorder=3)
            else:          # label above narrow segments
                ax.text(mid, 0.31, f"{name}\n{val:.0f}%", fontsize=9, fontweight="bold",
                        color=COLORS["text"], ha="center", va="bottom", zorder=3)
                ax.plot([mid, mid], [0.26, 0.30], color=COLORS["neutral"], lw=0.8, zorder=3)
            left += val

        # Two annotations under the bar: PURL (cross-cuts CPE) and the NVD backfill.
        purl_note = (f"PURL, the package-native newcomer, is on just {purl_now:.1f}% "
                     f"(new since {purl_first}, and usually alongside a CPE).")
        nvd_note = (f"NVD later backfills CPE from {cpe_now:.0f}% to about {nvd_cpe:.0f}% "
                    f"after publication.")
        ax.text(0, -0.55, "■", fontsize=11, color=COLORS["primary"], ha="left", va="center")
        ax.text(3.2, -0.55, purl_note, fontsize=9.5, color=COLORS["text"], ha="left", va="center")
        ax.text(0, -0.85, "■", fontsize=11, color=COLORS["accent"], ha="left", va="center")
        ax.text(3.2, -0.85, nvd_note, fontsize=9.5, color=COLORS["text"], ha="left", va="center")

        ax.set_yticks([])
        ax.set_xlim(0, 100)
        ax.set_ylim(-1.05, 0.72)
        ax.set_xticks(np.arange(0, 101, 20))
        ax.set_xticklabels([f"{v}%" for v in range(0, 101, 20)])
        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_visible(False)
        ax.tick_params(axis="both", length=0)
        ax.set_xticks([])

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.12,
                 f"As-authored in the CVE List CNA container, {n:,} non-rejected CVEs in {cur}. "
                 f"Free-text share was {bare_then:.0f}% in {int(base['year'])}. Source: CVE List V5 + NVD.",
                 fontsize=foot_size, color=COLORS["neutral"], ha="left", va="top")

        top_m = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        t1 = {"wide": 20, "square": 17, "portrait": 17}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.24, left=0.06, right=0.96)
        fig.text(0.05, 0.965, title1, fontsize=t1, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.915, title2, fontsize=10.5, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"product_id_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

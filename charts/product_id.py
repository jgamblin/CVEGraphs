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

    bare_now, bare_then = pct(row, "bare"), pct(base, "bare")
    cpe_now, cpe_then = pct(row, "cpe"), pct(base, "cpe")
    purl_now = pct(row, "purl")

    # NVD's enriched CPE coverage for the same year (the downstream backfill).
    pub = pd.to_datetime(nvd["published"], utc=True, errors="coerce")
    y = nvd[(pub.dt.year == cur) & (nvd["is_rejected"] != True)]
    nvd_cpe = 100.0 * y["has_cpe"].mean()

    # First year PURL reaches a non-trivial share (>=0.1%), not a stray record.
    share = cov.assign(ps=cov["purl"] / cov["records"])
    purl_years = share[share["ps"] >= 0.001]["year"]
    purl_first = int(purl_years.min()) if len(purl_years) else cur

    # bottom -> top
    bars = [
        ("PURL", "package-native identifier", purl_now, COLORS["primary"],
         f"first appeared in {purl_first}"),
        ("CPE", "as the CNA authors it", cpe_now, COLORS["accent"],
         f"up from {cpe_then:.0f}% in {int(base['year'])}"),
        ("No standard product ID", "vendor and product text only", bare_now, COLORS["secondary"],
         f"down from {bare_then:.0f}% in {int(base['year'])}"),
    ]

    title1 = "Most CVEs ship without a standard product ID at publication"
    title2 = (f"Share of {cur} CVEs that carry a standard product identifier (CPE or PURL), "
              f"as the assigning CNA writes it.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        for i, (name, sub, val, color, trend) in enumerate(bars):
            ax.barh(i, val, height=0.6, color=color, edgecolor="white",
                    linewidth=1.0, zorder=2)
            ax.text(val + 1.2, i, f"{val:.1f}%" if val < 10 else f"{val:.0f}%",
                    fontsize=11, fontweight="bold", color=COLORS["text"],
                    ha="left", va="center")
            ax.text(-0.02, i + 0.16, name, transform=ax.get_yaxis_transform(),
                    fontsize=11, fontweight="bold", color=COLORS["text"],
                    ha="right", va="center")
            ax.text(-0.02, i - 0.17, f"{sub} · {trend}", transform=ax.get_yaxis_transform(),
                    fontsize=8, color=COLORS["secondary"], ha="right", va="center")

        # CPE more than doubles once NVD backfills it: a ghost extension of the CPE bar
        # (index 1) from its as-authored value out to NVD's enriched coverage.
        ax.barh(1, nvd_cpe - cpe_now, left=cpe_now, height=0.6, color=COLORS["light"],
                edgecolor="white", linewidth=1.0, zorder=1)
        ax.text(nvd_cpe + 1.2, 1, f"{nvd_cpe:.0f}%", fontsize=10, fontweight="bold",
                color=COLORS["secondary"], ha="left", va="center")
        ax.text(nvd_cpe, 1 + 0.42, "after NVD backfill", fontsize=8, fontweight="bold",
                color=COLORS["secondary"], ha="center", va="bottom")

        ax.set_yticks([])
        ax.set_xlim(0, 100)
        ax.set_ylim(-0.7, len(bars) - 0.3)
        ax.set_xticks(np.arange(0, 101, 20))
        ax.set_xticklabels([f"{v}%" for v in range(0, 101, 20)])
        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="y", length=0)
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.10,
                 f"As-authored in the CVE List CNA container, {n:,} CVEs in {cur}. CPE and PURL "
                 f"counted independently. Source: CVE List V5 + NVD.",
                 fontsize=foot_size, color=COLORS["neutral"], ha="left", va="top")

        top_m = {"wide": 0.83, "square": 0.85, "portrait": 0.87}[ratio]
        t1 = {"wide": 20, "square": 17, "portrait": 17}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.22, left=0.30, right=0.94)
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

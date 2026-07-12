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

    # Three unstacked bars, one per group. They partition every record, so they sum
    # to 100. Labels are what the group actually is, not a vague "package id".
    bars = [
        ("No product ID", "free-text vendor and product only", bare_now, COLORS["neutral"]),
        ("CPE", "the incumbent standard identifier", cpe_now, COLORS["accent"]),
        ("Package or plugin name", "WordPress, npm, Maven, no CPE", pkg_only, COLORS["light"]),
    ]

    title1 = "Most CVEs ship without a standard product ID at publication"
    title2 = (f"How every {cur} CVE identifies the affected product, as the assigning CNA "
              f"writes it. The three groups sum to 100%.")

    # PURL is not one of the bars: it mostly rides along with a CPE, so it is a callout.
    purl_note = (f"PURL, pitched as the modern replacement for CPE, is on only {purl_now:.1f}% "
                 f"and almost always rides alongside a CPE, not on its own.")
    nvd_note = (f"NVD later backfills CPE from {cpe_now:.0f}% to about {nvd_cpe:.0f}% "
                f"after publication.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        pos = np.arange(len(bars))[::-1]  # first bar on top

        for y, (name, sub, val, color) in zip(pos, bars):
            ax.barh(y, val, height=0.62, color=color, edgecolor="white", linewidth=1.0, zorder=2)
            ax.text(val + 1.0, y, f"{val:.0f}%", fontsize=13, fontweight="bold",
                    color=COLORS["text"], ha="left", va="center")
            ax.text(-0.02, y + 0.17, name, transform=ax.get_yaxis_transform(), fontsize=12,
                    fontweight="bold", color=COLORS["text"], ha="right", va="center")
            ax.text(-0.02, y - 0.18, sub, transform=ax.get_yaxis_transform(), fontsize=8.5,
                    color=COLORS["secondary"], ha="right", va="center")

        ax.text(0, -1.05, "■", fontsize=11, color=COLORS["primary"], ha="left", va="center")
        ax.text(2.6, -1.05, purl_note, fontsize=9.5, color=COLORS["text"], ha="left", va="center")
        ax.text(0, -1.42, "■", fontsize=11, color=COLORS["accent"], ha="left", va="center")
        ax.text(2.6, -1.42, nvd_note, fontsize=9.5, color=COLORS["text"], ha="left", va="center")

        ax.set_yticks([])
        ax.set_xlim(0, 74)
        ax.set_ylim(-1.7, len(bars) - 0.35)
        for s in ("left", "right", "top", "bottom"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="both", length=0)
        ax.set_xticks([])

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.12,
                 f"As-authored in the CVE List CNA container, {n:,} non-rejected CVEs in {cur}. "
                 f"Free-text share was {bare_then:.0f}% in {int(base['year'])}. Source: CVE List V5 + NVD.",
                 fontsize=foot_size, color=COLORS["neutral"], ha="left", va="top")

        top_m = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        t1 = {"wide": 20, "square": 17, "portrait": 17}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.22, left=0.26, right=0.95)
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

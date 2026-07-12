#!/usr/bin/env python3
"""
What CVE enrichment fixes, and what it ignores: CPE vs PURL, before and after backfill.

For the current year, the share of CVEs carrying each identifier as the CNA writes it
(solid) versus after NVD and CISA enrichment (shaded). CPE gets a big backfill (about
26% to 59%); PURL gets nothing, because NVD is CPE-only and the CISA ADP container
carries no PURLs. So PURL, pitched as CPE's modern replacement, is neither adopted by
CNAs nor added by enrichers.

Data: processed/product_id_coverage.parquet (per-year scan of the CVE List V5 clone,
written by scripts_precompute_product_id.py) + NVD for enriched CPE coverage. The
zero-PURL-backfill finding is from a scan of the ADP containers (see the caption).
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
    n = int(row["records"])

    def pct(col):
        return 100.0 * row[col] / row["records"]

    bare_now = pct("bare")
    cpe_auth = pct("cpe")
    purl_auth = pct("purl")

    # Enriched CPE from NVD (downstream backfill). PURL gets no backfill: NVD is
    # CPE-only, and the CISA ADP container carries 0.0% PURL (scanned separately).
    pub = pd.to_datetime(nvd["published"], utc=True, errors="coerce")
    y = nvd[(pub.dt.year == cur) & (nvd["is_rejected"] != True)]
    cpe_enr = 100.0 * y["has_cpe"].mean()
    purl_enr = purl_auth

    groups = [("CPE", "the incumbent standard"), ("PURL", "the proposed replacement")]
    authored = [cpe_auth, purl_auth]
    enriched = [cpe_enr, purl_enr]

    title1 = "CVE enrichment rescues CPE. It does nothing for PURL."
    title2 = (f"Share of {cur} CVEs carrying each product identifier, before and after "
              f"NVD and CISA enrichment. {bare_now:.0f}% carry neither.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        x = np.arange(len(groups))
        w = 0.36

        b1 = ax.bar(x - w / 2, authored, w, color=COLORS["accent"], edgecolor="white",
                    linewidth=1.0, label="As the CNA writes it", zorder=3)
        b2 = ax.bar(x + w / 2, enriched, w, color=COLORS["primary"], edgecolor="white",
                    linewidth=1.0, label="After NVD + CISA enrichment", zorder=3)

        for rects, vals in ((b1, authored), (b2, enriched)):
            for rect, v in zip(rects, vals):
                label = f"{v:.0f}%" if v >= 10 else f"{v:.1f}%"
                ax.text(rect.get_x() + rect.get_width() / 2, v + 1.0, label, ha="center",
                        va="bottom", fontsize=12, fontweight="bold", color=COLORS["text"])

        ax.set_xticks(x)
        ax.set_xticklabels([g[0] for g in groups], fontsize=15, fontweight="bold")
        for xi, (_, sub) in zip(x, groups):
            ax.text(xi, -0.075, sub, transform=ax.get_xaxis_transform(), ha="center",
                    va="top", fontsize=9.5, color=COLORS["secondary"])

        ax.set_ylim(0, max(enriched) * 1.2)
        ax.set_yticks([0, 20, 40, 60])
        ax.set_yticklabels(["0", "20%", "40%", "60%"], fontsize=10, color=COLORS["secondary"])
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="both", length=0)

        ax.legend(loc="upper right", frameon=False, fontsize=10.5, handletextpad=0.6)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.09, 0.05,
                 f"{n:,} non-rejected {cur} CVEs. Enriched CPE per NVD; the CISA ADP container "
                 f"adds no PURLs. Source: CVE List V5 + NVD.",
                 fontsize=foot_size, color=COLORS["neutral"], ha="left", va="bottom")

        top_m = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        t1 = {"wide": 20, "square": 16, "portrait": 16}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.16, left=0.09, right=0.95)
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

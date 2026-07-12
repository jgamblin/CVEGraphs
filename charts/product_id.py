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

    # Two identifiers, each shown as-authored (solid) plus what NVD/CISA backfill
    # adds (shaded). CPE gets a big lift; PURL gets nothing (NVD is CPE-only, and
    # the CISA ADP container carries 0.0% PURL). purl_enr == purl_auth by that scan.
    cpe_auth, cpe_enr = cpe_now, nvd_cpe
    purl_auth, purl_enr = purl_now, purl_now
    rows_ = [
        ("CPE", "the incumbent standard", cpe_auth, cpe_enr, COLORS["accent"]),
        ("PURL", "the proposed replacement", purl_auth, purl_enr, COLORS["primary"]),
    ]

    title1 = "CVE enrichment rescues CPE. It does nothing for PURL."
    title2 = (f"Share of {cur} CVEs carrying each identifier, as the CNA writes it (solid) "
              f"and after NVD and CISA backfill (shaded).")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        pos = np.arange(len(rows_))[::-1]

        for y, (name, sub, auth, enr, color) in zip(pos, rows_):
            ax.barh(y, auth, height=0.52, color=color, edgecolor="white", linewidth=1.0, zorder=3)
            if enr > auth + 0.5:
                ax.barh(y, enr - auth, left=auth, height=0.52, color=COLORS["light"],
                        edgecolor="white", linewidth=1.0, zorder=2)
                ax.text(auth - 1.0, y, f"{auth:.0f}%", fontsize=12, fontweight="bold",
                        color="white", ha="right", va="center", zorder=4)
                ax.text(enr + 1.0, y, f"{enr:.0f}%", fontsize=13, fontweight="bold",
                        color=COLORS["text"], ha="left", va="center")
                ax.text((auth + enr) / 2, y + 0.40,
                        f"+{round(enr) - round(auth):.0f} points from backfill",
                        fontsize=9, fontweight="bold", color=COLORS["secondary"],
                        ha="center", va="bottom")
            else:
                ax.text(auth + 1.0, y, f"{auth:.1f}%", fontsize=13, fontweight="bold",
                        color=COLORS["text"], ha="left", va="center")
                ax.text(auth + 8.0, y, "backfill adds nothing", fontsize=10, fontweight="bold",
                        color=COLORS["primary"], ha="left", va="center")
            ax.text(-0.02, y + 0.17, name, transform=ax.get_yaxis_transform(), fontsize=13,
                    fontweight="bold", color=COLORS["text"], ha="right", va="center")
            ax.text(-0.02, y - 0.19, sub, transform=ax.get_yaxis_transform(), fontsize=8.5,
                    color=COLORS["secondary"], ha="right", va="center")

        # Context banner up top: most CVEs carry neither identifier to begin with.
        ax.text(0, 2.15, f"{bare_now:.0f}%", fontsize=34, fontweight="bold",
                color=COLORS["secondary"], ha="left", va="center")
        ax.text(13.5, 2.28, "of 2026 CVEs carry neither CPE nor PURL,", fontsize=11.5,
                fontweight="bold", color=COLORS["text"], ha="left", va="center")
        ax.text(13.5, 2.02, "as the assigning CNA writes them.", fontsize=11.5,
                color=COLORS["secondary"], ha="left", va="center")

        # legend for solid vs shaded
        ax.barh(-1.15, 4, height=0.34, color=COLORS["accent"], zorder=3)
        ax.text(6, -1.15, "as the CNA writes it", fontsize=9.5, color=COLORS["text"], va="center")
        ax.barh(-1.15, 4, left=34, height=0.34, color=COLORS["light"], zorder=3)
        ax.text(40, -1.15, "added by NVD + CISA backfill", fontsize=9.5, color=COLORS["text"], va="center")

        ax.set_yticks([])
        ax.set_xlim(0, 72)
        ax.set_ylim(-1.6, 2.7)
        for s in ("left", "right", "top", "bottom"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="both", length=0)
        ax.set_xticks([])

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.12,
                 f"{n:,} non-rejected {cur} CVEs. Enriched CPE per NVD; the CISA ADP container "
                 f"adds no PURLs. Source: CVE List V5 + NVD.",
                 fontsize=foot_size, color=COLORS["neutral"], ha="left", va="top")

        top_m = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        t1 = {"wide": 20, "square": 16, "portrait": 16}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.22, left=0.22, right=0.95)
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

#!/usr/bin/env python3
"""
What CVE enrichment fixes, and what it ignores: CPE vs PURL, before and after backfill.

A horizontal grouped bar chart, three groups (No CPE or PURL / CPE / PURL) each shown as
the CNA authors it and after NVD/CISA enrichment, on the SAME cohort: CVEs PUBLISHED in
the year (not CVE-<year>-* IDs), so the ~38k denominator matches cve.icu. Enrichment
nearly halves the no-ID pile (~75% to ~40%), all by backfilling CPE (about 25% to 59%);
PURL stays ~2% because NVD is CPE-only and the CISA ADP container carries no PURLs.

Data: processed/product_id_cve_flags.parquet (per-CVE CNA-authored CPE/PURL flags for CVEs
published in the latest year, written by scripts_precompute_product_id.py) joined to NVD's
enriched has_cpe. The zero-PURL-backfill finding is from a scan of the ADP containers.
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

    # Same-cohort before/after: join CNA-authored flags (CVE List) to NVD's enriched
    # CPE, so "as authored" and "after enrichment" are measured on the same CVEs.
    flags = pd.read_parquet(PROCESSED / "product_id_cve_flags.parquet")
    flags = flags[flags["year"] == cur]
    pub = pd.to_datetime(nvd["published"], utc=True, errors="coerce")
    nv = (nvd[(pub.dt.year == cur) & (nvd["is_rejected"] != True)][["cve_id", "has_cpe"]]
          .drop_duplicates("cve_id"))
    j = flags.merge(nv, on="cve_id", how="inner")
    n = len(j)

    def share(mask):
        return 100.0 * mask.mean()

    # Exclusive groups (priority PURL > CPE > neither) so each column sums to 100.
    purl_val = share(j["purl"])                              # no backfill: PURL is unchanged
    cpe_auth = share(j["cpe_cna"] & ~j["purl"])              # CPE, no PURL
    cpe_enr = share(j["has_cpe"] & ~j["purl"])
    neither_auth = share(~j["cpe_cna"] & ~j["purl"])
    neither_enr = share(~j["has_cpe"] & ~j["purl"])

    # Round for display so the labels sum to exactly 100 (naive rounding can give 101).
    # PURL is pinned to one value across both columns (it does not change), and the two
    # larger groups take the rounding remainder via largest-remainder.
    purl_disp = round(purl_val)

    def _pair(a, b, target):
        fa, fb = int(a), int(b)
        out = [fa, fb]
        order = sorted(((a - fa, 0), (b - fb, 1)), reverse=True)
        for k in range(target - fa - fb):
            out[order[k][1]] += 1
        return out

    nei_a, cpe_a = _pair(neither_auth, cpe_auth, 100 - purl_disp)
    nei_e, cpe_e = _pair(neither_enr, cpe_enr, 100 - purl_disp)

    # top -> bottom  (display integers; each column sums to 100)
    rows_ = [
        ("No CPE or PURL", "Free text or package name", nei_a, nei_e),
        ("CPE", "The incumbent standard", cpe_a, cpe_e),
        ("PURL", "The proposed replacement", purl_disp, purl_disp),
    ]

    title1 = f"How {cur} CVEs Identify the Affected Product"
    title2 = ("Share carrying CPE, PURL, or neither, before and after NVD and CISA enrichment.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        pos = np.arange(len(rows_))[::-1]
        h = 0.36

        first = True
        for y, (name, sub, auth, enr) in zip(pos, rows_):
            ax.barh(y + h / 2, auth, height=h, color=COLORS["accent"], edgecolor="white",
                    linewidth=1.0, zorder=3, label="As the CNA writes it" if first else None)
            ax.barh(y - h / 2, enr, height=h, color=COLORS["primary"], edgecolor="white",
                    linewidth=1.0, zorder=3, label="After NVD + CISA enrichment" if first else None)
            for val, yy in ((auth, y + h / 2), (enr, y - h / 2)):
                ax.text(val + 1.2, yy, f"{round(val)}%", ha="left", va="center", fontsize=11,
                        fontweight="bold", color=COLORS["text"])
            ax.text(-0.02, y + 0.20, name, transform=ax.get_yaxis_transform(), ha="right",
                    va="center", fontsize=12.5, fontweight="bold", color=COLORS["text"])
            ax.text(-0.02, y - 0.16, sub, transform=ax.get_yaxis_transform(), ha="right",
                    va="center", fontsize=8.5, color=COLORS["secondary"])
            first = False

        ax.set_yticks([])
        ax.set_xlim(0, 100)
        ax.set_ylim(-0.7, len(rows_) - 0.3)
        ax.set_xticks([0, 20, 40, 60, 80, 100])
        ax.set_xticklabels([f"{v}%" for v in (0, 20, 40, 60, 80, 100)], fontsize=10,
                           color=COLORS["secondary"])
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="both", length=0)

        ax.legend(loc="lower right", frameon=False, fontsize=10.5, handletextpad=0.6,
                  bbox_to_anchor=(1.0, -0.02))

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05,
                 f"{n:,} {cur} CVEs in both CVE List and NVD. Groups are exclusive: a CVE with "
                 f"both CPE and PURL counts under PURL. Source: CVE List V5 + NVD.",
                 fontsize=foot_size, color=COLORS["neutral"], ha="left", va="bottom")

        top_m = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        t1 = {"wide": 18, "square": 15, "portrait": 15}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.15, left=0.24, right=0.95)
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

#!/usr/bin/env python3
"""
Where "critical" (CVSS 9.0+) CVEs rank on exploitation likelihood.

Every 2026 CVE rated 9.0 or higher, placed by CVSS base score (x) against EPSS
PERCENTILE (y, its exploitation rank vs all CVEs). CVSS cannot separate them,
half sit on the single value 9.8, while EPSS percentile spreads them across the
full range. Red marks the ones CISA has ADDED TO ITS KEV catalog (a curated,
documented-exploited subset, not the full set of exploited CVEs); they cluster at
the top of the EPSS ranking.

Percentile, not raw probability, is deliberate: it shows relative ranking without
an arbitrary "danger" threshold, and it avoids the crushed-to-the-floor look of a
linear probability axis. Note percentile is RANK, not likelihood: a 90th-percentile
CVE is more likely than 90% of CVEs, which can still be a small absolute chance.
Do not mix raw-probability claims into copy built on this chart.

Note on language: "added to KEV" / "on the KEV list", never a blanket "exploited"
(KEV is a subset; other CVEs are exploited without being on it, and not-on-KEV
does not mean not-exploited). See content/INSIGHTS.md.

Data: NVD (CVSS v3) + EPSS percentile + CISA KEV, 2026 year-to-date, CVSS 9.0+.
"""

import json

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D

from cvegraphs.data import load_epss, load_nvd
from cvegraphs.paths import OUTPUT, PROCESSED
from cvegraphs.rolling import current_year, data_asof, ytd_mask
from cvegraphs.style import COLORS, DEFAULT_RATIOS, draw_header, figsize_for, stamp_and_save

DESCRIPTION = "Scatter: 2026 critical (9.0+) CVEs, CVSS vs EPSS; how few clear the danger band"

GRAPHS = OUTPUT
MIN_CVSS = 9.0  # "critical" cohort only


def render(nvd=None, ratios=DEFAULT_RATIOS):
    if nvd is None:
        nvd = load_nvd(with_epss=True)
    for col in ("epss", "percentile"):
        if col not in nvd.columns:
            nvd = nvd.merge(load_epss()[["cve_id", col]], on="cve_id", how="left")
    asof = data_asof(nvd)
    cur = current_year(asof)
    model = load_epss()["model_version"].iloc[0] or "EPSS"

    kev_ids = {e["cveID"] for e in
               json.load(open(PROCESSED / "kev_catalog.json")).get("vulnerabilities", [])}
    df = nvd[ytd_mask(nvd, cur, asof)].dropna(subset=["cvss_v3", "epss", "percentile"])
    df = df[df["cvss_v3"] >= MIN_CVSS]
    rng = np.random.default_rng(0)
    x = df["cvss_v3"].to_numpy()
    # Jitter so the 9.8 pile reads as a cloud, clamped just outside the real range
    # so no impossible score renders while the end columns keep full width.
    xj = np.clip(x + rng.uniform(-0.02, 0.02, size=len(x)), 8.98, 10.02)
    pct = df["percentile"].to_numpy()
    if np.nanmax(pct) <= 1.0:  # EPSS percentile ships as 0-1; show as 0-100
        pct = pct * 100.0
    kev = df["cve_id"].isin(kev_ids).to_numpy()  # on the CISA KEV list (documented
    # subset, not the full set of exploited CVEs)
    n = len(df)
    n_kev = int(kev.sum())
    # Computed, never hardcoded: the 9.8 share drifts with every refresh.
    n98 = int((x == 9.8).sum())
    lead = "Half" if 0.48 <= n98 / n <= 0.52 else f"{n98 / n:.0%}"

    title1 = f"Severity vs Exploitation Ranking, {cur} Critical CVEs"
    title2 = (f"Each dot is a CVE published in {cur} with a CVSS v3 score of 9.0 to 10.0, "
              f"placed by where it ranks on EPSS.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        # The mass: navy, jittered; alpha set so lone tail dots clear 3:1 on white.
        ax.scatter(xj[~kev], pct[~kev], s=11, alpha=0.48, color=COLORS["primary"],
                   edgecolors="none", zorder=3)
        # On the CISA KEV list (documented subset), drawn on top.
        ax.scatter(xj[kev], pct[kev], s=26, alpha=0.95, color=COLORS["alert"],
                   edgecolors="white", linewidths=0.5, zorder=5)

        # Make the 9.8 pileup explicit; arrow points at the column's mid-height so it
        # cannot be misread as labelling only the low-ranked dots.
        ax.annotate(f"{lead} ({n98:,}) score\nexactly 9.8", xy=(9.76, 45),
                    xytext=(9.50, 62), fontsize=10, fontweight="bold",
                    color=COLORS["secondary"], ha="center", va="center", zorder=7,
                    arrowprops=dict(arrowstyle="->", color=COLORS["secondary"],
                                    lw=1.3, alpha=0.9))

        ax.set_xlim(8.88, 10.12)
        ax.set_ylim(-3, 103)
        ax.set_xticks(np.arange(9.0, 10.01, 0.1))
        ax.set_yticks([0, 25, 50, 75, 100])
        ax.set_xlabel("CVSS v3 Base Score", fontsize=11,
                      fontweight="normal", color=COLORS["secondary"], labelpad=6)
        ax.set_ylabel("EPSS Percentile (rank vs all CVEs)", fontsize=11,
                      fontweight="normal", color=COLORS["secondary"], labelpad=6)
        ax.tick_params(labelsize=9, colors=COLORS["secondary"], length=0)
        for s in ("top", "right"):
            ax.spines[s].set_visible(False)
        for s in ("left", "bottom"):
            ax.spines[s].set_color(COLORS["grid"])
        ax.grid(True, color=COLORS["grid"], lw=0.6, alpha=0.6)
        ax.set_axisbelow(True)

        # Legend above the plot: inside the axes it sat on top of live data points.
        ax.legend(handles=[
            Line2D([0], [0], marker="o", color="none", markerfacecolor=COLORS["primary"],
                   markeredgecolor="none", markersize=9, label=f"Critical CVEs ({n:,})"),
            Line2D([0], [0], marker="o", color="none", markerfacecolor=COLORS["alert"],
                   markeredgecolor="white", markersize=9, label=f"Added to CISA KEV ({n_kev})")],
            loc="upper center", bbox_to_anchor=(0.5, -0.155), ncol=2, frameon=False,
            fontsize=10, handletextpad=0.4, columnspacing=2.4)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.035,
                 f"CVEs published in {cur} with a CVSS v3 base score of 9.0 or higher and "
                 f"an EPSS score, jittered to reduce overlap.\n"
                 f"Data through {asof.strftime('%b %-d, %Y')}. Sources: NVD, EPSS {model}, "
                 f"CISA KEV.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom",
                 linespacing=1.5)

        top_m = {"wide": 0.80, "square": 0.81, "portrait": 0.82}[ratio]
        t1 = {"wide": 22, "square": 18, "portrait": 17}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.27, left=0.11, right=0.96)
        draw_header(fig, title1, title2, ratio=ratio, eyebrow_suffix="SCORING",
                    title_size=t1)

        path = GRAPHS / f"cvss_epss_scatter_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

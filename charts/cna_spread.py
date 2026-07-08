#!/usr/bin/env python3
"""
One weakness class, many scorers: how CNAs disagree on CVSS for the same CWE.

For a single CWE (default XSS / CWE-79), show each high-volume CNA's typical
range of CVSS v3 scores (a bar from the 10th to 90th percentile) with a bold
tick at its average. Every CNA is consistent with itself, but the averages sit
across a ~3-point span, so the "same bug" lands very differently depending on
who scored it. The concrete, legible version of the "who holds the ruler matters
more than which ruler" story.

Uses CVE List V5 (the CNA's own vectors) and CVSS v3, which has the broadest
cross-CNA coverage; v4 adoption is too uneven per-CNA to compare cleanly yet.
Absolute min/max is deliberately avoided: a few rare outliers per CNA stretch
every bar across the whole scale and hide the difference, so the bar shows where
the middle 80% of each CNA's scores actually fall.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap

from data import load_cvelist, load_nvd
from rolling_config import data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

# Bars are colored by CVSS severity along the 0-10 scale in a cool blue/grey ramp:
# light grey (low) through mid blue up to deep navy (high). Single-family so the
# gradient stays clean, and on-brand.
SEV_CMAP = LinearSegmentedColormap.from_list("cvss_sev", [
    (0.00, COLORS["light"]),      # low -> light grey
    (0.35, COLORS["neutral"]),    # -> grey
    (0.70, COLORS["accent"]),     # -> mid blue
    (1.00, COLORS["primary"]),    # high -> deep navy
])

CWE = "CWE-79"          # swap to re-aim the chart at another weakness class
VER = "cvss_v3"         # v3 has the broadest cross-CNA coverage
MIN_N = 100             # a CNA needs this many scored CVEs of the class to show

CWE_NAMES = {
    "CWE-79": "Cross-site scripting (XSS)", "CWE-89": "SQL injection",
    "CWE-352": "CSRF", "CWE-22": "Path traversal", "CWE-78": "OS command injection",
    "CWE-434": "Unrestricted file upload", "CWE-918": "SSRF",
    "CWE-120": "Buffer copy overflow", "CWE-125": "Out-of-bounds read",
}


def render(nvd=None, ratios=DEFAULT_RATIOS, cwe=CWE):
    cl = load_cvelist()
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)  # share one date with the rest of the posting set

    d = cl[(cl["cwe"] == cwe) & cl[VER].notna()]
    grp = d.groupby("assigner_short_name")[VER]
    counts = grp.size()
    keep = counts[counts >= MIN_N].index
    stats = (grp.mean()[keep]).sort_values()  # ascending -> low at bottom
    order = list(stats.index)
    data = [d[d["assigner_short_name"] == c][VER].values for c in order]
    ns = [int(counts[c]) for c in order]

    # Typical range (10th-90th percentile) where each CNA's scores fall, plus the
    # average. Percentiles, not raw min/max, so rare outliers don't stretch every
    # bar across the whole scale.
    lob = [float(np.percentile(v, 10)) for v in data]
    hib = [float(np.percentile(v, 90)) for v in data]
    means = [float(np.mean(v)) for v in data]

    lo, hi = stats.min(), stats.max()
    name = CWE_NAMES.get(cwe, cwe)
    # Short label for the title (the acronym in parens if any) so it fits portrait.
    short = name[name.index("(") + 1:name.index(")")] if "(" in name else name
    title1 = f"One weakness, many scorers: CVSS for {short}"
    title2 = (f"Same bug class, different CNAs scoring it. Their average scores "
              f"range from {lo:.1f} to {hi:.1f}.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        pos = np.arange(len(order))

        for i, y in enumerate(pos):
            # Capsule: where the middle 80% of this CNA's scores fall, filled with
            # the severity gradient (colored by score, so low CNAs read cooler).
            if hib[i] > lob[i]:
                grad = np.linspace(lob[i], hib[i], 256).reshape(1, -1)
                ax.imshow(grad, extent=(lob[i], hib[i], y - 0.22, y + 0.22),
                          cmap=SEV_CMAP, vmin=0, vmax=10, aspect="auto",
                          interpolation="bilinear", zorder=1)
            # Bold tick at the average, with a white halo so it stays readable on
            # both the pale (low) and deep-navy (high) ends of the bar.
            ax.plot([means[i], means[i]], [y - 0.28, y + 0.28], color="white",
                    lw=5.0, solid_capstyle="round", zorder=3)
            ax.plot([means[i], means[i]], [y - 0.26, y + 0.26], color=COLORS["text"],
                    lw=2.5, solid_capstyle="round", zorder=4)
            ax.text(means[i], y + 0.3, f"{means[i]:.1f}", fontsize=9.5,
                    fontweight="bold", color=COLORS["text"], ha="center", va="bottom")
            # Low / high labels at the band ends, only when the band is wide enough
            # to separate them (collapsed bands are already summed up by the average).
            if hib[i] - lob[i] >= 0.4:
                ax.text(lob[i] - 0.15, y, f"{lob[i]:.1f}", fontsize=8,
                        color=COLORS["neutral"], ha="right", va="center")
                ax.text(hib[i] + 0.15, y, f"{hib[i]:.1f}", fontsize=8,
                        color=COLORS["neutral"], ha="left", va="center")

        ax.set_yticks(pos)
        ax.set_yticklabels(order, fontsize=11.5, fontweight="bold")
        # CVE count in a fixed right-hand column.
        for y, nval in zip(pos, ns):
            ax.text(1.005, y, f"{nval:,} CVEs", transform=ax.get_yaxis_transform(),
                    fontsize=7.5, color=COLORS["neutral"], ha="left", va="center")

        ax.set_xlabel("CVSS v3 base score")
        ax.set_xlim(0, 10)
        ax.set_ylim(-0.7, len(order) - 0.3)
        ax.set_xticks(range(0, 11, 2))
        ax.spines["bottom"].set_bounds(0, 10)

        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="y", length=0)
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        ax.text(0.0, -0.205,
                f"CVSS v3 for {cwe} by CNA ({MIN_N}+ CVEs). "
                "Bar = middle 80%; tick = average. Source: CVE List V5.",
                transform=ax.transAxes, fontsize=foot_size, color=COLORS["neutral"], va="top")

        top = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        t1_size = {"wide": 19, "square": 18, "portrait": 18}[ratio]
        fig.subplots_adjust(top=top, bottom=0.18, left=0.20, right=0.88)
        fig.text(0.05, 0.965, title1, fontsize=t1_size, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.918, title2, fontsize=11, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"cna_spread_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

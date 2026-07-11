#!/usr/bin/env python3
"""
How severe is each weakness class? CVSS spread by CWE.

For the ten most common CWEs, show the typical range of CVSS v3 base scores (a
bar from the 10th to 90th percentile, colored by severity) with a bold tick at
the median. Companion to `cna_spread`: that one holds the weakness fixed and
varies the scorer. This one is single-source (the CNA's own v3 vector, one per
CVE) and varies the weakness, so band width reflects real severity variation
across different CVEs within a class. It does NOT measure scorer disagreement.

Uses CVE List V5 and CVSS v3 for the broadest coverage.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap

from data import load_cvelist, load_nvd
from rolling_config import data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

VER = "cvss_v3"
TOP_N = 10

# Blue/grey severity ramp (light grey low -> deep navy high), matching cna_spread.
SEV_CMAP = LinearSegmentedColormap.from_list("cvss_sev", [
    (0.00, COLORS["light"]),
    (0.35, COLORS["neutral"]),
    (0.70, COLORS["accent"]),
    (1.00, COLORS["primary"]),
])

CWE_NAMES = {
    "CWE-79": "XSS", "CWE-89": "SQL injection", "CWE-862": "Missing authz",
    "CWE-352": "CSRF", "CWE-22": "Path traversal", "CWE-20": "Input validation",
    "CWE-125": "Out-of-bounds read", "CWE-78": "OS command inj.",
    "CWE-200": "Info exposure", "CWE-121": "Stack overflow", "CWE-416": "Use-after-free",
    "CWE-787": "Out-of-bounds write", "CWE-434": "File upload", "CWE-918": "SSRF",
    "CWE-94": "Code injection", "CWE-502": "Deserialization", "CWE-284": "Access control",
}


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist()
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)

    d = cl[cl[VER].notna() & cl["cwe"].notna()]
    top = list(d["cwe"].value_counts().head(TOP_N).index)
    data = {c: d[d["cwe"] == c][VER].values for c in top}
    med = {c: float(np.median(v)) for c, v in data.items()}
    order = sorted(top, key=lambda c: med[c])  # ascending -> low at bottom

    lob = [float(np.percentile(data[c], 10)) for c in order]
    hib = [float(np.percentile(data[c], 90)) for c in order]
    meds = [med[c] for c in order]
    ns = [len(data[c]) for c in order]
    labels = [CWE_NAMES.get(c, c) for c in order]

    lo, hi = min(meds), max(meds)
    title1 = "How severe is each weakness class?"
    title2 = f"80% range and median CVSS v3 for the {TOP_N} most common CWEs."

    ov_lo, ov_hi = max(lob), min(hib)  # band every class's 80% range overlaps

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        pos = np.arange(len(order))

        for i, y in enumerate(pos):
            if hib[i] > lob[i]:
                grad = np.linspace(lob[i], hib[i], 256).reshape(1, -1)
                ax.imshow(grad, extent=(lob[i], hib[i], y - 0.22, y + 0.22),
                          cmap=SEV_CMAP, vmin=0, vmax=10, aspect="auto",
                          interpolation="bilinear", zorder=1)
            # Median tick with a white halo so it reads on pale and dark ends alike.
            ax.plot([meds[i], meds[i]], [y - 0.28, y + 0.28], color="white",
                    lw=5.0, solid_capstyle="round", zorder=3)
            ax.plot([meds[i], meds[i]], [y - 0.26, y + 0.26], color=COLORS["text"],
                    lw=2.5, solid_capstyle="round", zorder=4)
            ax.text(meds[i], y + 0.3, f"{meds[i]:.1f}", fontsize=9.5,
                    fontweight="bold", color=COLORS["text"], ha="center", va="bottom")
            ax.text(lob[i] - 0.15, y, f"{lob[i]:.1f}", fontsize=8,
                    color=COLORS["neutral"], ha="right", va="center")
            ax.text(hib[i] + 0.15, y, f"{hib[i]:.1f}", fontsize=8,
                    color=COLORS["neutral"], ha="left", va="center")

        # Common overlap band: every one of the 10 classes has its middle 80%
        # passing through here, so a score in this range fits any of them.
        ax.axvspan(ov_lo, ov_hi, color="0.5", alpha=0.15, zorder=2.4)  # neutral grey
        for xb in (ov_lo, ov_hi):
            ax.plot([xb, xb], [-0.7, len(order) + 0.25], color="0.35",
                    lw=1.0, ls=(0, (4, 3)), alpha=0.7, zorder=2.5)
        yb = len(order) - 0.15
        ax.plot([ov_lo, ov_hi], [yb, yb], color="0.25", lw=2.5,
                solid_capstyle="round", zorder=6)
        ax.text((ov_lo + ov_hi) / 2, yb + 0.13, "All 10 classes overlap here",
                fontsize=9, fontweight="bold", color="0.25",
                ha="center", va="bottom", zorder=6)

        ax.set_yticks(pos)
        ax.set_yticklabels([])  # draw two-line labels by hand (name + CWE id)
        for y, nm, cwe_id in zip(pos, labels, order):
            ax.text(-0.015, y + 0.12, nm, transform=ax.get_yaxis_transform(),
                    fontsize=11, fontweight="bold", color=COLORS["text"], ha="right", va="center")
            ax.text(-0.015, y - 0.17, cwe_id, transform=ax.get_yaxis_transform(),
                    fontsize=7.5, color=COLORS["neutral"], ha="right", va="center")
        for y, nval in zip(pos, ns):
            ax.text(1.03, y, f"{nval:,} CVEs", transform=ax.get_yaxis_transform(),
                    fontsize=7.5, color=COLORS["neutral"], ha="left", va="center")

        ax.set_xlabel("CVSS v3 base score")
        ax.set_xlim(0, 10)
        ax.set_ylim(-0.7, len(order) + 0.25)
        ax.set_xticks(range(0, 11, 2))
        ax.spines["bottom"].set_bounds(0, 10)

        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="y", length=0)
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        ax.text(0.0, -0.205,
                f"Top {TOP_N} CWEs by volume, CVSS v3. Bar = middle 80% of scores; "
                "tick = median. Source: CVE List V5.",
                transform=ax.transAxes, fontsize=foot_size, color=COLORS["neutral"], va="top")

        top_m = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        t1_size = {"wide": 20, "square": 19, "portrait": 19}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.18, left=0.22, right=0.84)
        fig.text(0.05, 0.965, title1, fontsize=t1_size, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.918, title2, fontsize=11, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"cwe_spread_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

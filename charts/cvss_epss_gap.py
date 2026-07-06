#!/usr/bin/env python3
"""
Severe on paper, quiet in the wild — the CVSS vs EPSS gap.

Companion to the "vulnpocalypse that wasn't" framing. Every dot is one CVE,
placed by CVSS severity (x, impact-if-exploited) against EPSS (y, likelihood of
exploitation) and colored by severity. The point of the picture: even the
High/Critical (orange/red) dots hug the EPSS floor, nowhere near the
"exploitation likely" band. High counts of severe-looking bugs, almost none
actually likely to be exploited.

Scoped to Chrome by default (the batch that motivated the post). Set FOCUS = None
to plot the whole current-year population instead.
"""

from pathlib import Path

import matplotlib.pyplot as plt

from data import load_epss, load_nvd
from rolling_config import current_year, data_asof, ytd_mask
from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    SEVERITY_COLORS,
    figsize_for,
    stamp_and_save,
)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
FOCUS = "chrome"  # product filter; None = all current-year CVEs
DANGER = 0.5      # EPSS at/above which exploitation is "likely"


def render(nvd=None, ratios=DEFAULT_RATIOS):
    if nvd is None:
        nvd = load_nvd(with_epss=True)
    elif "epss" not in nvd.columns:
        nvd = nvd.merge(load_epss()[["cve_id", "epss", "percentile"]], on="cve_id", how="left")

    asof = data_asof(nvd)
    asof_str = asof.strftime("%b %d, %Y")
    cur = current_year(asof)
    model = load_epss()["model_version"].iloc[0] or "EPSS"

    df = nvd[ytd_mask(nvd, cur, asof)].copy()
    label = "CVEs"
    if FOCUS:
        df = df[df["product"] == FOCUS]
        label = f"{FOCUS.title()} CVEs"
    df = df.dropna(subset=["cvss_v3", "epss"])

    n = len(df)
    severe = int((df["cvss_v3"] >= 7.0).sum())
    max_epss = float(df["epss"].max())
    likely = int((df["epss"] >= DANGER).sum())

    title1 = f"{label}: severe on paper, quiet in the wild"
    title2 = f"{severe:,} of {n:,} rate High or Critical. Highest EPSS: just {max_epss:.2f}."
    sub = "Each dot is one CVE. Right = severe if exploited (CVSS). Up = likely to be exploited (EPSS)."

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        # Danger band: EPSS >= 0.5. Its emptiness is the message.
        ax.axhspan(DANGER, 1.0, color=COLORS["alert"], alpha=0.06)
        ax.axhline(DANGER, color=COLORS["alert"], lw=1, ls="--", alpha=0.6)
        ax.text(0.15, DANGER + 0.02, "exploitation likely (EPSS ≥ 0.5)",
                fontsize=10, color=COLORS["alert"], va="bottom", alpha=0.8)

        for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            s = df[df["severity"] == sev]
            if len(s):
                ax.scatter(s["cvss_v3"], s["epss"], s=16, alpha=0.4,
                           color=SEVERITY_COLORS[sev], edgecolors="none", label=sev.title())

        ax.set_xlim(0, 10)
        ax.set_ylim(0, 1)
        ax.set_xlabel("CVSS base score (impact if exploited)")
        ax.set_ylabel("EPSS (probability of exploitation)")
        ax.grid(True, axis="both", alpha=0.5)
        ax.legend(loc="upper right", fontsize=10, frameon=False, markerscale=1.6)

        ax.text(0.0, -0.16,
                f"{cur} year-to-date. Sources: NVD, EPSS {model}.",
                transform=ax.transAxes, fontsize=10, color=COLORS["neutral"], va="top")

        top = {"wide": 0.80, "square": 0.84, "portrait": 0.86}[ratio]
        fig.subplots_adjust(top=top, bottom=0.16, left=0.12, right=0.96)
        if ratio == "wide":
            fig.text(0.04, 0.95, title1, fontsize=20, fontweight="bold",
                     color=COLORS["text"], ha="left", va="top")
            fig.text(0.04, 0.885, f"{title2} {sub}", fontsize=11,
                     color=COLORS["secondary"], ha="left", va="top")
        else:
            fig.text(0.05, 0.965, title1, fontsize=18, fontweight="bold",
                     color=COLORS["text"], ha="left", va="top")
            fig.text(0.05, 0.920, title2, fontsize=11.5, fontweight="bold",
                     color=COLORS["alert"], ha="left", va="top")
            fig.text(0.05, 0.878, sub, fontsize=10.5, color=COLORS["secondary"],
                     ha="left", va="top")

        path = GRAPHS / f"cvss_epss_gap_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof_str)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

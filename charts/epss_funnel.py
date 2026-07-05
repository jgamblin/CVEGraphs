#!/usr/bin/env python3
"""
EPSS funnel — how few CVEs show any exploitation signal.

Pairs predicted exploitation (EPSS) with confirmed exploitation (CISA KEV) to
make the "volume up, exploitation rare" thesis visual in one image.

Honest framing: KEV-listed and EPSS >= 0.5 are DISTINCT signals, not nested
subsets (a CVE can be on KEV with a modest EPSS, or high-EPSS and not yet on
KEV). So this is not a literal nested funnel; it is several exploitation filters
applied to the same population, each still flagging a tiny share. Bars are
ordered by count so it reads as a narrowing, with a caption that says so.
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt

from data import load_epss, load_nvd
from rolling_config import current_year, data_asof, ytd_mask
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
PROCESSED = Path(__file__).resolve().parent.parent / "processed"


def _stages(nvd_epss, kev_ids, cur, asof):
    ytd = nvd_epss[ytd_mask(nvd_epss, cur, asof)]
    total = len(ytd)
    stages = [
        ("All published", total, COLORS["primary"]),
        ("EPSS ≥ 0.1", int((ytd["epss"] >= 0.1).sum()), COLORS["accent"]),
        ("On KEV", int(ytd["cve_id"].isin(kev_ids).sum()), COLORS["alert"]),
        ("EPSS ≥ 0.5", int((ytd["epss"] >= 0.5).sum()), COLORS["accent"]),
    ]
    # Order by count descending so it visually narrows.
    head, tail = stages[0], sorted(stages[1:], key=lambda s: s[1], reverse=True)
    return [head] + tail, total


def render(nvd=None, ratios=DEFAULT_RATIOS):
    if nvd is None:
        nvd = load_nvd(with_epss=True)
    elif "epss" not in nvd.columns:
        epss = load_epss()[["cve_id", "epss", "percentile"]]
        nvd = nvd.merge(epss, on="cve_id", how="left")

    asof = data_asof(nvd)
    asof_str = asof.strftime("%b %d, %Y")
    cur = current_year(asof)

    kev = json.load(open(PROCESSED / "kev_catalog.json"))
    kev_ids = {e["cveID"] for e in kev.get("vulnerabilities", [])}
    model = load_epss()["model_version"].iloc[0] or "EPSS"

    stages, total = _stages(nvd, kev_ids, cur, asof)
    title1 = f"How few of {cur}'s {total:,} CVEs"
    title2 = "show any exploitation signal"
    sub = "On KEV = confirmed exploited.  EPSS = model-predicted.  Both are rare."

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        labels = [s[0] for s in stages]
        counts = [s[1] for s in stages]
        colors = [s[2] for s in stages]
        y = list(range(len(stages)))[::-1]  # first stage on top

        ax.barh(y, counts, color=colors, edgecolor="white", height=0.72)
        for yi, c in zip(y, counts):
            pct = c / total * 100
            label = f"{c:,}  ({pct:.2f}%)" if c < total else f"{c:,}"
            ax.text(c + total * 0.015, yi, label, va="center", ha="left",
                    fontsize=15, fontweight="bold", color=COLORS["text"])

        ax.set_yticks(y)
        ax.set_yticklabels(labels, fontsize=14, fontweight="bold")
        ax.set_xlim(0, total * 1.18)
        ax.set_xticks([])
        ax.grid(False)
        for spine in ("bottom", "left"):
            ax.spines[spine].set_visible(False)

        ax.text(0.0, -0.15,
                f"{cur} YTD through {asof.strftime('%b %d')}. EPSS and KEV are "
                f"different lenses, not nested.\n"
                f"Sources: NVD, EPSS {model}, CISA KEV.",
                transform=ax.transAxes, fontsize=10.5, color=COLORS["neutral"], va="top")

        # Header: two title lines on tall ratios, one on wide.
        left = {"wide": 0.16, "square": 0.20, "portrait": 0.20}[ratio]
        top = {"wide": 0.78, "square": 0.82, "portrait": 0.85}[ratio]
        fig.subplots_adjust(top=top, bottom=0.19, left=left, right=0.95)
        if ratio == "wide":
            fig.text(0.04, 0.95, f"{title1} {title2}", fontsize=20,
                     fontweight="bold", color=COLORS["text"], ha="left", va="top")
            fig.text(0.04, 0.87, sub, fontsize=12.5, color=COLORS["secondary"],
                     ha="left", va="top")
        else:
            fig.text(0.05, 0.965, title1, fontsize=19, fontweight="bold",
                     color=COLORS["text"], ha="left", va="top")
            fig.text(0.05, 0.918, title2, fontsize=19, fontweight="bold",
                     color=COLORS["text"], ha="left", va="top")
            fig.text(0.05, 0.868, sub, fontsize=11.5, color=COLORS["secondary"],
                     ha="left", va="top")

        path = GRAPHS / f"epss_funnel_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof_str)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

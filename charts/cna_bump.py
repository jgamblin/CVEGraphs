#!/usr/bin/env python3
"""
The rise of GitHub and VulnCheck — a two-year CNA rank-flow (bump) chart.

Monthly rank among all CVE Numbering Authorities over the last 24 months. Every
issuer is a faint grey line (the churn); GitHub and VulnCheck are drawn bold and
labeled with how far they climbed. The visible window is the top ~10, so
VulnCheck rises into view from the bottom (it started outside the top 90).
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from data import load_cvelist
from rolling_config import data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
MONTHS = 24
VIS = 10  # visible rank window (top-10); climbers rise into it from below
HIGHLIGHT = {"GitHub_M": COLORS["alert"], "VulnCheck": COLORS["primary"]}
NICE = {"GitHub_M": "GitHub"}  # display names


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cve = load_cvelist()
    cpub = pd.to_datetime(cve["date_published"], utc=True, errors="coerce").dt.tz_convert(None)
    asof = data_asof(cve)
    m = cpub.dt.to_period("M")

    last_complete = asof.tz_convert(None).to_period("M") - 1
    periods = [last_complete - i for i in range(MONTHS)][::-1]

    # Rank every issuer within each month.
    per_month = {}
    for p in periods:
        vc = cve[m == p]["assigner_short_name"].replace("", "unknown").value_counts()
        per_month[p] = {name: rank + 1 for rank, name in enumerate(vc.index)}

    def ranks_for(name):
        return [per_month[p].get(name) for p in periods]

    # Every issuer that ever cracks the visible window = the grey mesh.
    mesh_names = set()
    for p in periods:
        mesh_names.update(n for n, r in per_month[p].items() if r <= VIS)
    mesh_names -= set(HIGHLIGHT)

    x = list(range(len(periods)))

    def journey(name):
        rs = [r for r in ranks_for(name) if r is not None]
        return max(rs), ranks_for(name)[-1]  # deepest seen, current

    gh_from, gh_now = journey("GitHub_M")
    vc_from, vc_now = journey("VulnCheck")

    title1 = "The rise of GitHub and VulnCheck"
    title2 = "Monthly rank among every CVE issuer, over the last two years."

    labels = [p.strftime("%b\n%y") if i % 3 == 0 else "" for i, p in enumerate(periods)]

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        # Grey mesh: faint, thin, no labels, clipped to the visible window.
        for name in mesh_names:
            rs = ranks_for(name)
            xs = [xi for xi, r in zip(x, rs) if r is not None and r <= VIS]
            ys = [r for r in rs if r is not None and r <= VIS]
            if len(ys) >= 2:
                ax.plot(xs, ys, "-", color=COLORS["light"], lw=1.0, alpha=0.45, zorder=1)

        # Highlighted climbers.
        for name, color in HIGHLIGHT.items():
            rs = ranks_for(name)
            xs = [xi for xi, r in zip(x, rs) if r is not None and r <= VIS]
            ys = [r for r in rs if r is not None and r <= VIS]
            ax.plot(xs, ys, "-o", color=color, lw=3.6, markersize=6,
                    markerfacecolor=color, markeredgecolor="white", zorder=5)
            frm, now = (gh_from, gh_now) if name == "GitHub_M" else (vc_from, vc_now)
            disp = NICE.get(name, name)
            ax.text(xs[-1] + 0.3, ys[-1], f"{disp}\n#{frm} → #{now}",
                    fontsize=11, fontweight="bold", color=color, va="center", ha="left", zorder=6)

            # If it climbed into view from below the visible window, mark the
            # off-chart origin so the "#130" in the label is anchored on-image.
            first_vis = next((i for i, r in enumerate(rs) if r is not None and r <= VIS), None)
            if first_vis is not None and frm > VIS and any(
                    rs[j] is None or rs[j] > VIS for j in range(first_vis)):
                ax.annotate(f"entered from #{frm}", xy=(x[first_vis], rs[first_vis]),
                            xytext=(x[first_vis] - 2.4, VIS + 0.35),
                            fontsize=9.5, fontweight="bold", fontstyle="italic",
                            color=color, alpha=0.9, ha="center", va="center", zorder=6,
                            arrowprops=dict(arrowstyle="-|>", color=color, alpha=0.6,
                                            lw=1.6, connectionstyle="arc3,rad=-0.25"))

        ax.set_ylim(VIS + 0.6, 0.4)  # rank 1 at top; below VIS is off-chart
        ax.set_yticks(range(1, VIS + 1))
        ax.set_yticklabels([f"#{i}" for i in range(1, VIS + 1)], fontsize=10)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=10)
        ax.set_xlim(-0.3, len(periods) + 2.4)
        for s in ("right", "top"):
            ax.spines[s].set_visible(False)
        ax.grid(True, axis="y", alpha=0.35)

        ax.text(0.0, -0.10,
                "Rank by monthly CVE count among 200+ CNAs. Grey = other issuers.\n"
                "Source: CVE List V5.",
                transform=ax.transAxes, fontsize=9.5, color=COLORS["neutral"],
                va="top", linespacing=1.5)

        top = {"wide": 0.82, "square": 0.86, "portrait": 0.88}[ratio]
        fig.subplots_adjust(top=top, bottom=0.17, left=0.09, right=0.86)
        fig.text(0.05, 0.965, title1, fontsize=20, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.918, title2, fontsize=11.5, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"cna_bump_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

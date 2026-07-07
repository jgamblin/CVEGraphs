#!/usr/bin/env python3
"""
The rise of GitHub and VulnCheck — a two-year CNA rank-flow (bump) chart.

Monthly rank among all CVE Numbering Authorities over the last 24 months. The
y-axis runs the full depth (past #130) so VulnCheck's entire climb from the
depths to the top 5 is visible as one dramatic sweep. GitHub and VulnCheck are
bold and labeled; a faint mesh of the top issuers gives context near the top.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from data import load_cvelist
from rolling_config import data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
MONTHS = 24
MESH_VIS = 15   # grey mesh lines shown only while an issuer sits in the top 15
HIGHLIGHT = {"GitHub_M": COLORS["alert"], "VulnCheck": COLORS["primary"]}
NICE = {"GitHub_M": "GitHub"}
YTICKS = [1, 25, 50, 75, 100, 130]


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cve = load_cvelist()
    cpub = pd.to_datetime(cve["date_published"], utc=True, errors="coerce").dt.tz_convert(None)
    asof = data_asof(cve)
    m = cpub.dt.to_period("M")

    last_complete = asof.tz_convert(None).to_period("M") - 1
    periods = [last_complete - i for i in range(MONTHS)][::-1]

    per_month = {}
    for p in periods:
        vc = cve[m == p]["assigner_short_name"].replace("", "unknown").value_counts()
        per_month[p] = {name: rank + 1 for rank, name in enumerate(vc.index)}

    def ranks_for(name):
        return [per_month[p].get(name) for p in periods]

    mesh_names = set()
    for p in periods:
        mesh_names.update(n for n, r in per_month[p].items() if r <= MESH_VIS)
    mesh_names -= set(HIGHLIGHT)

    x = list(range(len(periods)))

    def journey(name):
        rs = [r for r in ranks_for(name) if r is not None]
        return max(rs), ranks_for(name)[-1]

    gh_from, gh_now = journey("GitHub_M")
    vc_from, vc_now = journey("VulnCheck")
    y_bottom = max(gh_from, vc_from) + 6

    title1 = "The rise of GitHub and VulnCheck"
    title2 = "Monthly rank among every CVE issuer, over the last two years."
    labels = [p.strftime("%b\n%y") if i % 3 == 0 else "" for i, p in enumerate(periods)]

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        # Faint mesh: only where an issuer is inside the top 15 (stays near top).
        for name in mesh_names:
            rs = ranks_for(name)
            xs = [xi for xi, r in zip(x, rs) if r is not None and r <= MESH_VIS]
            ys = [r for r in rs if r is not None and r <= MESH_VIS]
            if len(ys) >= 2:
                ax.plot(xs, ys, "-", color=COLORS["light"], lw=1.0, alpha=0.4, zorder=1)

        # Highlighted climbers, full trajectory.
        for name, color in HIGHLIGHT.items():
            rs = ranks_for(name)
            pts = [(xi, r) for xi, r in zip(x, rs) if r is not None]
            xs = [p[0] for p in pts]
            ys = [p[1] for p in pts]
            ax.plot(xs, ys, "-o", color=color, lw=3.6, markersize=6,
                    markerfacecolor=color, markeredgecolor="white", zorder=5)
            frm, now = (gh_from, gh_now) if name == "GitHub_M" else (vc_from, vc_now)
            disp = NICE.get(name, name)
            if name == "GitHub_M":
                lx, ly, va = xs[-1] + 0.3, ys[-1], "center"      # label at the top end
            else:
                di = ys.index(max(ys))                            # label at the deepest point
                lx, ly, va = xs[di] + 0.5, max(ys), "center"
            ax.text(lx, ly, f"{disp}\n#{frm} → #{now}", fontsize=11, fontweight="bold",
                    color=color, va=va, ha="left", zorder=6)

        ax.set_ylim(y_bottom, 0.5)  # reversed => rank 1 at top, deep ranks at bottom
        ax.set_yticks(YTICKS)
        ax.set_yticklabels([f"#{t}" for t in YTICKS], fontsize=10)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize=10)
        ax.set_xlim(-0.3, len(periods) + 2.4)
        for s in ("right", "top"):
            ax.spines[s].set_visible(False)
        ax.grid(True, axis="y", alpha=0.35)

        ax.text(0.0, -0.10,
                "Rank by monthly CVE count among 200+ CNAs. Grey = other top issuers.\n"
                "Source: CVE List V5.",
                transform=ax.transAxes, fontsize=9.5, color=COLORS["neutral"],
                va="top", linespacing=1.5)

        top = {"wide": 0.82, "square": 0.86, "portrait": 0.88}[ratio]
        fig.subplots_adjust(top=top, bottom=0.17, left=0.10, right=0.86)
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

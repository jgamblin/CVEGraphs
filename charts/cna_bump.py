#!/usr/bin/env python3
"""
GitHub and MITRE trade places — a two-year CNA rank-flow (bump) chart.

Monthly rank among all CVE Numbering Authorities over the last 24 months. MITRE,
which runs the CVE program and was its #1 issuer for years, descends as GitHub
climbs past it. Those two are bold and labeled; every other issuer (VulnCheck,
Patchstack, Linux, VulDB, ...) is a faint grey line for context.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from data import load_cvelist
from rolling_config import data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
MONTHS = 24
VIS = 10  # visible rank window (top-10)
HIGHLIGHT = {"GitHub_M": COLORS["alert"], "mitre": COLORS["primary"]}
NICE = {"GitHub_M": "GitHub", "mitre": "MITRE"}


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

    def journey(name):
        rs = ranks_for(name)
        valid = [r for r in rs if r is not None]
        start = next(r for r in rs if r is not None)
        now = valid[-1]
        # Riser -> show its deepest; faller -> show its best. Both end at "now".
        frm = max(valid) if now <= start else min(valid)
        return frm, now

    mesh_names = set()
    for p in periods:
        mesh_names.update(n for n, r in per_month[p].items() if r <= VIS)
    mesh_names -= set(HIGHLIGHT)

    x = list(range(len(periods)))

    title1 = "GitHub and MITRE trade places"
    title2 = "GitHub passed MITRE, the organization that runs the CVE program."
    labels = [p.strftime("%b\n%y") if i % 3 == 0 else "" for i, p in enumerate(periods)]

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        # Grey mesh: every other top-10 issuer, faint and unlabeled.
        for name in mesh_names:
            rs = ranks_for(name)
            xs = [xi for xi, r in zip(x, rs) if r is not None and r <= VIS]
            ys = [r for r in rs if r is not None and r <= VIS]
            if len(ys) >= 2:
                ax.plot(xs, ys, "-", color=COLORS["light"], lw=1.0, alpha=0.45, zorder=1)

        # The two protagonists.
        for name, color in HIGHLIGHT.items():
            rs = ranks_for(name)
            xs = [xi for xi, r in zip(x, rs) if r is not None and r <= VIS]
            ys = [r for r in rs if r is not None and r <= VIS]
            ax.plot(xs, ys, "-o", color=color, lw=3.6, markersize=6,
                    markerfacecolor=color, markeredgecolor="white", zorder=5)
            frm, now = journey(name)
            ax.text(xs[-1] + 0.3, ys[-1], f"{NICE[name]}\n#{frm} → #{now}",
                    fontsize=11, fontweight="bold", color=color, va="center", ha="left", zorder=6)

        ax.set_ylim(VIS + 0.6, 0.4)  # rank 1 at top
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

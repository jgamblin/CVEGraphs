#!/usr/bin/env python3
"""
The anatomy of software weaknesses — hierarchical circle packing of CWEs.

Every CWE rolls up to one of MITRE's 10 top-level Pillars (CWE-1000 Research
view). Pillars are the big outlined circles; individual CWEs nest inside, sized
by 2026 CVE count and colored by average CVSS. So you can see both the shape of
the taxonomy and, within it, which weaknesses are common vs severe.

Pillar mapping comes from processed/cwe_pillars.json (built by refresh_data.py
from cwe.mitre.org), so the grouping is authoritative, not hand-curated.
"""

import json
import math
from collections import defaultdict
from pathlib import Path

import circlify
import matplotlib.pyplot as plt
from matplotlib.cm import ScalarMappable
from matplotlib.colors import LinearSegmentedColormap, Normalize

from data import load_nvd
from rolling_config import current_year, data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
PROCESSED = Path(__file__).resolve().parent.parent / "processed"
TOP_N = 22
DROP = {"NVD-CWE-noinfo", "NVD-CWE-Other", None}

# Lightly shortened, faithful pillar labels (full names live in the caption).
PILLAR_SHORT = {
    "CWE-707": "Improper Neutralization", "CWE-664": "Improper Resource Control",
    "CWE-284": "Improper Access Control", "CWE-693": "Protection Mechanism Failure",
    "CWE-710": "Improper Coding Practice", "CWE-682": "Incorrect Calculation",
    "CWE-691": "Insufficient Control Flow", "CWE-697": "Incorrect Comparison",
    "CWE-703": "Improper Exception Handling", "CWE-435": "Improper Entity Interaction",
}
CWE_NAMES = {
    "CWE-79": "XSS", "CWE-89": "SQLi", "CWE-787": "OOB Write", "CWE-125": "OOB Read",
    "CWE-20": "Input Valid.", "CWE-22": "Path Trav.", "CWE-352": "CSRF",
    "CWE-78": "OS Cmd Inj", "CWE-416": "Use-After-Free", "CWE-476": "NULL Deref",
    "CWE-119": "Buffer Err", "CWE-200": "Info Leak", "CWE-400": "Resource Exh",
    "CWE-434": "File Upload", "CWE-863": "Bad Authz", "CWE-918": "SSRF",
    "CWE-94": "Code Inj", "CWE-502": "Deserialize", "CWE-287": "Improper Auth",
    "CWE-77": "Cmd Inj", "CWE-862": "Missing Authz", "CWE-798": "Hardcoded Creds",
    "CWE-306": "Missing Auth", "CWE-611": "XXE", "CWE-74": "Injection",
    "CWE-284": "Access Ctrl", "CWE-639": "Authz Bypass", "CWE-122": "Heap Overflow",
    "CWE-843": "Type Confusion", "CWE-770": "No Rate Limit", "CWE-98": "PHP File Incl",
    "CWE-121": "Stack Overflow", "CWE-269": "Priv Mgmt", "CWE-276": "Default Perms",
    "CWE-120": "Buffer Copy",
}


def render(nvd=None, ratios=DEFAULT_RATIOS):
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)
    cur = current_year(asof)

    pill = json.load(open(PROCESSED / "cwe_pillars.json"))
    cwe2pillar = pill["cwe_to_pillar"]

    df = nvd[(nvd["year"] == cur) & nvd["cwe"].notna() & ~nvd["cwe"].isin(DROP)]
    g = df.groupby("cwe").agg(n=("cve_id", "size"), cvss=("cvss_v3", "mean"))
    g = g.sort_values("n", ascending=False).head(TOP_N)
    cvss_map = g["cvss"].to_dict()

    groups = defaultdict(list)
    for cwe, row in g.iterrows():
        groups[cwe2pillar.get(cwe, "CWE-710")].append((cwe, int(row.n)))

    data = [{"id": pil, "datum": sum(n for _, n in items),
             "children": [{"id": cwe, "datum": n} for cwe, n in items]}
            for pil, items in groups.items()]
    circles = circlify.circlify(data, show_enclosure=False,
                                target_enclosure=circlify.Circle(x=0, y=0, r=1))

    vmin, vmax = float(g["cvss"].min()), float(g["cvss"].max())
    # On-brand blue/grey ramp: light slate -> navy, darker = more severe.
    cmap = LinearSegmentedColormap.from_list("sev", ["#e9eef4", "#6f93b8", COLORS["primary"]])
    norm = Normalize(vmin=vmin, vmax=vmax)

    title1 = f"The anatomy of software weaknesses in {cur}"
    title2 = "CWEs grouped by MITRE pillar.  Size = CVE count.  Color = average CVSS."

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        ax.set_aspect("equal")
        ax.axis("off")
        ax.set_xlim(-1.12, 1.12)
        ax.set_ylim(-1.12, 1.20)

        # Pillars (level 1): faint fill + outline + a label on the top rim.
        for c in circles:
            if c.level != 1:
                continue
            ax.add_patch(plt.Circle((c.x, c.y), c.r, facecolor="white",
                                    edgecolor=COLORS["secondary"], linewidth=1.3, zorder=1))
            if c.r >= 0.15:
                name = PILLAR_SHORT.get(c.ex["id"], c.ex["id"])
                # Label above pillars in the top half, below those in the bottom
                # half. Keeps labels in open vertical whitespace, never in the
                # crowded center where the circles meet, and never at the edges.
                pad = 0.04
                if c.y >= 0:
                    ly, va = c.y + c.r + pad, "bottom"
                else:
                    ly, va = c.y - c.r - pad, "top"
                ax.text(c.x, ly, name, ha="center", va=va,
                        fontsize=min(11.5, c.r * 24), fontweight="bold",
                        color=COLORS["text"], zorder=7,
                        bbox=dict(boxstyle="round,pad=0.28", fc="white", ec=COLORS["light"], alpha=0.92))

        # CWE leaves (level 2): colored by severity.
        for c in circles:
            if c.level != 2:
                continue
            cwe = c.ex["id"]
            avg = float(cvss_map[cwe])
            ax.add_patch(plt.Circle((c.x, c.y), c.r, facecolor=cmap(norm(avg)),
                                    edgecolor=COLORS["light"], linewidth=1.0, zorder=2))
            name = CWE_NAMES.get(cwe, cwe.replace("CWE-", "CWE "))
            fs = min(13, c.r * 600 / max(len(name), 3))
            if fs >= 7:
                txt = COLORS["text"] if avg < (vmin + vmax) / 2 else "white"
                ax.text(c.x, c.y, name, ha="center", va="center", fontsize=fs,
                        fontweight="bold", color=txt, zorder=3)

        cax = fig.add_axes([0.30, 0.125, 0.40, 0.02])
        cb = fig.colorbar(ScalarMappable(norm=norm, cmap=cmap), cax=cax, orientation="horizontal")
        cb.set_label("Average CVSS  (lighter = milder, darker = more severe)",
                     fontsize=9, color=COLORS["secondary"], labelpad=3)
        cb.ax.tick_params(labelsize=8, length=0)
        cb.outline.set_visible(False)
        fig.text(0.5, 0.055,
                 f"Top {TOP_N} CWEs of {cur}, grouped by MITRE CWE-1000 pillar. "
                 f"Sources: NVD, cwe.mitre.org.",
                 fontsize=9, color=COLORS["neutral"], ha="center", va="bottom")

        top = {"wide": 0.80, "square": 0.85, "portrait": 0.80}[ratio]
        fig.subplots_adjust(top=top, bottom=0.19, left=0.03, right=0.97)
        fig.text(0.05, 0.965, title1, fontsize=19, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.918, title2, fontsize=11.5, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"cwe_circles_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

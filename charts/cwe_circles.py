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


def _units(name):
    """Break a label into wrap units + the separator to rejoin within a line."""
    if " " in name:
        return name.split(" "), " "
    if "-" in name:                       # e.g. Use-After-Free -> Use- / After- / Free
        parts = name.split("-")
        return [p + "-" for p in parts[:-1]] + [parts[-1]], ""
    return [name], ""


def _candidates(name):
    """Candidate line-wraps (1, 2, or 3 lines), each a list of line strings."""
    units, sep = _units(name)
    n = len(units)
    cands = [[name]]
    if n >= 2:
        best = min(([sep.join(units[:i]), sep.join(units[i:])] for i in range(1, n)),
                   key=lambda ls: max(len(x) for x in ls))
        cands.append(best)
    if n >= 3:
        best = min(([sep.join(units[:i]), sep.join(units[i:j]), sep.join(units[j:])]
                    for i in range(1, n - 1) for j in range(i + 1, n)),
                   key=lambda ls: max(len(x) for x in ls))
        cands.append(best)
    return cands


def _fit_label(ax, rend, name, avail_px):
    """Best (text, fontsize) that fits an inscribed square of side avail_px."""
    best_fs, best_txt = -1, None
    for lines in _candidates(name):
        s = "\n".join(lines)
        probe = ax.text(0, 0, s, fontsize=10, fontweight="bold",
                        ha="center", va="center")
        bb = probe.get_window_extent(rend)
        probe.remove()
        fs = min(10 * min(avail_px / bb.width, avail_px / bb.height), 13)
        if fs > best_fs:
            best_fs, best_txt = fs, s
    return best_txt, best_fs


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

        # Pillars (level 1): faint fill + outline.
        pillars = [c for c in circles if c.level == 1]
        for c in pillars:
            ax.add_patch(plt.Circle((c.x, c.y), c.r, facecolor="white",
                                    edgecolor=COLORS["secondary"], linewidth=1.3, zorder=1))

        # Labels above top-half pillars and below bottom-half ones, but aligned
        # to a SHARED baseline per side so all bottom labels sit on one line.
        pad = 0.05
        labeled = [c for c in pillars if c.r >= 0.15]
        bottoms = [c for c in labeled if c.y < 0]
        tops = [c for c in labeled if c.y >= 0]
        bot_y = min((c.y - c.r for c in bottoms), default=0) - pad
        top_y = max((c.y + c.r for c in tops), default=0) + pad
        for c in labeled:
            name = PILLAR_SHORT.get(c.ex["id"], c.ex["id"])
            ly, va = (top_y, "bottom") if c.y >= 0 else (bot_y, "top")
            ax.text(c.x, ly, name, ha="center", va=va,
                    fontsize=min(11.5, c.r * 24), fontweight="bold",
                    color=COLORS["text"], zorder=7,
                    bbox=dict(boxstyle="round,pad=0.28", fc="white", ec=COLORS["light"], alpha=0.92))

        # CWE leaves (level 2): colored circles first, labels measured after.
        leaves = [c for c in circles if c.level == 2]
        for c in leaves:
            ax.add_patch(plt.Circle((c.x, c.y), c.r, facecolor=cmap(norm(cvss_map[c.ex["id"]])),
                                    edgecolor=COLORS["light"], linewidth=1.0, zorder=2))

        # Measure text against actual pixels so labels wrap to stay inside the
        # circle (two lines if needed) and never overflow.
        fig.canvas.draw()
        rend = fig.canvas.get_renderer()
        o = ax.transData.transform((0, 0))
        px_per_unit = abs(ax.transData.transform((1, 0))[0] - o[0])
        for c in leaves:
            avg = float(cvss_map[c.ex["id"]])
            name = CWE_NAMES.get(c.ex["id"], c.ex["id"].replace("CWE-", "CWE "))
            avail = 2 * c.r * px_per_unit * 0.72  # side of inscribed square
            txt, fs = _fit_label(ax, rend, name, avail)
            if fs >= 6:
                color = COLORS["text"] if avg < (vmin + vmax) / 2 else "white"
                ax.text(c.x, c.y, txt, ha="center", va="center", fontsize=fs,
                        fontweight="bold", color=color, zorder=3, linespacing=0.95)

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

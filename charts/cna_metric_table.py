#!/usr/bin/env python3
"""
The underlying CVSS v3 metrics behind the XSS scoring spread, by CNA.

A table (heatmap) companion to `cna_spread`: for each high-volume CNA, the share
of its XSS CVEs that set the four threat-model metrics that move a CVSS v3 base
score. Answers "compare the underlying metrics" directly. The stark column is
Confidentiality: VulDB scores it None on ~100% of its XSS (a self-contained
integrity bug) while everyone else scores data exposure; privileges and user
interaction genuinely vary too (real attack-surface differences).

Vectors are read from CVE List V5 (the CNA's own vector), sampled per CNA for speed.
"""

from pathlib import Path

import glob
import json

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.patches import Rectangle

from data import load_cvelist, load_nvd
from rolling_config import data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
CVELIST = Path(__file__).resolve().parent.parent / "data" / "cvelistV5" / "cves"

CWE = "CWE-79"
MIN_N = 100
SAMPLE = 600  # vectors sampled per CNA (parsing raw JSON is the slow part)

# Light-grey to deep-navy ramp for cell shading (magnitude, not severity).
CELL_CMAP = LinearSegmentedColormap.from_list("cell", [COLORS["grid"], COLORS["accent"], COLORS["primary"]])

COLUMNS = [
    ("Avg CVSS", "avg", 10.0),
    ("Conf = None", "confN", 100.0),
    ("Scope = Changed", "scopeC", 100.0),
    ("Needs privileges", "priv", 100.0),
    ("Needs interaction", "ui", 100.0),
]


def _vector(cid):
    p = cid.split("-")
    bucket = (p[2][:-3] or "0") + "xxx"
    hits = glob.glob(str(CVELIST / p[1] / bucket / f"{cid}.json"))
    if not hits:
        return None
    try:
        j = json.load(open(hits[0]))
    except Exception:
        return None
    for m in j.get("containers", {}).get("cna", {}).get("metrics", []):
        for k in ("cvssV3_1", "cvssV3_0"):
            if k in m and m[k].get("vectorString"):
                return dict(t.split(":") for t in m[k]["vectorString"].split("/")[1:] if ":" in t)
    return None


def render(nvd=None, ratios=DEFAULT_RATIOS, cwe=CWE):
    cl = load_cvelist()
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(nvd)

    x = cl[(cl["cwe"] == cwe) & cl["cvss_v3"].notna()]
    counts = x["assigner_short_name"].value_counts()
    keep = list(counts[counts >= MIN_N].index)

    rows = []
    for cna in keep:
        ids = list(x[x["assigner_short_name"] == cna]["cve_id"])
        if len(ids) > SAMPLE:
            ids = ids[:: max(1, len(ids) // SAMPLE)][:SAMPLE]
        cN = sC = priv = ui = n = 0
        for cid in ids:
            t = _vector(cid)
            if not t or "S" not in t:
                continue
            n += 1
            cN += t.get("C") == "N"
            sC += t.get("S") == "C"
            priv += t.get("PR") in ("L", "H")
            ui += t.get("UI") == "R"
        if not n:
            continue
        rows.append({
            "cna": cna, "avg": float(x[x["assigner_short_name"] == cna]["cvss_v3"].mean()),
            "confN": 100 * cN / n, "scopeC": 100 * sC / n, "priv": 100 * priv / n, "ui": 100 * ui / n,
        })
    rows.sort(key=lambda r: r["avg"], reverse=True)  # highest average on top

    title1 = "Same bug, different threat model: the XSS metrics by scorer"
    title2 = ("Share of each CNA's XSS that sets the CVSS v3 metrics that move the score. "
              "The big split is Confidentiality: does the bug leak data?")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")

        n_rows = len(rows) + 1  # + header
        rh = 1.0 / n_rows
        label_w = 0.18
        col_w = (1.0 - label_w) / len(COLUMNS)

        def col_x(i):
            return label_w + i * col_w

        def yrow(r):  # r=0 header, 1..N data; top-down
            return 1.0 - (r + 1) * rh

        # Header row
        ax.text(0.0, yrow(0) + rh / 2, "CNA", fontsize=10.5, fontweight="bold",
                color=COLORS["text"], ha="left", va="center")
        for i, (head, _, _) in enumerate(COLUMNS):
            ax.text(col_x(i) + col_w / 2, yrow(0) + rh / 2, head, fontsize=9.5,
                    fontweight="bold", color=COLORS["text"], ha="center", va="center")

        # Data rows
        for r, row in enumerate(rows, start=1):
            y = yrow(r)
            is_vuldb = row["cna"] == "VulDB"
            ax.text(0.0, y + rh / 2, row["cna"], fontsize=10,
                    fontweight="bold" if is_vuldb else "normal",
                    color=COLORS["alert"] if is_vuldb else COLORS["text"],
                    ha="left", va="center")
            for i, (_, key, scale) in enumerate(COLUMNS):
                val = row[key]
                frac = min(val / scale, 1.0)
                cell = CELL_CMAP(frac)
                ax.add_patch(Rectangle((col_x(i) + 0.004, y + rh * 0.12),
                                       col_w - 0.008, rh * 0.76,
                                       facecolor=cell, edgecolor="white", linewidth=1.0))
                txt = f"{val:.1f}" if key == "avg" else f"{val:.0f}%"
                ax.text(col_x(i) + col_w / 2, y + rh / 2, txt, fontsize=9.5,
                        fontweight="bold",
                        color="white" if frac > 0.55 else COLORS["text"],
                        ha="center", va="center")

        ax.text(0.0, -0.06 if ratio != "portrait" else -0.04,
                f"CVSS v3 vector metrics for {cwe} (XSS) by scoring CNA, {MIN_N}+ CVEs each. "
                "Source: CVE List V5.",
                transform=ax.transAxes, fontsize=8.5, color=COLORS["neutral"], va="top")

        top = {"wide": 0.80, "square": 0.84, "portrait": 0.86}[ratio]
        fig.subplots_adjust(top=top, bottom=0.10, left=0.06, right=0.97)
        fig.text(0.05, 0.95, title1, fontsize={"wide": 18, "square": 16, "portrait": 16}[ratio],
                 fontweight="bold", color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.895, title2, fontsize=10.5, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top", wrap=True)

        path = GRAPHS / f"cna_metric_table_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

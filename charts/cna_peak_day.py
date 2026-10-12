#!/usr/bin/env python3
"""
Each CNA's biggest single publishing day, ranked.

One bar per CNA: the most CVEs that CNA has ever published on one calendar day
(CVE.org publication date, UTC), 2017 to date. Unlike ``cna_burst``, which ranks
CNA-days and so lists Linux or Oracle several times, this is a "personal best"
table: every CNA appears once, at its record. Oracle and Microsoft are
highlighted; ``stats()`` prints their rank and the size of the gap to the bars
around them, for the caption copy.

Data: CVE List V5 (assigner short name + publication date), non-rejected,
de-duplicated by CVE id.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter
import pandas as pd

from data import load_cvelist, load_nvd
from rolling_config import data_asof
from style_social import (COLORS, DEFAULT_RATIOS, draw_header, figsize_for,
                          stamp_and_save)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

START_YEAR = 2017  # "modern era"; earlier bursts are MITRE sole-assigner backfill
TOP_N = 15
HIGHLIGHT = ("oracle", "microsoft")
# Same pale fill as cna_burst: clears WCAG 3:1 on white while staying distinct
# from the navy highlight.
OTHER_FILL = "#7b91b4"

CNA_NAMES = {
    "zdi": "ZDI", "Linux": "Linux Kernel", "microsoft": "Microsoft", "Chrome": "Chrome",
    "mitre": "MITRE", "mozilla": "Mozilla", "Patchstack": "Patchstack",
    "@huntr_ai": "huntr", "GitHub_M": "GitHub", "oracle": "Oracle",
    "redhat": "Red Hat", "adobe": "Adobe", "apple": "Apple", "cisco": "Cisco",
    "Wordfence": "Wordfence", "VulDB": "VulDB", "qualcomm": "Qualcomm",
    "Google": "Google", "ibm": "IBM", "sap": "SAP", "siemens": "Siemens",
    "dell": "Dell", "nvidia": "NVIDIA", "intel": "Intel", "samsung.tv_appliance":
    "Samsung", "Samsung Mobile": "Samsung Mobile", "jenkins": "Jenkins",
    "Go": "Go", "debian": "Debian", "certcc": "CERT/CC", "hp": "HP",
    "Fluid Attacks": "Fluid Attacks", "TALOS": "Talos", "VulnCheck": "VulnCheck",
    "MediaTek": "MediaTek", "huawei": "Huawei", "JFROG": "JFrog",
    "google_android": "Android", "WPScan": "WPScan", "hackerone": "HackerOne",
}


def _table(cl):
    """One row per CNA: its record single-day count and the day it happened."""
    pub = pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
    cl = cl.assign(pub=pub).dropna(subset=["pub"])
    cl = cl[cl["pub"].dt.year >= START_YEAR]
    cl["day"] = cl["pub"].dt.normalize()
    days = cl.groupby(["assigner_short_name", "day"]).size().reset_index(name="n")
    # Ties on n resolve to the EARLIEST day (first time the CNA hit its record).
    days = days.sort_values(["n", "day"], ascending=[False, True])
    peak = days.drop_duplicates("assigner_short_name").reset_index(drop=True)
    peak["rank"] = np.arange(1, len(peak) + 1)
    return peak


def _follow_on(cl, key, peak, since_days=90, min_n=300):
    """Later big days by ``key`` after its record, for the under-bar annotation.

    Returns (record_day, [(day, n), ...]) for days of ``min_n``+ CVEs after the record
    and within ``since_days`` of the data as-of; empty list if there are none.
    """
    row = peak[peak["assigner_short_name"] == key]
    if row.empty:
        return None, []
    rec_day = row.iloc[0]["day"]
    pub = pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
    sub = cl.assign(pub=pub).dropna(subset=["pub"])
    sub = sub[sub["assigner_short_name"] == key]
    days = sub.groupby(sub["pub"].dt.normalize()).size()
    cutoff = data_asof(cl) - pd.Timedelta(days=since_days)
    later = days[(days.index > rec_day) & (days.index >= cutoff) & (days >= min_n)]
    return rec_day, [(d, int(n)) for d, n in later.sort_index().items()]


def stats():
    """Rank and neighbours for the highlighted CNAs, for the caption copy."""
    cl = load_cvelist().drop_duplicates("cve_id")
    peak = _table(cl)
    out = {"asof": data_asof(cl).strftime("%Y-%m-%d"), "cnas_ranked": len(peak)}
    for key in HIGHLIGHT:
        row = peak[peak["assigner_short_name"] == key]
        if row.empty:
            out[key] = None
            continue
        r = row.iloc[0]
        above = peak[peak["rank"] == r["rank"] - 1]
        below = peak[peak["rank"] == r["rank"] + 1]
        out[key] = {
            "rank": int(r["rank"]), "n": int(r["n"]),
            "day": r["day"].strftime("%Y-%m-%d"),
            "above": None if above.empty else (above.iloc[0]["assigner_short_name"],
                                                int(above.iloc[0]["n"])),
            "below": None if below.empty else (below.iloc[0]["assigner_short_name"],
                                                int(below.iloc[0]["n"])),
        }
    top = peak.head(TOP_N)
    out["top"] = [(a, int(n), d.strftime("%Y-%m-%d"))
                  for a, n, d in zip(top["assigner_short_name"], top["n"], top["day"])]
    out["top_set_in_2026"] = int((top["day"].dt.year == 2026).sum())
    return out


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist().drop_duplicates("cve_id")
    if nvd is None:
        nvd = load_nvd()
    asof = data_asof(cl)

    full = _table(cl)
    peak = full.head(TOP_N).iloc[::-1]  # ascending so #1 lands on top
    follow = _follow_on(cl, "oracle", full)

    counts = peak["n"].tolist()
    keys = peak["assigner_short_name"].tolist()
    cnas = [CNA_NAMES.get(a, a) for a in keys]
    dates = list(peak["day"])
    ranks = peak["rank"].tolist()
    hi = [k in HIGHLIGHT for k in keys]

    title1 = "Each CNA's Biggest Single Publishing Day"
    title2 = (f"Top {TOP_N} CNAs by the most CVEs published on one calendar day, "
              "2017 to date.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        y = np.arange(len(counts))

        colors = [COLORS["primary"] if h else OTHER_FILL for h in hi]
        ax.barh(y, counts, color=colors, edgecolor=COLORS["neutral"], linewidth=0.8,
                zorder=3)

        xmax = max(counts)
        # Bar-end label: bold count, then the record date in muted ink. Both are
        # anchored to the bar end in POINTS (not data units), and the date sits at
        # the count's measured width plus a fixed gap, so the spacing is identical
        # in every ratio and survives the later subplots_adjust.
        count_texts = []
        for yi, c, h in zip(y, counts, hi):
            count_texts.append(ax.annotate(
                f"{c:,}", xy=(c, yi), xytext=(5, 0), textcoords="offset points",
                va="center", ha="left", fontsize=11, fontweight="bold",
                color=COLORS["primary"] if h else COLORS["text"]))
        # An annotation anchored in data coords reports a 1px box until the figure
        # has been drawn once, so draw, then measure, then place the dates.
        fig.canvas.draw()
        for t, yi, c, d in zip(count_texts, y, counts, dates):
            w_pts = t.get_window_extent().width / fig.dpi * 72
            ax.annotate(d.strftime("%b %-d, %Y"), xy=(c, yi), xytext=(5 + w_pts + 6, 0),
                        textcoords="offset points", va="center", ha="left",
                        fontsize=9, color=COLORS["secondary"])

        # Left labels: "#rank  CNA", one line per bar.
        for yi, r, name, h in zip(y, ranks, cnas, hi):
            ax.text(-0.015, yi, f"#{r}  {name}", transform=ax.get_yaxis_transform(),
                    ha="right", va="center", fontsize=11, fontweight="bold",
                    color=COLORS["primary"] if h else COLORS["text"])

        # Inside the record bar, right-aligned in white: the batches that followed it.
        rec_day, later = follow
        if later and "oracle" in keys:
            i = keys.index("oracle")
            txt = "then " + " and ".join(f"{n:,} on {d.strftime('%b %-d')}" for d, n in later)
            ax.annotate(txt, xy=(counts[i], y[i]), xytext=(-8, 0), textcoords="offset points",
                        va="center", ha="right", fontsize=9, color="white")

        ax.set_yticks([])
        ax.set_ylim(-0.6, len(counts) - 0.4)
        xtop = (int(xmax // 200) + 1) * 200
        ax.set_xlim(0, xtop * 1.12)  # room for the count + date label
        ax.set_xticks(np.arange(0, xtop + 1, 200))
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
        ax.tick_params(axis="x", labelsize=10, colors=COLORS["secondary"], length=0)
        ax.tick_params(axis="y", length=0)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.set_axisbelow(True)

        # House rule: one footnote, one line, source and as-of date only.
        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05,
                 f"Source: CVE List V5, non-rejected CVEs, data as of "
                 f"{asof.strftime('%b %-d, %Y')}.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom")

        top_m = {"wide": 0.77, "square": 0.805, "portrait": 0.84}[ratio]
        left_m = {"wide": 0.17, "square": 0.22, "portrait": 0.24}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.12, left=left_m, right=0.96)
        t1 = {"wide": 23, "square": 20, "portrait": 19}[ratio]
        draw_header(fig, title1, title2, ratio=ratio, eyebrow_suffix="CNA VOLUME",
                    title_size=t1)

        path = GRAPHS / f"cna_peak_day_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    import pprint
    pprint.pprint(stats(), sort_dicts=False)
    for p in render():
        print(p)

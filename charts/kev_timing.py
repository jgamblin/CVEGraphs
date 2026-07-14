#!/usr/bin/env python3
"""
How old a vulnerability is when CISA adds it to the KEV list.

Gap = KEV dateAdded minus the CVE.org record's publication date, compared on
CALENDAR dates (dateAdded is date-only; datePublished carries a time, so a raw
subtraction floors same-day-published-later gaps to -1 and invents a phantom
"before publication" bucket). Restricted to KEV entries CISA added so far this
calendar year, so it reflects how CISA flags exploitation now, not the 2021
bulk-load of old CVEs when the program started.

The story: most flagged CVEs are recent (over half within a month, ~three
quarters within a year), but a stubborn multi-year tail (~16% over three years,
some ~17 years old) shows old vulnerabilities coming back.

Data: processed/kev_catalog.json (CISA KEV dateAdded) + CVE List datePublished.
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from data import load_cvelist
from rolling_config import today_utc
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
PROCESSED = Path(__file__).resolve().parent.parent / "processed"


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cl = load_cvelist()
    pub = pd.to_datetime(cl["date_published"], utc=True, errors="coerce")
    pubs = (cl.assign(pub=pub).dropna(subset=["pub"]).drop_duplicates("cve_id")
              .set_index("cve_id")["pub"])

    kev = json.load(open(PROCESSED / "kev_catalog.json"))
    stamp = today_utc()  # house rule: stamp the post/render date, not the data date
    k = pd.DataFrame([(v.get("cveID"), v.get("dateAdded")) for v in kev["vulnerabilities"]],
                     columns=["cve_id", "dateAdded"])
    k["added"] = pd.to_datetime(k["dateAdded"], utc=True, errors="coerce")
    k["pub"] = k["cve_id"].map(pubs)
    k = k.dropna(subset=["added", "pub"])
    # Compare CALENDAR dates: dateAdded is date-only (midnight), datePublished carries a
    # time, so a raw subtraction floors a same-day-published-later gap to -1 and invents a
    # phantom "before publication" bucket. Normalize both to dates first.
    k["gap"] = (k["added"].dt.normalize() - k["pub"].dt.normalize()).dt.days

    year = int(k["added"].max().year)
    recent = k[k["added"] >= pd.Timestamp(year, 1, 1, tz="UTC")]  # added so far this year
    n = len(recent)
    g = recent["gap"]

    # Calendar-day age buckets. A "Before Publication" bucket (KEV listed a full calendar
    # day before the CVE.org record) is included only if it is non-empty; it is 0 for 2026.
    buckets = []
    if (g <= -1).any():
        buckets.append(("Before\nPublication", g <= -1, COLORS["accent"]))
    buckets += [
        ("Same Day", g == 0, COLORS["accent"]),
        ("1 to 7\nDays", (g >= 1) & (g <= 7), COLORS["accent"]),
        ("8 to 30\nDays", (g > 7) & (g <= 30), COLORS["accent"]),
        ("1 to 12\nMonths", (g > 30) & (g <= 365), COLORS["accent"]),
        ("1 to 3\nYears", (g > 365) & (g <= 1095), COLORS["accent"]),
        ("Over 3\nYears", g > 1095, COLORS["primary"]),  # accent the aged tail (the story)
    ]
    # Every CVE lands in exactly one bucket, so display should total 100.
    exact = [100.0 * m.mean() for _, m, _ in buckets]
    floors = [int(v) for v in exact]
    order = sorted(range(len(exact)), key=lambda i: exact[i] - floors[i], reverse=True)
    for i in range(100 - sum(floors)):
        floors[order[i]] += 1
    pcts = floors

    title1 = "How Old CVEs Are When CISA Adds Them to KEV"
    title2 = (f"Days from a CVE.org record's publication to its CISA KEV (Known Exploited "
              f"Vulnerabilities) listing, for the {n} CVEs added in {year}.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        x = np.arange(len(buckets))

        for xi, (label, _, color), p in zip(x, buckets, pcts):
            ax.bar(xi, p, width=0.72, color=color, edgecolor="white", linewidth=1.0, zorder=3)
            ax.text(xi, p + 0.6, f"{p:.0f}%", ha="center", va="bottom", fontsize=12,
                    fontweight="bold", color=COLORS["text"])

        ax.set_xticks(x)
        ax.set_xticklabels([b[0] for b in buckets], fontsize=10.5, color=COLORS["text"])
        ax.set_ylim(0, max(pcts) * 1.22)
        ax.set_yticks([])
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])
        ax.tick_params(axis="both", length=0)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.055,
                 "Gap = KEV add date minus the CVE.org record's publication date (calendar "
                 "dates). Source: CISA KEV + CVE List V5.",
                 fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom")

        top_m = {"wide": 0.82, "square": 0.85, "portrait": 0.87}[ratio]
        t1 = {"wide": 20, "square": 17, "portrait": 17}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.20, left=0.06, right=0.96)
        fig.text(0.05, 0.965, title1, fontsize=t1, fontweight="bold",
                 color=COLORS["text"], ha="left", va="top")
        fig.text(0.05, 0.915, title2, fontsize=10.5, fontweight="bold",
                 color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"kev_timing_{ratio}_{stamp.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, stamp.strftime("%b %d, %Y"))
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

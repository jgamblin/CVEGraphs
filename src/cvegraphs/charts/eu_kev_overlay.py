#!/usr/bin/env python3
"""
EU KEV over CISA KEV: cumulative CVEs on each exploited list, overlaid.

ENISA's EU Vulnerability Database (EUVD, live since May 13 2025) flags "exploited"
vulnerabilities, a list people call the EU KEV. Overlaid on CISA's KEV catalog the
two cumulative lines are one line: every CISA KEV CVE is on the EU list, and on
all but a handful the EU's ``exploitedSince`` date is CISA's ``dateAdded``, back to
KEV's Nov 2021 launch (years before EUVD existed). The EU's own contribution is the
dozen CVEs CISA has not added, plus a few it listed days before CISA did.

The EU line is drawn as a thick pale band with the CISA line thin and dark inside
it, so the overlap reads as "both are there" rather than a missing series.

Data: processed/euvd_kev.json (cvegraphs.data.refresh.feeds.fetch_euvd_exploited) + CISA KEV
(processed/kev_catalog.json). Both date fields are date-only, compared as dates.
"""

import json
import re

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd

from cvegraphs.paths import OUTPUT, PROCESSED
from cvegraphs.style import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
    thousands_formatter,
)

DESCRIPTION = "Step lines: ENISA EUVD exploited list overlaid on CISA KEV, cumulative"

GRAPHS = OUTPUT


def _load():
    """(eu, cisa) frames of cve_id + list date, one row per CVE."""
    rows = []
    for i in json.load(open(PROCESSED / "euvd_kev.json")):
        cves = re.findall(r"CVE-\d{4}-\d+", i.get("aliases") or "")
        if cves:
            rows.append((cves[0], i.get("exploitedSince")))
    eu = pd.DataFrame(rows, columns=["cve_id", "date"])
    eu["date"] = pd.to_datetime(eu["date"], format="%b %d, %Y, %I:%M:%S %p",
                                errors="coerce").dt.normalize()
    eu = eu.dropna().sort_values("date").drop_duplicates("cve_id")

    kev = json.load(open(PROCESSED / "kev_catalog.json"))
    cisa = pd.DataFrame([(v["cveID"], v["dateAdded"]) for v in kev["vulnerabilities"]],
                        columns=["cve_id", "date"])
    cisa["date"] = pd.to_datetime(cisa["date"], errors="coerce").dt.normalize()
    cisa = cisa.dropna().drop_duplicates("cve_id")
    return eu, cisa


def stats():
    """The numbers the caption quotes, computed the same way the chart draws them."""
    eu, cisa = _load()
    E, C = set(eu["cve_id"]), set(cisa["cve_id"])
    m = eu.merge(cisa, on="cve_id", suffixes=("_eu", "_cisa"))
    lead = (m["date_cisa"] - m["date_eu"]).dt.days
    return {
        "eu": len(E), "cisa": len(C), "both": len(E & C),
        "eu_only": len(E - C), "cisa_only": len(C - E),
        "same_date": int((lead == 0).sum()), "eu_earlier": int((lead > 0).sum()),
        "eu_later": int((lead < 0).sum()),
        "eu_only_ids": sorted(E - C),
        "last": max(eu["date"].max(), cisa["date"].max()),
    }


def _cumulative(df, end):
    s = df.groupby("date").size().cumsum()
    s.loc[end] = s.iloc[-1]  # carry the step to the right edge
    return s.sort_index()


def render(nvd=None, ratios=DEFAULT_RATIOS):
    eu, cisa = _load()
    st = stats()
    end = st["last"]
    eu_c, cisa_c = _cumulative(eu, end), _cumulative(cisa, end)

    title = "EU KEV and CISA KEV, Overlaid"
    subtitle = ("Cumulative CVEs on ENISA's EUVD exploited list and on CISA's KEV "
                "catalog, by listing date.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        ax.step(eu_c.index, eu_c.values, where="post", color=COLORS["light"],
                lw={"wide": 11, "square": 10, "portrait": 10}[ratio],
                solid_capstyle="butt", zorder=2)
        ax.step(cisa_c.index, cisa_c.values, where="post", color=COLORS["primary"],
                lw=2.0, zorder=3)

        # EUVD went live May 13 2025; everything left of here is dated by CISA.
        launch = pd.Timestamp("2025-05-13")
        ax.axvline(launch, color=COLORS["secondary"], lw=1.1, ls=(0, (3, 3)), zorder=1)
        ax.text(launch - pd.Timedelta(days=25), 180, "EUVD\ngoes live\nMay 2025",
                fontsize=9.5, color=COLORS["secondary"], ha="right", va="bottom",
                linespacing=1.15)

        # Stat block: the whole story in three numbers.
        lab = {"wide": 12, "square": 10.5, "portrait": 11}[ratio]
        big = {"wide": 22, "square": 19, "portrait": 20}[ratio]
        # Wide has no headroom above the 2022 ramp, so its block sits in the empty
        # lower right, past the EUVD launch line.
        x0, y0, dy = {"wide": (0.72, 0.62, 0.19), "square": (0.04, 0.95, 0.15),
                      "portrait": (0.04, 0.95, 0.12)}[ratio]
        for k, (n, text, col) in enumerate([
                (st["both"], "on both lists", COLORS["primary"]),
                (st["eu_only"], "on the EU list only", COLORS["accent"]),
                (st["cisa_only"], "on CISA's list only", COLORS["neutral"])]):
            y = y0 - k * dy
            ax.text(x0, y, f"{n:,}", transform=ax.transAxes, fontsize=big,
                    fontweight="bold", color=col, ha="left", va="top")
            ax.annotate(text, (x0, y), xycoords="axes fraction",
                        xytext=(0, -big * 1.45), textcoords="offset points",
                        fontsize=lab, color=COLORS["text"], ha="left", va="top")

        # End labels.
        ax.text(end + pd.Timedelta(days=20), st["eu"] + 40, f"EU  {st['eu']:,}",
                fontsize=lab, fontweight="bold", color=COLORS["accent"],
                ha="left", va="bottom")
        ax.text(end + pd.Timedelta(days=20), st["cisa"] - 40, f"CISA  {st['cisa']:,}",
                fontsize=lab, fontweight="bold", color=COLORS["primary"],
                ha="left", va="top")

        ax.set_xlim(pd.Timestamp("2021-10-01"),
                    end + pd.Timedelta(days={"wide": 190, "square": 290,
                                             "portrait": 290}[ratio]))
        ax.set_ylim(0, st["eu"] * 1.08)
        ax.yaxis.set_major_formatter(thousands_formatter())
        ax.set_xticks([pd.Timestamp(y, 1, 1) for y in range(2022, end.year + 1)])
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%Y"))
        ax.grid(axis="y", color=COLORS["grid"], lw=0.8, zorder=0)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(COLORS["grid"])
        ax.tick_params(axis="both", length=0, labelsize=11, colors=COLORS["text"])

        foot = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05, "Thick pale line: EU (EUVD exploitedSince). Thin dark line: "
                 "CISA (KEV dateAdded). Source: ENISA EUVD API, CISA KEV.",
                 fontsize=foot, color=COLORS["secondary"], ha="left", va="bottom")

        top_m = {"wide": 0.76, "square": 0.80, "portrait": 0.83}[ratio]
        fig.subplots_adjust(top=top_m, bottom=0.14, left=0.08, right=0.96)
        draw_header(fig, title, subtitle, ratio=ratio, eyebrow_suffix="EXPLOITATION",
                    title_size={"wide": 26, "square": 22, "portrait": 22}[ratio])

        path = GRAPHS / f"eu_kev_overlay_{ratio}_{end.strftime('%Y-%m-%d')}.png"
        out.append(stamp_and_save(fig, path))
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

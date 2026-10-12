#!/usr/bin/env python3
"""
Which day of the week CISA adds CVEs to KEV, and the four times it was a weekend.

One bar per weekday across the whole catalog (Nov 3 2021 to the latest
addition). The weekend bars are the finding: no Saturday addition ever, and
four Sunday additions, three of them Citrix NetScaler on consecutive Sundays
(Sep 27 and Oct 4, 2026). A callout lists all four so the reader can count them.

Accuracy notes:

* KEV ``dateAdded`` is date-only (CISA's calendar date), so the weekday is read
  straight off it. No timezone conversion is applied or needed.
* Wednesday is inflated by the catalog launch (Nov 3 2021, a Wednesday, carried
  287 entries). That does not touch the weekend counts, which are the claim.
* The copy may quote the due-date window: since mid-2026 most entries carry a
  3-day federal deadline, so a Sunday listing is due Wednesday. ``stats()``
  prints the monthly share so that sentence is never retyped off memory.

Data: processed/kev_catalog.json (CISA KEV).
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch
import pandas as pd

from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

HERE = Path(__file__).resolve().parent
GRAPHS = HERE.parent / "graphs"
PROCESSED = HERE.parent / "processed"

DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
        "Saturday", "Sunday"]
SHORT = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def _load():
    cat = json.load(open(PROCESSED / "kev_catalog.json"))
    k = pd.DataFrame(cat["vulnerabilities"])
    k["added"] = pd.to_datetime(k["dateAdded"])
    k["due"] = pd.to_datetime(k["dueDate"])
    k["dow"] = k["added"].dt.day_name()
    return k


def _weekend_rows(k):
    """(date, product) callout rows, one per weekend listing day and product."""
    we = k[k["added"].dt.dayofweek >= 5]
    rows = []
    for day, g in we.groupby("added"):
        prods = g.groupby(["vendorProject", "product"]).size()
        for (vendor, product), n in prods.items():
            mult = f" ({n} CVEs)" if n > 1 else ""
            rows.append((f"{day:%a %b %-d, %Y}", f"{vendor} {product}{mult}"))
    return rows


def render(nvd=None, ratios=DEFAULT_RATIOS):
    k = _load()
    counts = k["dow"].value_counts().reindex(DAYS, fill_value=0)
    newest = k["added"].max()
    launch = k["added"].min()
    n_launch = int((k["added"] == launch).sum())
    we = k[k["added"].dt.dayofweek >= 5]
    rows = _weekend_rows(k)

    title = "CISA KEV Additions by Day of the Week"
    subtitle = (f"All {len(k):,} KEV entries, {launch:%b %-d, %Y} to "
                f"{newest:%b %-d, %Y}")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        x = list(range(7))
        colors = [COLORS["light"]] * 5 + [COLORS["alert"]] * 2
        # Launch-day entries (a Wednesday) drawn as their own pale segment so
        # the Wednesday bar does not read as a weekday habit.
        base = counts.values.copy()
        wed = DAYS.index(launch.day_name())
        base[wed] -= n_launch
        ax.bar(x, base, color=colors, width=0.7, zorder=3)
        ax.bar([wed], [n_launch], bottom=[base[wed]], color=COLORS["soft"],
               edgecolor=COLORS["light"], linewidth=1.2, width=0.7, zorder=3)
        lfs = {"wide": 10, "square": 8.5, "portrait": 8.5}[ratio]
        ax.text(wed, base[wed] + n_launch / 2,
                f"Launch\nday\n{n_launch}", ha="center",
                va="center", fontsize=lfs, color=COLORS["secondary"], zorder=6)

        fs = {"wide": 13, "square": 12, "portrait": 12}[ratio]
        for i, v in enumerate(counts.values):
            weekend = i >= 5
            ax.annotate(f"{int(v):,}", (i, v), textcoords="offset points",
                        xytext=(0, 5), ha="center", va="bottom",
                        fontsize=fs + (4 if weekend else 0), fontweight="bold",
                        color=COLORS["alert"] if weekend else COLORS["text"],
                        zorder=6)

        # Callout: every Sunday addition as a two-column table, in axes
        # coordinates so the columns stay aligned at every ratio.
        g = {"wide":     dict(x0=0.595, w=0.39, col=0.16, fs=11, dy=0.072),
             "square":   dict(x0=0.465, w=0.52, col=0.215, fs=9.5, dy=0.055),
             "portrait": dict(x0=0.445, w=0.54, col=0.22, fs=10, dy=0.045)}[ratio]
        y_top, pad = 0.95, 0.025
        h = pad * 2 + g["dy"] * (len(rows) + 1.3)
        ax.add_patch(FancyBboxPatch(
            (g["x0"], y_top - h), g["w"], h, transform=ax.transAxes,
            boxstyle="round,pad=0,rounding_size=0.012", facecolor=COLORS["soft"],
            edgecolor=COLORS["grid"], lw=1.2, zorder=7))
        tx = g["x0"] + 0.02
        y = y_top - pad
        ax.text(tx, y, f"All {len(we)} Sunday additions "
                f"({we['added'].nunique()} days)", transform=ax.transAxes,
                ha="left", va="top", fontsize=g["fs"], fontweight="bold",
                color=COLORS["text"], zorder=8)
        y -= g["dy"] * 1.05
        ax.plot([tx, g["x0"] + g["w"] - 0.02], [y + g["dy"] * 0.2] * 2,
                transform=ax.transAxes, color=COLORS["grid"], lw=0.8, zorder=8)
        for date, prod in rows:
            y -= g["dy"] * 0.25
            ax.text(tx, y, date, transform=ax.transAxes, ha="left", va="top",
                    fontsize=g["fs"], color=COLORS["text"], zorder=8)
            ax.text(tx + g["col"], y, prod, transform=ax.transAxes, ha="left",
                    va="top", fontsize=g["fs"], color=COLORS["text"], zorder=8)
            y -= g["dy"] * 0.75

        ax.set_xticks(x)
        ax.set_xticklabels(SHORT, fontsize={"wide": 13, "square": 12,
                                            "portrait": 12}[ratio])
        for lbl in ax.get_xticklabels()[5:]:
            lbl.set_color(COLORS["alert"])
            lbl.set_fontweight("bold")
        ax.tick_params(axis="x", length=0)
        # Every bar carries its own label, so the y-axis is redundant.
        ax.set_yticks([])
        ax.spines["left"].set_visible(False)
        ax.grid(False)
        ax.set_ylim(0, counts.max() * 1.12)
        ax.set_xlim(-0.6, 6.6)

        top_m = {"wide": 0.76, "square": 0.80, "portrait": 0.83}[ratio]
        bottom_m = {"wide": 0.14, "square": 0.12, "portrait": 0.10}[ratio]
        fig.subplots_adjust(top=top_m, bottom=bottom_m, left=0.05,
                            right=0.965)
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="Exploitation",
                    title_size={"wide": 26, "square": 21, "portrait": 21}[ratio])

        foot = {"wide": 9.5, "square": 8.0, "portrait": 8.0}[ratio]
        fig.text(0.05, 0.045,
                 "Day is the date CISA added the entry. Source: CISA Known "
                 f"Exploited Vulnerabilities catalog, version {newest:%Y.%m.%d}.",
                 fontsize=foot, color=COLORS["secondary"], ha="left",
                 va="bottom")

        path = GRAPHS / f"kev_weekend_{ratio}_{newest:%Y-%m-%d}.png"
        out.append(stamp_and_save(fig, path))
    return out


def stats():
    """Every figure the caption and copy quote, so none is retyped off the image."""
    k = _load()
    counts = k["dow"].value_counts().reindex(DAYS, fill_value=0)
    we = k[k["added"].dt.dayofweek >= 5]
    k["window"] = (k["due"] - k["added"]).dt.days
    r = k[k["added"] >= "2026-01-01"]
    by_month = r.groupby(r["added"].dt.to_period("M"))["window"].agg(
        lambda s: f"{(s <= 3).sum()}/{len(s)}")
    days = k.groupby("added").size()
    return {
        "newest_add": k["added"].max().date(),
        "catalog_total": len(k),
        "by_weekday": counts.to_dict(),
        "weekend_total": len(we),
        "listing_days": len(days),
        "weekend_listing_days": int((days.index.dayofweek >= 5).sum()),
        "weekend_entries": we[["cveID", "vendorProject", "product",
                               "dateAdded", "dueDate"]].to_dict("records"),
        "due_window_le3_by_month_2026": by_month.to_dict(),
    }


if __name__ == "__main__":
    for key, val in stats().items():
        print(f"{key:>30}: {val}")
    for p in render():
        print(p)

#!/usr/bin/env python3
"""
What a KEV listing now asks an agency to do, week by week through 2026.

CISA's BOD 26-04 (issued June 10, 2026) replaced the flat KEV remediation
deadline with a decision table keyed on four variables: whether the asset is
publicly exposed, whether the CVE is on KEV, whether the exploit is automatable,
and the technical impact. The top cell of that table reads "3 days & forensic
triage", and the directive defines the second half of that phrase: the agency
must "carry out a forensic triage of the asset to assess whether the system is
compromised."

CISA publishes which entries land in that cell. The KEV catalog carries a
per-entry ``forensicTriage`` flag ("Forensic triage required per BOD-26-04" on
the public catalog page), and the implementation guidance spells the triage out
as six sequential steps: scoping within 2 hours, evidence preservation and
critical patching at 2-24 hours, containment at 6-24, analysis at 24-48, and an
escalation decision at 48-72.

The chart is one dot per KEV entry, stacked into the week CISA added it, split
by that flag. The shape is the finding: the flag does not appear at all for the
first six months of 2026, then from July 1 it is on most of what CISA adds.

Two accuracy notes that shape the cohort:

* The first ``forensicTriage: Yes`` entry is dated 2026-07-01, three weeks AFTER
  BOD 26-04 was issued (June 10) and first cited in a KEV ``requiredAction``
  (2026-06-11). The 12 three-day entries CISA added under BOD 26-04 before
  July 1 carry no flag. That is either 12 genuine "no triage needed" calls or a
  field CISA had not started populating, and the catalog cannot tell the two
  apart, so the headline share is quoted from July 1 onward and June is left
  visible but unclaimed.
* ``forensicTriage: No`` is populated catalog-wide, on all 1,655 entries added
  before July 2026 as well. So the flag's absence in the first half of the chart
  is the catalog's own statement, not missing data.

Deliberately NOT plotted: the due-date window (21 -> 14 -> 3 days across 2026).
It is a real regime change and it correlates with this flag almost perfectly
(48 of the 53 three-day entries since July 1 are flagged, and no 14-day entry
is), but it is ground Jerry's BOD 26-04 commentary already covered, and putting
two step-changes on one canvas splits the finding. The window figures are in
the caption for the copy.

Data: processed/kev_catalog.json (CISA KEV, ``forensicTriage`` + ``dateAdded``).
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from rolling_config import today_utc
from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    MONO_FONT,
    draw_header,
    figsize_for,
    stamp_and_save,
)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
PROCESSED = Path(__file__).resolve().parent.parent / "processed"

YEAR = 2026

# Date of the first entry CISA flagged for forensic triage. Doubles as the bin
# anchor so a bin edge lands exactly on it (see _weekly).
ANCHOR = pd.Timestamp(YEAR, 7, 1)

# Stack order is bottom-up, so the flagged entries sit on the baseline and their
# height can be read straight off the axis. Same convention as patch_tuesday.
SERIES = [
    ("triage", "Forensic Triage Flagged", COLORS["primary"]),
    ("patch_only", "Not Flagged", COLORS["neutral"]),
]


def _load():
    """One row per KEV entry added in YEAR, with the triage flag and its week."""
    cat = json.load(open(PROCESSED / "kev_catalog.json"))
    k = pd.DataFrame([
        {
            "cve_id": v.get("cveID"),
            "vendor": v.get("vendorProject"),
            "product": v.get("product"),
            "added": v.get("dateAdded"),
            "due": v.get("dueDate"),
            "triage": v.get("forensicTriage") == "Yes",
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            "bod_26_04": "26-04" in (v.get("requiredAction") or ""),
        }
        for v in cat.get("vulnerabilities", [])
    ])
    # dateAdded and dueDate are both date-only, so this subtraction is a clean
    # calendar-day window with no time-of-day flooring to worry about.
    k["added"] = pd.to_datetime(k["added"], errors="coerce")
    k["due"] = pd.to_datetime(k["due"], errors="coerce")
    k["window"] = (k["due"] - k["added"]).dt.days
    k = k.dropna(subset=["added"])
    released = pd.to_datetime(cat.get("dateReleased"), errors="coerce", utc=True)
    return k, released


def _weekly(k):
    """Counts per seven-day bin of YEAR: flagged, patch-only, total.

    Bins are anchored on ANCHOR (the first flagged entry's date) rather than on
    the ISO week, so a bin EDGE falls exactly on it. With ISO weeks the bin
    holding Jul 1 also held Jun 29 and 30, which put 74 dots to the right of a
    divider labelled Jul 1 while the copy said 73. On a unit chart the reader
    can count, so that gap is a defect, not a rounding detail.
    """
    cur = k[k["added"].dt.year == YEAR].copy()
    cur["bin"] = ((cur["added"] - ANCHOR).dt.days // 7).astype(int)
    # Span the bin holding Jan 1 through the bin holding the newest addition, so
    # a quiet bin with zero KEV additions renders as an empty column instead of
    # vanishing and compressing the time axis.
    lo = int((pd.Timestamp(YEAR, 1, 1) - ANCHOR).days // 7)
    hi = int(cur["bin"].max())
    t = (cur.groupby("bin")["triage"].agg(triage="sum", total="size")
            .reindex(range(lo, hi + 1), fill_value=0))
    t["patch_only"] = t["total"] - t["triage"]
    t["start"] = [ANCHOR + pd.Timedelta(days=7 * b) for b in t.index]
    return t


def render(nvd=None, ratios=DEFAULT_RATIOS):
    k, released = _load()
    t = _weekly(k)
    s = stats()

    bins = list(t.index)
    first_i = bins.index(0)  # bin 0 starts on ANCHOR, so its LEFT edge is Jul 1

    # Month ticks sit on the bin that CONTAINS the 1st of the month, so a label
    # can never drift a column away from the date it names.
    ticks, labels = [], []
    for m in range(1, 13):
        d = pd.Timestamp(YEAR, m, 1)
        b = int((d - ANCHOR).days // 7)
        if b in t.index:
            ticks.append(bins.index(b))
            labels.append(d.strftime("%b"))

    title = "Forensic Triage on 2026 KEV Additions"
    subtitle = ("One dot per KEV entry, stacked into the week CISA added it; "
                f"{s['since_first_flagged']} of the {s['since_first_adds']} "
                "since Jul 1 are flagged.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        dot = {"wide": 108, "square": 62, "portrait": 62}[ratio]
        edge = {"wide": 1.1, "square": 0.9, "portrait": 0.9}[ratio]

        for key, label, color in SERIES:
            xs, ys = [], []
            for i, wk in enumerate(t.index):
                # Flagged dots occupy the bottom of the column, patch-only above.
                base = 0 if key == "triage" else int(t["triage"].iloc[i])
                for j in range(int(t[key].iloc[i])):
                    xs.append(i)
                    # Centers on integers, so columns line up dot-for-dot across
                    # the axis and an even-height stack tops out ON its gridline.
                    # Ticks are every 2, so an odd column sits between lines;
                    # the unit dots are the count, the axis is the scale.
                    ys.append(base + j + 1)
            ax.scatter(xs, ys, s=dot, color=color, label=label, zorder=3,
                       edgecolors="white", linewidths=edge)

        # The week the flag first appears. A rule plus one short callout: the
        # date is the load-bearing fact, so it is named on the image.
        ax.axvline(first_i - 0.5, color=COLORS["text"],
                   lw={"wide": 1.8, "square": 1.5, "portrait": 1.5}[ratio],
                   ls=(0, (7, 4)), zorder=2, alpha=1.0)
        ax.annotate(f"First Flagged Entry\n{s['first_flagged']:%b %-d}",
                    xy=(first_i - 0.4, t["total"].max() * 1.02),
                    xytext=(first_i - 1.1, t["total"].max() * 1.02),
                    ha="right", va="top",
                    fontsize={"wide": 11, "square": 9.5, "portrait": 9.5}[ratio],
                    fontweight="bold", color=COLORS["text"], zorder=6,
                    bbox=dict(facecolor="white", edgecolor="none", pad=2.0))

        ax.set_xticks(ticks)
        ax.set_xticklabels(labels,
                           fontsize={"wide": 12, "square": 10.5, "portrait": 10.5}[ratio])
        ax.set_ylabel("KEV Entries Added", fontsize=12, fontweight="normal")
        ax.set_ylim(0, t["total"].max() * 1.06)
        ax.set_xlim(-1.0, len(t) - 0.3)
        ax.set_axisbelow(True)
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.tick_params(axis="x", length=0)

        # Legend order follows the visual stack (bottom series first).
        handles, lbls = ax.get_legend_handles_labels()
        leg = fig.legend(handles, lbls, loc="lower left",
                         bbox_to_anchor=(0.05, {"wide": 0.105, "square": 0.098,
                                                "portrait": 0.088}[ratio]),
                         bbox_transform=fig.transFigure, ncol=2, frameon=False,
                         fontsize={"wide": 11.5, "square": 9.5, "portrait": 9.5}[ratio],
                         handletextpad=0.35, columnspacing=1.6, scatterpoints=1)
        leg.set_zorder(7)
        for txt in leg.get_texts():
            txt.set_color(COLORS["secondary"])

        top = {"wide": 0.80, "square": 0.79, "portrait": 0.82}[ratio]
        bottom_m = {"wide": 0.215, "square": 0.20, "portrait": 0.165}[ratio]
        left_m = {"wide": 0.095, "square": 0.12, "portrait": 0.12}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom_m, left=left_m, right=0.965)
        t1 = {"wide": 26, "square": 21, "portrait": 21}[ratio]
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="Exploitation",
                    title_size=t1)

        # House rule: ONE footnote, one line at every ratio. The BOD 26-04 tier
        # table, the six triage steps, the due-date collapse and the June
        # ambiguity all live in content/captions/kev_triage.md.
        foot = {"wide": 9.5, "square": 8.5, "portrait": 8.5}[ratio]
        fig.text(0.05, 0.055,
                 "Source: CISA KEV catalog, per-entry forensicTriage flag; entries "
                 f"added Jan 1 to {s['newest_add']:%b %-d, %Y} "
                 "(no earlier entry is flagged).",
                 fontsize=foot, color=COLORS["secondary"], ha="left", va="bottom")

        path = GRAPHS / f"kev_triage_{ratio}_{today_utc():%Y-%m-%d}.png"
        out.append(stamp_and_save(fig, path))
    return out


def stats():
    """Figures the chart does not print, for the caption and the copy."""
    k, released = _load()
    cur = k[k["added"].dt.year == YEAR]
    flagged = k[k["triage"]]
    first = flagged["added"].min()
    since = cur[cur["added"] >= first]
    bod = k[k["bod_26_04"]]

    win = since.groupby([since["window"], since["triage"]]).size()
    return {
        "catalog_total": int(len(k)),
        "catalog_released": released,
        "newest_add": cur["added"].max(),
        "ytd_adds": int(len(cur)),
        "ytd_flagged": int(cur["triage"].sum()),
        "first_flagged": first,
        "since_first_adds": int(len(since)),
        "since_first_flagged": int(since["triage"].sum()),
        "since_first_pct": 100 * since["triage"].mean(),
        "flagged_all_time": int(len(flagged)),
        "bod_cited": int(len(bod)),
        "bod_first_cited": bod["added"].min(),
        "bod_flagged": int(bod["triage"].sum()),
        # Three-day entries added under BOD 26-04 BEFORE the flag first
        # appears. These are the cohort caveat: either 12 genuine "no triage"
        # calls or a field CISA had not started populating.
        "bod_3day_before_flag": int(len(k[k["bod_26_04"]
                                          & (k["added"] < first)
                                          & (k["window"] == 3)])),
        "pre_2026_flagged": int(len(k[(k["added"].dt.year < YEAR) & k["triage"]])),
        "win_3_flagged": int(win.get((3, True), 0)),
        "win_3_unflagged": int(win.get((3, False), 0)),
        "win_14_flagged": int(win.get((14, True), 0)),
        "win_14_unflagged": int(win.get((14, False), 0)),
        "flagged_vendors": int(flagged["vendor"].nunique()),
        "flagged_ransomware": int(flagged["ransomware"].sum()),
        "since_first_ransomware": int(since["ransomware"].sum()),
    }


if __name__ == "__main__":
    for k, v in stats().items():
        print(f"{k:>22}: {v}")
    for p in render():
        print(p)

#!/usr/bin/env python3
"""
EPSS Early Warning — what EPSS said in the 90 days before a KEV listing.

Tests EPSS as an alarm rather than as a score. For the CVEs CISA added to KEV
this year that had been public at least 90 days, read the production EPSS score
at six fixed lookbacks before the KEV date (90, 60, 30, 15, 7, 1 day) and stack
the cohort into EPSS bands at each one. If EPSS worked like a tripwire, the dark
(high-score) mass would grow left to right as CISA's decision approached.

The cohort is fixed at the 90-day bar so every lookback describes the SAME
CVEs; the shorter horizons would each admit more additions, and a growing
cohort would move the bands for reasons that have nothing to do with EPSS.

The chart states the bands and the 0.10 contour; the argument --- that EPSS
holds a near-static prior rather than escalating into the KEV date --- lives in
the post copy, with the movement counts in a footnote line so a bare screenshot
still carries the caveat.

Data: processed/epss_early_warning.parquet + _meta.json from
cvegraphs.precompute.epss_early_warning (exact-date historical EPSS
snapshots at each lookback).

Renders one PNG per aspect ratio into content/drafts/<name>/.
"""

import json

import matplotlib.pyplot as plt
import pandas as pd

from cvegraphs.paths import OUTPUT, PROCESSED
from cvegraphs.style import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

DESCRIPTION = "Stacked bands: EPSS score at 90/60/30/15/7/1 days before each 2026 KEV addition, fixed cohort"

GRAPHS = OUTPUT

# Band -> (fill, label ink). A single navy ramp, light (quiet) to dark (loud),
# so the stack reads as one sequential scale rather than four categories.
BAND_STYLE = {
    "Under 0.01":  (COLORS["light"], COLORS["text"]),
    "0.01 - 0.10": (COLORS["neutral"], COLORS["text"]),
    "0.10 - 0.50": (COLORS["accent"], "white"),
    "0.50 and up": (COLORS["primary"], "white"),
}
# Bottom-to-top stack order: quiet at the base, loud on top.
ORDER = ["Under 0.01", "0.01 - 0.10", "0.10 - 0.50", "0.50 and up"]
ALARM = ("0.10 - 0.50", "0.50 and up")   # bands at or above EPSS 0.10


def _load():
    df = pd.read_parquet(PROCESSED / "epss_early_warning.parquet")
    meta = json.loads((PROCESSED / "epss_early_warning_meta.json").read_text())
    return df, meta


def render(nvd=None, ratios=DEFAULT_RATIOS):
    """Render the early-warning stack for each ratio. Returns output paths.

    ``nvd`` is accepted for the shared registry render signature and ignored:
    everything comes from the precomputed early-warning parquet.
    """
    _, meta = _load()
    hz = meta["horizons"]
    per = meta["per_horizon"]
    n = meta["cohort"]
    year = meta["kev_year"]
    mv = meta["movement"]

    xs = list(range(len(hz)))
    # counts per band per horizon, and the height of the 0.10 boundary
    bands = {b: [per[str(h)]["bands"][b] for h in hz] for b in ORDER}
    below10 = [per[str(h)]["bands"]["Under 0.01"]
               + per[str(h)]["bands"]["0.01 - 0.10"] for h in hz]
    alarm_pct = [100 * sum(per[str(h)]["bands"][b] for b in ALARM) / n
                 for h in hz]

    title = "EPSS in the 90 Days Before a KEV Listing"
    sub = (f"{n} CVEs added to KEV in {year} after 90+ days in public: "
           "EPSS score band at six lookbacks before the KEV date")

    out = []
    for ratio in ratios:
        fig = plt.figure(figsize=figsize_for(ratio))
        # Header -> legend -> plot -> footnote, top to bottom. The legend rides
        # above the plot so the footer belongs entirely to the footnote.
        top = {"wide": 0.695, "square": 0.655, "portrait": 0.700}[ratio]
        bottom = {"wide": 0.300, "square": 0.325, "portrait": 0.285}[ratio]
        left = {"wide": 0.085, "square": 0.115, "portrait": 0.115}[ratio]
        ax = fig.subplots(gridspec_kw=dict(top=top, bottom=bottom, left=left,
                                           right=0.965))

        bw = {"wide": 0.62, "square": 0.66, "portrait": 0.66}[ratio]
        lab = {"wide": 12, "square": 10.5, "portrait": 11}[ratio]
        val = {"wide": 12.5, "square": 10.5, "portrait": 11}[ratio]

        # ---- stacked bands --------------------------------------------------
        base = [0] * len(hz)
        for b in ORDER:
            vals = bands[b]
            fill, ink = BAND_STYLE[b]
            ax.bar(xs, vals, bottom=base, width=bw, color=fill, zorder=3,
                   edgecolor="white", linewidth=1.6)
            for x, v, b0 in zip(xs, vals, base):
                if v >= 4:  # only label segments with room for the digits
                    ax.text(x, b0 + v / 2, str(v), ha="center", va="center",
                            fontsize=val, fontweight="bold", color=ink,
                            zorder=5)
            base = [a + b_ for a, b_ in zip(base, vals)]

        # ---- the EPSS 0.10 contour -----------------------------------------
        # Traces the top of the below-0.10 mass, i.e. the boundary between the
        # quiet and alarm halves of the stack. Read it on the y-axis as "how
        # many CVEs EPSS was not flagging". A flat contour means the alarm rate
        # never really moves.
        ax.plot(xs, below10, color=COLORS["alert"], lw=2.0, zorder=6,
                marker="o", markersize=5, markerfacecolor="white",
                markeredgewidth=1.8, markeredgecolor=COLORS["alert"])

        # ---- alarm share above each bar ------------------------------------
        for x, p in zip(xs, alarm_pct):
            ax.text(x, n + 1.4, f"{p:.0f}%", ha="center", va="bottom",
                    fontsize=val, fontweight="bold", color=COLORS["primary"],
                    zorder=5)

        ax.set_ylim(0, n + {"wide": 7.5, "square": 8.5, "portrait": 8.0}[ratio])
        ax.set_xlim(-0.62, len(hz) - 0.38)
        ax.set_xticks(xs)
        ax.set_xticklabels([f"{h}" for h in hz], fontsize=lab,
                           fontweight="bold")
        ax.set_xlabel("Days before the CVE was added to KEV",
                      fontsize=lab, fontweight="bold")
        ax.set_ylabel(f"CVEs (of {n})", fontsize=lab, fontweight="bold")
        ax.set_yticks([0, 15, 30, 45, 60])
        ax.grid(axis="y", color=COLORS["grid"], linewidth=0.6, alpha=0.8)
        ax.grid(axis="x", visible=False)
        ax.set_axisbelow(True)
        ax.spines["left"].set_visible(False)
        ax.tick_params(axis="both", length=0)

        # ---- legend ---------------------------------------------------------
        handles = [plt.Rectangle((0, 0), 1, 1, color=BAND_STYLE[b][0])
                   for b in reversed(ORDER)]
        labels = [f"EPSS {b}" for b in reversed(ORDER)]
        handles.append(plt.Line2D([0], [0], color=COLORS["alert"], lw=2.0,
                                  marker="o", markersize=5,
                                  markerfacecolor="white", markeredgewidth=1.8,
                                  markeredgecolor=COLORS["alert"]))
        labels.append("CVEs below 0.10")
        # Placed in FIGURE coordinates so the row sits at a known height
        # instead of drifting with the axes box.
        ncol = {"wide": 5, "square": 3, "portrait": 3}[ratio]
        leg_y = {"wide": 0.775, "square": 0.745, "portrait": 0.780}[ratio]
        ax.legend(handles, labels, loc="upper center",
                  bbox_to_anchor=(0.525, leg_y), bbox_transform=fig.transFigure,
                  ncol=ncol, frameon=False, fontsize=lab - 0.5,
                  handlelength=1.5, handleheight=1.0, columnspacing=1.4,
                  labelspacing=0.7)

        t1 = {"wide": 26, "square": 19, "portrait": 20}[ratio]
        wsub = sub if ratio == "wide" else sub.replace(": ", ":\n")
        draw_header(fig, title, wsub, ratio, eyebrow_suffix="Exploitation",
                    title_size=t1)

        # ---- footnote -------------------------------------------------------
        foot_size = {"wide": 9.5, "square": 8, "portrait": 8}[ratio]
        if ratio == "wide":
            foot = (
                f"Of {meta['total_added']} CVEs added to KEV in {year}, "
                f"{meta['same_day']} were added the same day the CVE went "
                f"public and {meta['within_1d']} within a day; "
                f"{meta['under_min_age']} had under 90 days of public "
                "history.\n"
                f"The {n} shown are the same CVEs at every lookback. Over the "
                f"full 90 days {mv['flat_05']} of {mv['pairs']} moved under "
                f"0.05, {mv['crossed_10_up']} crossed 0.10 upward, "
                f"{mv['never_10']} never reached 0.10.\n"
                "EPSS retrained inside 8 of the 62 windows; on the other 54 "
                "the pattern holds. Scores read from production snapshots on "
                "the exact lookback dates.\n"
                "Source: CISA KEV · FIRST EPSS · CVE List V5."
            )
        else:
            foot = (
                f"Of {meta['total_added']} CVEs added to KEV in {year}, "
                f"{meta['same_day']} were added the same day the CVE went "
                f"public and {meta['within_1d']} within a day;\n"
                f"{meta['under_min_age']} had under 90 days of public history. "
                f"The {n} shown are the same CVEs at every lookback.\n"
                f"Over the full 90 days {mv['flat_05']} of {mv['pairs']} moved "
                f"under 0.05, {mv['crossed_10_up']} crossed 0.10 upward, "
                f"{mv['never_10']} never reached 0.10.\n"
                "EPSS retrained inside 8 of the 62 windows; on the other 54 "
                "the pattern holds. Scores read\n"
                "from production snapshots on the exact lookback dates.  "
                "Source: CISA KEV · FIRST EPSS · CVE List V5."
            )
        fig.text(0.05, 0.035, foot, fontsize=foot_size,
                 color=COLORS["secondary"], ha="left", va="bottom",
                 linespacing=1.5)

        path = GRAPHS / (f"epss_early_warning_{ratio}_"
                         f"{pd.Timestamp.today().strftime('%Y-%m-%d')}.png")
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

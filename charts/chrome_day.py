#!/usr/bin/env python3
"""
Out with Patch Tuesday, in with Chrome Day.

Monthly head-to-head of the single biggest publishing day for Microsoft (its
Patch Tuesday) vs Google's Chrome CNA, over the trailing ~14 months. Tells two
honest truths at once: Microsoft is a monthly metronome, while Chrome's drops
are burstier but have grown to dwarf a Patch Tuesday.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from data import load_cvelist
import matplotlib.patches as mpatches

from rolling_config import data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
MONTHS = 14
# Distinct hues per vendor (brand colors are both blue, so unusable here).
# Each month the winner is full-saturation; the loser is faded, so the
# crossover reads at a glance while vendor identity stays fixed by hue.
MS_COLOR = "#ea580c"              # Microsoft = orange
MS_LIGHT = "#f9d0b4"             # faded orange (Microsoft, month it lost)
CHROME_COLOR = COLORS["primary"]  # Chrome = navy
CHROME_LIGHT = "#b7c1cf"         # faded navy (Chrome, month it lost)


def _monthly_max_day(cve, cpub, assigner):
    """Period(month) -> largest single-day CVE count that CNA published."""
    sub = cve[cve["assigner_short_name"] == assigner]
    spub = cpub[sub.index]
    daily = sub.assign(d=spub.dt.date).groupby("d").size()
    dd = pd.to_datetime(pd.Series(daily.index), utc=True)
    return daily.groupby(dd.dt.to_period("M").values).max()


def render(nvd=None, ratios=DEFAULT_RATIOS):
    cve = load_cvelist()
    cpub = pd.to_datetime(cve["date_published"], utc=True, errors="coerce").dt.tz_convert(None)
    asof = data_asof(cve)
    asof_str = asof.strftime("%b %d, %Y")

    ms = _monthly_max_day(cve, cpub, "microsoft")
    ch = _monthly_max_day(cve, cpub, "Chrome")

    # End on the last COMPLETE month; the current month is partial (and its
    # Patch Tuesday may not have landed), so it is dropped rather than shown
    # half-formed.
    last_complete = asof.tz_convert(None).to_period("M") - 1
    periods = [last_complete - i for i in range(MONTHS)][::-1]
    ms_v = [int(ms.get(p, 0)) for p in periods]
    ch_v = [int(ch.get(p, 0)) for p in periods]

    ch_peak = max(ch_v)
    ch_peak_i = ch_v.index(ch_peak)
    ms_peak = max(ms_v)

    title1 = "Out with Patch Tuesday, in with Chrome Day"
    title2 = f"Chrome's biggest day hit {ch_peak}; Microsoft's biggest Patch Tuesday: {ms_peak}"
    sub = "Biggest single publishing day per month. Microsoft is monthly clockwork; Chrome is burstier but bigger."

    labels = [p.strftime("%b\n%y") for p in periods]
    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        x = range(len(periods))
        w = 0.42
        # Winner full-saturation, loser faded (position + legend keep vendor ID).
        ms_c = [MS_COLOR if ms_v[i] >= ch_v[i] else MS_LIGHT for i in x]
        ch_c = [CHROME_COLOR if ch_v[i] > ms_v[i] else CHROME_LIGHT for i in x]
        ax.bar([i - w / 2 for i in x], ms_v, width=w, color=ms_c, edgecolor="white")
        ax.bar([i + w / 2 for i in x], ch_v, width=w, color=ch_c, edgecolor="white")

        # Annotate the Chrome peak.
        ax.annotate(f"{ch_peak}", xy=(ch_peak_i + w / 2, ch_peak),
                    xytext=(0, 4), textcoords="offset points",
                    ha="center", va="bottom", fontsize=13,
                    fontweight="bold", color=CHROME_COLOR)

        ax.set_xticks(list(x))
        ax.set_xticklabels(labels, fontsize=10)
        ax.margins(y=0.18)
        # Manual legend so swatches stay full-saturation regardless of bar fades.
        ax.legend(handles=[mpatches.Patch(color=MS_COLOR, label="Microsoft (Patch Tuesday)"),
                           mpatches.Patch(color=CHROME_COLOR, label="Chrome (Google)")],
                  loc="upper left", fontsize=11, frameon=False)

        ax.text(0.0, -0.155,
                f"Biggest single day each CNA published, {MONTHS} complete months "
                f"through {periods[-1].strftime('%b %Y')}.\nWinner each month shown "
                f"in full color. Source: CVE List V5.",
                transform=ax.transAxes, fontsize=9.5, color=COLORS["neutral"],
                va="top", linespacing=1.4)

        top = {"wide": 0.80, "square": 0.84, "portrait": 0.86}[ratio]
        fig.subplots_adjust(top=top, bottom=0.19, left=0.10, right=0.96)
        if ratio == "wide":
            fig.text(0.04, 0.95, title1, fontsize=21, fontweight="bold",
                     color=COLORS["text"], ha="left", va="top")
            fig.text(0.04, 0.90, title2, fontsize=12.5, fontweight="bold",
                     color=COLORS["alert"], ha="left", va="top")
            fig.text(0.04, 0.855, sub, fontsize=11, color=COLORS["secondary"],
                     ha="left", va="top")
        else:
            fig.text(0.05, 0.965, title1, fontsize=19, fontweight="bold",
                     color=COLORS["text"], ha="left", va="top")
            fig.text(0.05, 0.918, title2, fontsize=12.5, fontweight="bold",
                     color=COLORS["alert"], ha="left", va="top")
            fig.text(0.05, 0.882, sub, fontsize=10.5, color=COLORS["secondary"],
                     ha="left", va="top")

        path = GRAPHS / f"chrome_day_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof_str)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

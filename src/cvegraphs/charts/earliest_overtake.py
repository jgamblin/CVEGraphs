#!/usr/bin/env python3
"""
The earliest a year has passed the PREVIOUS year's full CVE total.

For each year Y, the calendar day Y's cumulative non-rejected count first reaches
year (Y-1)'s full-year total. Ranked earliest first, top N shown.

The honest catch, and the reason this chart exists: the earliest crossings in the
raw record are not the fastest-growing years, they are the years with a trivially
small baseline. 2017 cleared the 2016 data-reboot anomaly by June. So the baseline
each year had to beat is printed next to the year, and the chart lets the reader
disqualify those rows without the chart hiding them.

Only one year is excluded, and not for being inconvenient:

1. The series starts at ``MIN_YEAR`` (2001) so every baseline is a full year of
   program operation. This drops exactly one crossing, 2000, whose baseline is
   1999: a founding stub of 320 CVEs that all carry a single publication date.
2. Years that never reached the prior year's total simply do not appear (2016 was
   smaller than 2015, for example).

Early years ARE dated coarsely (2002 has 60 distinct publishing days against 246
in 2005, and 2004 has 88). That is DISCLOSED in the footnote rather than used to
remove them. An earlier draft filtered them out on a distinct-publishing-days
guard; it was reverted deliberately, because keeping them demotes the current year
and a filter that flatters the headline is not worth defending.

Data: CVE List V5 (published, non-rejected, by publication date).
"""


import matplotlib.pyplot as plt
import pandas as pd

from cvegraphs.data import load_cvelist
from cvegraphs.paths import OUTPUT
from cvegraphs.rolling import current_year, data_asof
from cvegraphs.style import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

DESCRIPTION = "Lollipop: the earliest a year passed the previous year's full CVE total, top 10"

GRAPHS = OUTPUT
TOP_N = 10
# How many of the top rows carry their baseline inline. Covers the current year
# and everything that outranks it, which is the comparison that matters.
BASELINE_ROWS = 4
# Series starts at 2001 so every baseline year is a full year of program
# operation. 2000 is the only crossing this drops, and it is dropped because its
# baseline is 1999, the founding stub: 320 CVEs that all carry one publication
# date. Nothing else is excluded. Early years ARE dated coarsely (2002 has 60
# distinct publishing days against 246 in 2005), but that is disclosed in the
# footnote rather than used to remove them, because including them makes the
# current year look LESS exceptional, not more.
MIN_YEAR = 2001
# Below this many distinct publishing days a year's dating is called out as
# coarse in the footnote.
COARSE_PUB_DAYS = 150

# Day-of-year for the first of each month (non-leap) for the x axis.
_MONTHS = [("Jan", 1), ("Feb", 32), ("Mar", 60), ("Apr", 91), ("May", 121),
           ("Jun", 152), ("Jul", 182), ("Aug", 213), ("Sep", 244),
           ("Oct", 274), ("Nov", 305), ("Dec", 335)]


def _load():
    df = load_cvelist()
    if "is_published" in df.columns:
        df = df[df["is_published"]]
    return df


def _crossings(df):
    """Every year that passed the prior year's full total, on real daily dating.

    Returns (crossings DataFrame, list of years dropped for bulk dating).
    """
    dates = pd.to_datetime(df["date_published"], utc=True, errors="coerce")
    d = df.assign(dp=dates).dropna(subset=["dp"])
    d = d.assign(year=d["dp"].dt.year)
    totals = d.groupby("year").size()
    pub_days = d.groupby("year")["dp"].apply(lambda s: s.dt.date.nunique())

    rows, coarse = [], []
    for y in sorted(totals.index):
        if y < MIN_YEAR:
            continue
        prior = int(totals.get(y - 1, 0))
        if not prior:
            continue
        cur = d[d["year"] == y].sort_values("dp")
        if len(cur) < prior:
            continue  # never got there
        hit = cur.iloc[prior - 1]["dp"]  # the row that reaches the baseline
        days = int(pub_days.get(y, 0))
        if days < COARSE_PUB_DAYS:
            coarse.append(int(y))  # kept, but its date is approximate
        rows.append({
            "year": int(y),
            "baseline": prior,
            "date": hit,
            "doy": int(hit.dayofyear),
            "pub_days": days,
        })
    return pd.DataFrame(rows), coarse


def render(nvd=None, ratios=DEFAULT_RATIOS):
    """``nvd`` accepted for the shared registry render signature and ignored."""
    df = _load()
    asof = data_asof(df)
    cur_year = current_year(asof)

    ranked, coarse = _crossings(df)
    ranked = ranked.sort_values("doy").reset_index(drop=True)
    cross = ranked.head(TOP_N)
    # Earliest at the TOP of the chart.
    cross = cross.iloc[::-1].reset_index(drop=True)

    this_year = cross[cross["year"] == cur_year]
    rank = None
    if (ranked["year"] == cur_year).any():
        rank = int(ranked.index[ranked["year"] == cur_year][0]) + 1

    title = "The Earliest a Year Has Passed the Previous Year's CVE Total"
    if rank and len(this_year):
        row = this_year.iloc[0]
        ordinal = {1: "earliest", 2: "2nd earliest", 3: "3rd earliest"}.get(
            rank, f"{rank}th earliest")
        sub = (
            f"{cur_year} crossed on {row['date'].strftime('%b %-d')}, the {ordinal} "
            f"since {MIN_YEAR}, and the only one that had to clear more than "
            f"{row['baseline'] // 1000},000 CVEs to do it"
        )
    else:
        sub = f"Top {TOP_N} earliest crossings, with the total each year had to beat"

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        ypos = range(len(cross))
        # Clear the marker before the date label; the dot covers more x-units on
        # the narrow canvases, so the gap scales with the ratio.
        label_gap = {"wide": 7, "square": 11, "portrait": 12}[ratio]

        for i, r in cross.iterrows():
            is_cur = r["year"] == cur_year
            color = COLORS["alert"] if is_cur else COLORS["primary"]
            ax.plot([0, r["doy"]], [i, i], color=color,
                    linewidth=3.0 if is_cur else 2.2,
                    solid_capstyle="round", zorder=2)
            ax.plot([r["doy"]], [i], "o", color=color,
                    markersize=11 if is_cur else 8.5, zorder=3)
            # The top rows outrank the current year, so the baseline each one
            # cleared rides with the date. Without it the dominant read is
            # "2026 is only fourth" and the answer sits in 9pt footnote grey.
            txt = r["date"].strftime("%b %-d")
            if i >= len(cross) - BASELINE_ROWS:
                txt += f"  ·  cleared {int(r['baseline']):,}"
            ax.text(r["doy"] + label_gap, i, txt,
                    va="center", ha="left",
                    fontsize=12.5 if is_cur else 11.5,
                    fontweight="bold" if is_cur else "normal",
                    color=color, zorder=4)

        # Year only. The baselines differ by more than an order of magnitude, but
        # printing them per row crowded the plot; that context lives in the
        # subtitle and one footnote line instead.
        ax.set_yticks(list(ypos))
        ax.set_yticklabels([str(r["year"]) for _, r in cross.iterrows()])
        for tick, (_, r) in zip(ax.get_yticklabels(), cross.iterrows()):
            if r["year"] == cur_year:
                tick.set_color(COLORS["alert"])
                tick.set_fontweight("bold")

        ax.set_xticks([d for _, d in _MONTHS])
        ax.set_xticklabels([m for m, _ in _MONTHS])
        ax.set_xlim(0, 378)
        ax.set_ylim(-0.7, len(cross) - 0.3)
        ax.grid(axis="x", visible=True)
        ax.grid(axis="y", visible=False)
        ax.set_axisbelow(True)
        ax.spines["left"].set_visible(False)
        ax.tick_params(axis="y", length=0)

        top = {"wide": 0.78, "square": 0.80, "portrait": 0.82}[ratio]
        bottom = {"wide": 0.30, "square": 0.26, "portrait": 0.23}[ratio]
        left = {"wide": 0.10, "square": 0.13, "portrait": 0.14}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom, left=left, right=0.97)

        t1 = {"wide": 22, "square": 17, "portrait": 16}[ratio]
        sub_wrapped = (sub if ratio == "wide"
                       else sub.replace(", and the only one", ",\nand the only one"))
        draw_header(fig, title, sub_wrapped, ratio, eyebrow_suffix="Volume",
                    title_size=t1)

        foot_size = {"wide": 9.5, "square": 8.5, "portrait": 8.5}[ratio]
        # Coarse-dated years that actually made the top N, so the note only
        # appears when a reader can see one of them.
        shown_coarse = sorted(int(y) for y in cross["year"] if y in coarse)

        coarse_note = ""
        if shown_coarse:
            listed = " and ".join(", ".join(str(y) for y in shown_coarse)
                                  .rsplit(", ", 1))
            if ratio == "wide":
                coarse_note = (
                    f"Dates for {listed} are approximate: those years were published "
                    "in large batches rather than daily, so the crossing day is coarse."
                )
            else:
                coarse_note = (f"Dates for {listed} are approximate: those years were "
                               "published in batches, not daily.")

        # TOP_N truncates: say so, and say where the rest landed. A footnote that
        # only mentions non-crossers reads as "these are all of them".
        n_all = len(ranked)
        rest = ranked.iloc[TOP_N:]
        rest_when = ""
        if len(rest):
            months = sorted({d.month for d in rest["date"]})
            names = [pd.Timestamp(2001, m, 1).strftime("%B") for m in months]
            rest_when = (" and ".join(names) if len(names) <= 2
                         else ", ".join(names[:-1]) + " and " + names[-1])

        if len(rest):
            lead = (f"The {TOP_N} earliest of the {n_all} crossings since {MIN_YEAR}; "
                    f"the other {n_all - TOP_N} all landed in {rest_when}.")
        else:
            lead = f"All {n_all} crossings since {MIN_YEAR}."

        # base_note is deliberately unused: the top rows now carry their cleared
        # total inline, so repeating it here was the same fact three times.
        lines = ["The day each year's running CVE count first reached the previous "
                 "year's full-year total.", lead]
        if coarse_note:
            lines.append(coarse_note)
        lines.append("Source: CVE List V5, published and non-rejected, by "
                     "publication date.")
        fig.text(
            0.05, 0.045, "\n".join(lines),
            fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom",
            linespacing=1.5,
        )

        path = GRAPHS / f"earliest_overtake_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

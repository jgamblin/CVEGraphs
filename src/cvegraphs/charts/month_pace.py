#!/usr/bin/env python3
"""
Is this month on pace to be the biggest month on record?

One cumulative line per month of the current year: CVEs published from the 1st
to each day of the month. The newest (partial) month is drawn heavy in navy,
the previous month in mid navy, the rest in pale grey. The dashed rule is the
all-time monthly record, so the reader can see the gap closing without the
chart projecting anything.

Why cumulative-by-day instead of monthly bars: a partial month drawn as a bar
next to complete ones always looks like a dip. Here every month is compared
at the same day of the month, so a partial month is a fair comparison at every
point it has.

Scope note: the month-close volume post (final count, YoY growth) comes from
the MonthlyCVEStats repo, not this one. This chart is the mid-month
companion and says nothing a month-close post would need to retract.

Data: CVE List V5, non-rejected, by UTC publication date.
"""


import matplotlib.pyplot as plt
import pandas as pd

from cvegraphs.data import load_cvelist
from cvegraphs.paths import OUTPUT
from cvegraphs.rolling import data_asof
from cvegraphs.style import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
    thousands_formatter,
)

DESCRIPTION = "Cumulative lines: CVEs by day of month for each month this year, against the monthly record"

GRAPHS = OUTPUT


def _load():
    cl = load_cvelist().drop_duplicates("cve_id")
    pub = pd.to_datetime(cl["date_published"], utc=True, errors="coerce").dropna()
    asof = data_asof(cl)
    return pub.dt.tz_localize(None), asof


def _cumulative(pub, period):
    """Cumulative CVEs by day of month for one month, days 1..last day seen."""
    x = pub[pub.dt.to_period("M") == period]
    daily = x.dt.day.value_counts().sort_index()
    last = period.days_in_month if x.empty or x.max().day == period.days_in_month \
        else x.max().day
    return daily.reindex(range(1, last + 1), fill_value=0).cumsum()


def _table():
    pub, asof = _load()
    cur = asof.tz_localize(None).to_period("M")
    months = pd.period_range(pd.Period(f"{cur.year}-01", "M"), cur, freq="M")
    curves = {}
    for p in months:
        c = _cumulative(pub, p)
        if p != cur:  # a complete month runs to its last calendar day
            c = c.reindex(range(1, p.days_in_month + 1)).ffill().fillna(0)
        curves[p] = c
    totals = pub.dt.to_period("M").value_counts()
    record_month = totals.drop(cur).idxmax()
    return curves, cur, record_month, int(totals[record_month]), asof


def render(nvd=None, ratios=DEFAULT_RATIOS):
    curves, cur, rec_m, rec_n, asof = _table()
    prev = cur - 1
    now = curves[cur]
    day = int(now.index[-1])
    # Today is still filling in, so the like-for-like comparison uses the last
    # COMPLETED day of the month, not a few hours of today against a full day.
    done = day - 1
    prev_at_day = int(curves[prev].loc[done])

    # Once the current month passes the old record, the dashed rule is the
    # PREVIOUS record and the labels have to say so.
    passed = int(now.iloc[-1]) > rec_n
    rec_word = "previous record" if passed else "monthly record"
    title = f"Cumulative CVEs Published by Day of Month, {cur.year}"
    subtitle = (f"{cur.strftime('%B')} (partial) against every earlier "
                f"{cur.year} month; dashed line is the {rec_word}.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        fs = {"wide": 11.5, "square": 10, "portrait": 10}[ratio]

        for p, c in curves.items():
            if p in (cur, prev):
                continue
            ax.plot(c.index, c.values, color=COLORS["light"], lw=1.6, zorder=2)
            ax.annotate(p.strftime("%b"), (c.index[-1], c.iloc[-1]),
                        textcoords="offset points", xytext=(5, 0), va="center",
                        fontsize=fs - 2, color=COLORS["neutral"])
        pc = curves[prev]
        ax.plot(pc.index, pc.values, color=COLORS["accent"], lw=2.6, zorder=3)
        # When last month IS the record, the record rule already names it and
        # a second label would sit on top of the dashed line.
        ax.annotate(prev.strftime("%b") if prev == rec_m
                    else f"{prev.strftime('%b')} {int(pc.iloc[-1]):,}",
                    (pc.index[-1], pc.iloc[-1]), textcoords="offset points",
                    xytext=(5, -2), va="top", fontsize=fs, fontweight="bold",
                    color=COLORS["accent"])
        ax.plot(now.index, now.values, color=COLORS["primary"], lw=3.8, zorder=4)
        ax.scatter([day], [now.iloc[-1]], s=46, color=COLORS["primary"], zorder=5)
        # Same form as the previous-month label, at the same completed day, so
        # the two read as the pair they are.
        ax.annotate(f"{cur.strftime('%b')} at day {done}: {int(now.loc[done]):,}",
                    (done, now.loc[done]), textcoords="offset points",
                    xytext=(-30, 30), ha="right", va="bottom", fontsize=fs + 0.5,
                    fontweight="bold", color=COLORS["primary"], zorder=6,
                    bbox=dict(facecolor="white", edgecolor="none", pad=1.0),
                    arrowprops=dict(arrowstyle="-", color=COLORS["primary"],
                                    lw=1.0, shrinkA=0, shrinkB=4))
        # The previous month at the same day: the like-for-like comparison.
        ax.scatter([done], [now.loc[done]], s=30, color=COLORS["primary"],
                   zorder=5)
        ax.scatter([done], [prev_at_day], s=30, color=COLORS["accent"], zorder=5)
        ax.annotate(f"{prev.strftime('%b')} at day {done}: {prev_at_day:,}",
                    (done, prev_at_day), textcoords="offset points",
                    xytext=(8, -4), ha="left", va="top", fontsize=fs - 1,
                    color=COLORS["accent"], zorder=6)

        ax.axhline(rec_n, color=COLORS["secondary"], lw=1.0, ls=(0, (5, 4)),
                   zorder=1)
        ax.text(1, rec_n, f"{'Previous record' if passed else 'Record'}: "
                f"{rec_m.strftime('%b %Y')}, {rec_n:,}",
                fontsize=fs - 1.5, color=COLORS["secondary"], ha="left",
                va="bottom")

        ax.set_xlim(1, 31 + {"wide": 3.2, "square": 5.0, "portrait": 5.0}[ratio])
        ax.set_ylim(0, rec_n * 1.24)
        ax.set_xticks([1, 5, 10, 15, 20, 25, 30])
        ax.yaxis.set_major_formatter(thousands_formatter())
        ax.set_axisbelow(True)
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)

        top = {"wide": 0.78, "square": 0.78, "portrait": 0.82}[ratio]
        bottom_m = {"wide": 0.18, "square": 0.16, "portrait": 0.13}[ratio]
        left_m = {"wide": 0.075, "square": 0.105, "portrait": 0.115}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom_m, left=left_m, right=0.965)
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="Volume",
                    title_size={"wide": 26, "square": 19, "portrait": 19}[ratio])

        foot = {"wide": 9.5, "square": 8.0, "portrait": 8.0}[ratio]
        fig.text(0.05, 0.055,
                 "Source: CVE List V5, non-rejected CVEs by UTC publication date, "
                 f"through {asof:%b %-d, %Y} (that day partial).",
                 fontsize=foot, color=COLORS["secondary"], ha="left",
                 va="bottom")

        path = GRAPHS / f"month_pace_{ratio}_{asof:%Y-%m-%d}.png"
        out.append(stamp_and_save(fig, path))
    return out


def _passed_at(rec_n):
    """UTC publication time of the current month's (rec_n + 1)th CVE, or None."""
    pub, asof = _load()
    cur = asof.tz_localize(None).to_period("M")
    x = pub[pub.dt.to_period("M") == cur].sort_values()
    return x.iloc[rec_n] if len(x) > rec_n else None


def stats():
    curves, cur, rec_m, rec_n, asof = _table()
    now, prev = curves[cur], curves[cur - 1]
    day = int(now.index[-1])
    days_left = cur.days_in_month - day
    # The current day is usually partial, so the run rate uses completed days.
    rate = now.loc[day - 1] / (day - 1)
    return {
        "asof": asof,
        "month": str(cur),
        "mtd": int(now.iloc[-1]),
        "through_day": day,
        "prev_month_total": int(prev.iloc[-1]),
        "completed_day": day - 1,
        "mtd_completed": int(now.loc[day - 1]),
        "prev_at_completed_day": int(prev.loc[day - 1]),
        "lead_vs_prev_pct": round(100 * (now.loc[day - 1] / prev.loc[day - 1] - 1), 1),
        "record_month": str(rec_m),
        "record": rec_n,
        "gap_to_record": rec_n - int(now.iloc[-1]),
        # Timestamp of the CVE that took the month past the old record.
        "record_passed_at": _passed_at(rec_n),
        "rate_per_completed_day": round(float(rate), 1),
        "days_left_incl_today": days_left + 1,
    }


if __name__ == "__main__":
    for key, val in stats().items():
        print(f"{key:>24}: {val}")
    for p in render():
        print(p)

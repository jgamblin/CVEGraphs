#!/usr/bin/env python3
"""
GitHub's advisory surge in two panels: how much it published, and whether its
own CVE records kept up.

GitHub's post ("Inside the Advisory Database and what happens when
vulnerability volume breaks records", github.blog) says reviewed output hit a
record 1,560 in May 2026, about five times normal, and that publication still
slipped "to multiple weeks for a meaningful share". Both halves are checked here
against public data, and both are GitHub's own work only.

* Top panel: advisories GitHub reviewed into its database each month, against
  the 2025 average. Roughly 350 a month in 2025, about 1,500 from March to July
  2026, lower in August and September but still around 3x.
* Bottom panel: of the reviewed advisories whose CVE GitHub assigned as a CNA
  (GitHub_M), the share whose CVE record reached CVE List V5 more than 7 days
  after the advisory went out. Normally they publish together. It climbs from
  about 1% to 59% in May and falls back to about 2% by September.

The bottom panel is why the top panel's August dip reads as catch-up rather than
decline: output is not performance, and the one timeliness measure fully inside
GitHub's control recovered while output settled. On the top panel alone, the
drop looked like getting worse (Jerry's read of the first render, 2026-09-28).

Late-share rules:
  * Month is the month GitHub reviewed the advisory.
  * An advisory whose CVE is still not on CVE List V5 more than 7 days after
    review counts as LATE. Its assigner is unknown, but every one of them in 2026
    carries a repository-advisory reference, the GitHub-CNA pattern, so leaving
    them out would flatter the recovery. They are in the denominator too.
  * The CVE List snapshot sets "now" for that test, and reviews after it are
    dropped so the two sources stop on the same day.

Counts use ``github_reviewed_at``. Our May (1,608) sits close to GitHub's 1,560;
by our count March (1,615) edges it, so the record claim stays attributed to
GitHub. Rejected and duplicate reports leave no row, so the top panel is
published output, not the "6,000 decisions a month" GitHub also cites.

Data: processed/ghsa_reviewed.parquet (scripts_precompute_ghsa_reviewed.py)
joined to processed/cvelist_v5.parquet.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.ticker import MultipleLocator, PercentFormatter

from data import load_cvelist
from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
    thousands_formatter,
)

HERE = Path(__file__).resolve().parent
PROCESSED = HERE.parent / "processed"
GRAPHS = HERE.parent / "graphs"

START = pd.Period("2025-01", "M")
BASE_YEAR = 2025
GITHUB_CNA = "GitHub_M"
LATE_DAYS = 7


def _frame():
    gh = pd.read_parquet(PROCESSED / "ghsa_reviewed.parquet")
    # Rejected records are loaded too: a rejected alias is a settled CVE, not a
    # pending one, and without them old rejected IDs pile up as "late".
    cl = load_cvelist(include_rejected=True)[
        ["cve_id", "date_published", "assigner_short_name", "is_rejected"]]
    cl = cl.drop_duplicates("cve_id")
    now = pd.to_datetime(cl["date_published"], utc=True).max()
    gh = gh[gh["reviewed_at"] <= now]
    gh = gh.merge(cl, left_on="cve", right_on="cve_id", how="left")
    gh["period"] = gh["reviewed_at"].dt.tz_localize(None).dt.to_period("M")
    gh = gh[gh["period"] >= START]

    day = pd.Timedelta(days=1)
    wait = (gh["date_published"] - gh["reviewed_at"]) / day
    rejected = gh["is_rejected"].fillna(False).astype(bool)
    pending = gh["cve"].notna() & gh["cve_id"].isna()
    gh["github"] = (((gh["assigner_short_name"] == GITHUB_CNA) & ~rejected)
                    | pending)
    gh["pending"] = pending
    gh["late"] = (wait > LATE_DAYS) | (
        pending & ((now - gh["reviewed_at"]) / day > LATE_DAYS))
    return gh, now


def _monthly(gh):
    m = gh.groupby("period").size()
    base = m[m.index.year == BASE_YEAR].mean()
    g = gh[gh["github"]].groupby("period")
    late = g["late"].mean()
    return m, base, late, g.size()


def render(nvd=None, ratios=DEFAULT_RATIOS):
    gh, now = _frame()
    m, base, late, _ = _monthly(gh)
    last_review = gh["reviewed_at"].max()
    x = np.arange(len(m))
    labels = [p.strftime("%b") + (f"\n{p.year}" if i == 0 or p.month == 1 else "")
              for i, p in enumerate(m.index)]
    labels[-1] = labels[-1].replace(m.index[-1].strftime("%b"),
                                    m.index[-1].strftime("%b") + "*", 1)
    cur = [p.year > BASE_YEAR for p in m.index]
    colors = [COLORS["primary"] if c else COLORS["light"] for c in cur]

    title = "GitHub's Advisory Surge: Output and Catch-Up"
    subtitle = "GitHub Advisory Database and GitHub's own CVE records, by review month"

    out = []
    for ratio in ratios:
        fig, (ax, bx) = plt.subplots(
            2, 1, figsize=figsize_for(ratio), sharex=True,
            gridspec_kw={"height_ratios": [3, 2],
                         "hspace": {"wide": 0.42}.get(ratio, 0.32)})
        fs = {"wide": 11.5, "square": 10, "portrait": 10}[ratio]
        vfs = {"wide": fs - 1, "square": fs - 2.5, "portrait": fs - 2.5}[ratio]
        panel = dict(fontsize=fs, fontweight="bold", color=COLORS["text"],
                     ha="left", va="bottom")

        # ---- top: reviewed advisories -------------------------------------
        ax.bar(x, m.values, width=0.72, color=colors, zorder=3)
        ax.axhline(base, color=COLORS["secondary"], lw=1.1, ls=(0, (5, 4)),
                   zorder=4, alpha=0.8)
        # Parked over May to Sep 2025, the one stretch where every bar sits
        # below the label; at the left edge it ran into the Mar/Apr bars.
        ax.text(3.7, base + 30, f"{BASE_YEAR} average: {base:,.0f}",
                fontsize=fs - 1, fontweight="bold",
                color=COLORS["secondary"], ha="left", va="bottom", zorder=5)
        for i, v in enumerate(m.values):
            if cur[i]:
                ax.text(i, v + 25, f"{v:,}", ha="center", va="bottom",
                        fontsize=vfs, fontweight="bold",
                        color=COLORS["primary"], zorder=5)
        ax.text(-0.5, m.max() * 1.2, "Advisories reviewed per month", **panel)
        ax.set_ylim(0, m.max() * 1.18)
        ax.yaxis.set_major_locator(MultipleLocator(500))
        ax.yaxis.set_major_formatter(thousands_formatter())

        # ---- bottom: share of GitHub's own CVE records a week late ---------
        ly = late.reindex(m.index).to_numpy()
        bx.fill_between(x, ly, color=COLORS["alert"], alpha=0.12, lw=0,
                        zorder=2)
        bx.plot(x, ly, color=COLORS["alert"], lw=2.6, marker="o", ms=4.5,
                zorder=4)
        pk = int(np.nanargmax(ly))
        for i, dy in ((pk, 9), (len(ly) - 1, 9)):
            bx.annotate(f"{ly[i]:.0%}", (x[i], ly[i]), textcoords="offset points",
                        xytext=(0, dy), ha="center", va="bottom",
                        fontsize=fs, fontweight="bold", color=COLORS["alert"],
                        zorder=6)
        bx.text(-0.5, 0.86,
                f"GitHub's CVE record more than {LATE_DAYS} days behind "
                "its advisory", **panel)
        bx.set_ylim(0, 0.84)
        bx.yaxis.set_major_locator(MultipleLocator(0.25))
        bx.yaxis.set_major_formatter(PercentFormatter(1.0, decimals=0))

        for a in (ax, bx):
            a.set_xlim(-0.6, len(m) - 0.4)
            a.tick_params(axis="both", length=0)
            a.set_axisbelow(True)
            a.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)
            a.grid(axis="x", visible=False)
            for side in ("top", "right", "left"):
                a.spines[side].set_visible(False)
        bx.set_xticks(x)
        bx.set_xticklabels(labels, fontsize={"wide": 10.5, "square": 8.5,
                                             "portrait": 8.5}[ratio])

        top = {"wide": 0.69, "square": 0.76, "portrait": 0.80}[ratio]
        bottom_m = {"wide": 0.17, "square": 0.15, "portrait": 0.13}[ratio]
        left_m = {"wide": 0.065, "square": 0.09, "portrait": 0.10}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom_m, left=left_m, right=0.975)
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="CNA Volume",
                    title_size={"wide": 26, "square": 19, "portrait": 19}[ratio])

        foot = {"wide": 9.5, "square": 8.0, "portrait": 8.0}[ratio]
        fig.text(0.05, 0.055,
                 f"*Reviews through {last_review:%b %-d}. A CVE still not public "
                 f"after {LATE_DAYS} days counts as late. Source: GitHub Advisory "
                 "Database, CVE List V5.",
                 fontsize=foot, color=COLORS["secondary"], ha="left",
                 va="bottom")

        path = GRAPHS / f"ghsa_output_{ratio}_{last_review:%Y-%m-%d}.png"
        out.append(stamp_and_save(fig, path))
    return out


def stats():
    gh, now = _frame()
    m, base, late, gn = _monthly(gh)
    last = gh["reviewed_at"].max()
    surge = m["2026-03":"2026-07"]
    p = m.index[-1]
    done = np.busday_count(p.start_time.date(), (last + pd.Timedelta(days=1)).date())
    full = np.busday_count(p.start_time.date(), (p + 1).start_time.date())
    pend = gh[gh["pending"]].groupby("period").size()
    table = pd.DataFrame({"reviewed": m, "x_2025": (m / base).round(2),
                          "github_n": gn, "late_share": late.round(3),
                          "pending_cve": pend}).fillna({"pending_cve": 0})
    return {
        "cvelist_now": now,
        "last_review": last,
        "base_avg": round(base, 1),
        "surge_avg": f"{surge.mean():,.0f} ({surge.mean() / base:.2f}x)",
        "partial_pace": f"{m.iloc[-1]:,} in {done} of {full} weekdays -> "
                        f"{m.iloc[-1] * full / done:,.0f} full-month pace",
        "table": table.to_string(),
    }


if __name__ == "__main__":
    for key, val in stats().items():
        print(f"{key:>14}: {val}")

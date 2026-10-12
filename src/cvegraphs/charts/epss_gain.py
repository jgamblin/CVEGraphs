#!/usr/bin/env python3
"""
EPSS vs CVSS gain curves, one month before the KEV list.

Companion image to epss_report_card, built on Jay Jacobs' feedback that
fixed-threshold bars invite an apples-to-oranges objection: instead, sweep
each scoring system's threshold and plot coverage (share of future KEV
entries caught) against effort (share of all scored CVEs flagged), with
CISA KEV as the outcome variable.

Two panels split by the CVE's age when it was added to KEV, because the
pooled curve hides the finding: on additions under a year old CVSS severity
dominates at every budget, and on the year-plus backlog EPSS dominates every
realistic one. The named policies from the companion chart (CVSS 7.0+/9.0+,
EPSS 0.10+/0.50+) are marked as dots on their curves.

Effort axes: the EPSS curve uses each CVE's stored percentile from its own
KEV-minus-30-days snapshot (so effort is measured on the decision date);
the CVSS curve sweeps the score over today's v3-scored corpus (CNA score,
NVD fallback), which is stable over the window.

Data: processed/epss_report_card.parquet via
cvegraphs.precompute.epss_report_card. Renders one PNG per ratio.
"""

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from cvegraphs.charts.epss_report_card import GRAPHS, _load
from cvegraphs.style import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

DESCRIPTION = "Gain curves: coverage vs effort for EPSS and CVSS against 2026 KEV additions, split by age"

FRESH_DAYS = 365


def _epss_curve(sub):
    """Coverage at each effort level, sweeping the EPSS percentile."""
    efforts = np.linspace(0, 1, 401)
    cov = [(sub.pct_30d >= 1 - e).mean() for e in efforts]
    return efforts, np.array(cov)


def _cvss_curve(sub, corpus_v3):
    """Step curve: sweep the v3 threshold from 10.0 down to 0."""
    thresholds = np.arange(10.0, -0.1, -0.1)
    eff = [(corpus_v3 >= t).mean() for t in thresholds]
    cov = [(sub.v3 >= t).mean() for t in thresholds]
    return np.array(eff), np.array(cov), thresholds


def _dot(ax, x, y, color, label, dx, dy, size, fs, ha="left"):
    ax.scatter([100 * x], [100 * y], s=size, color=color, zorder=5,
               edgecolor="white", linewidth=1.2)
    ax.annotate(label, (100 * x, 100 * y), xytext=(dx, dy),
                textcoords="offset points", fontsize=fs, fontweight="bold",
                color=color, ha=ha, zorder=5)


def render(nvd=None, ratios=DEFAULT_RATIOS):
    """Render the gain curves for each ratio. Returns output paths.

    ``nvd`` is accepted for the registry render signature and ignored.
    """
    df, meta, corpus_v3 = _load()
    year = meta["kev_year"]
    corpus_v3 = corpus_v3.values

    fair = df[df["age_at_kev"] >= 30].dropna(subset=["v3", "pct_30d"])
    cohorts = [
        (fair[fair.age_at_kev < FRESH_DAYS], "Under a Year Old at KEV"),
        (fair[fair.age_at_kev >= FRESH_DAYS], "A Year or Older at KEV"),
    ]

    title = "Coverage vs Effort, One Month Before the KEV List"
    sub = (f"Each curve sweeps its score's threshold over the "
           f"{len(fair)} CVEs added to KEV in {year} after 30+ days "
           "in public")

    out = []
    for ratio in ratios:
        fig = plt.figure(figsize=figsize_for(ratio))
        stacked = ratio != "wide"
        top = {"wide": 0.72, "square": 0.745, "portrait": 0.775}[ratio]
        bottom = {"wide": 0.26, "square": 0.265, "portrait": 0.24}[ratio]
        if stacked:
            axes = fig.subplots(2, 1, gridspec_kw=dict(
                top=top, bottom=bottom, left=0.13, right=0.955, hspace=0.52))
        else:
            axes = fig.subplots(1, 2, sharey=True, gridspec_kw=dict(
                top=top, bottom=bottom, left=0.09, right=0.965, wspace=0.12))

        lab = {"wide": 12, "square": 10.5, "portrait": 11}[ratio]
        dot_fs = {"wide": 10.5, "square": 9, "portrait": 9.5}[ratio]
        dot_sz = {"wide": 55, "square": 40, "portrait": 45}[ratio]

        for ax, (cohort, name) in zip(axes, cohorts):
            n = len(cohort)
            e_eff, e_cov = _epss_curve(cohort)
            c_eff, c_cov, c_thr = _cvss_curve(cohort, corpus_v3)

            ax.plot([0, 100], [0, 100], linestyle="--", linewidth=1,
                    color=COLORS["neutral"], zorder=2)
            ax.plot(100 * c_eff, 100 * c_cov, drawstyle="steps-post",
                    color=COLORS["light"], linewidth=2.6, zorder=3,
                    solid_capstyle="round")
            ax.plot(100 * e_eff, 100 * e_cov, color=COLORS["primary"],
                    linewidth=2.6, zorder=4, solid_capstyle="round")

            # named policies as dots on their own curves, each labeled with
            # the absolute remediation workload its effort share implies
            # (the percent axis alone hides how many CVEs a policy flags).
            # EPSS dots hug the left edge, so their labels sit to the right.
            n_epss = meta["epss_corpus_rows"]
            # the 9.0 label wraps to two lines so it stays clear of the
            # curve's next step up
            for t, sep, dx, dy in [(9.0, "\n", 6, -26), (7.0, " · ", 6, -13)]:
                share = (corpus_v3 >= t).mean()
                _dot(ax, share, (cohort.v3 >= t).mean(), COLORS["light"],
                     f"CVSS {t:.1f}+{sep}"
                     f"{share * len(corpus_v3) / 1000:,.0f}K CVEs",
                     dx, dy, dot_sz, dot_fs)
            for thr, key, dlabel, dx, dy in [
                    (0.10, "0.1", "EPSS 0.10+", 10, -16),
                    (0.50, "0.5", "EPSS 0.50+", 9, -14)]:
                share = meta["epss_workload_share"][key]
                _dot(ax, share, (cohort.epss_30d >= thr).mean(),
                     COLORS["primary"],
                     f"{dlabel} · {share * n_epss / 1000:,.0f}K CVEs",
                     dx, dy, dot_sz, dot_fs)

            ax.set_xlim(0, 100)
            ax.set_ylim(0, 102)
            ax.set_title(f"{name} ({n} CVEs)", loc="left", fontsize=lab,
                         fontweight="bold", color=COLORS["secondary"],
                         pad=10)
            ax.grid(color=COLORS["grid"], linewidth=0.6, alpha=0.8)
            ax.set_axisbelow(True)
            ax.set_xticks([0, 25, 50, 75, 100])
            ax.set_yticks([0, 25, 50, 75, 100])
            ax.tick_params(labelsize=lab - 1.5)
            ax.xaxis.set_major_formatter(lambda v, _: f"{v:.0f}%")
            ax.yaxis.set_major_formatter(lambda v, _: f"{v:.0f}%")
        # x-axis label: both panels in wide, bottom panel only when stacked
        for ax in (axes if not stacked else [axes[1]]):
            ax.set_xlabel("Share of All Scored CVEs Flagged (Effort)",
                          fontsize=lab - 1, color=COLORS["secondary"])
        first = axes[0]
        first.set_ylabel("Future KEV Entries\nCaught (Coverage)",
                         fontsize=lab - 1, color=COLORS["secondary"])
        if stacked:
            axes[1].set_ylabel("Future KEV Entries\nCaught (Coverage)",
                               fontsize=lab - 1, color=COLORS["secondary"])

        # curve key, drawn as colored text in the first panel's whitespace
        first.text(97, 14, "EPSS at KEV−30 days", ha="right",
                   fontsize=lab, fontweight="bold", color=COLORS["primary"])
        first.text(97, 5, "CVSS v3", ha="right", fontsize=lab,
                   fontweight="bold", color=COLORS["light"])
        first.text(97, 23, "random", ha="right", fontsize=lab - 2,
                   color=COLORS["neutral"])

        t1 = {"wide": 25, "square": 17, "portrait": 18.5}[ratio]
        wsub = sub if ratio == "wide" else sub.replace("threshold over ",
                                                       "threshold over\n")
        draw_header(fig, title, wsub, ratio, eyebrow_suffix="Exploitation",
                    title_size=t1)

        foot_size = {"wide": 9.5, "square": 8, "portrait": 8}[ratio]
        eff_line = (
            "Every 10% of effort is roughly "
            f"{meta['epss_corpus_rows'] / 10_000:,.0f}K CVEs to remediate "
            f"for EPSS ({meta['epss_corpus_rows'] / 1000:,.0f}K scored) and "
            f"{len(corpus_v3) / 10_000:,.0f}K for CVSS "
            f"({len(corpus_v3) / 1000:,.0f}K scored)."
        )
        if ratio == "wide":
            foot = (
                "EPSS effort uses each CVE's percentile in its own snapshot "
                "30 days before its KEV date; CVSS sweeps the v3 score over "
                "today's scored corpus (CNA score, NVD fallback).\n"
                f"{eff_line} Dots mark the fixed policies from the "
                "companion chart.\n"
                f"Excludes the {meta['within_1d'] + meta['under_30d']} of "
                f"{meta['total_added']} additions public under 30 days "
                f"({meta['within_1d']} under a day), where no score had "
                "time to help.  "
                "Source: CISA KEV · FIRST EPSS · CVE List V5 / NVD."
            )
        else:
            foot = (
                "EPSS effort uses each CVE's percentile in its own snapshot "
                "30 days before its KEV date;\n"
                "CVSS sweeps the v3 score over today's scored corpus (CNA "
                "score, NVD fallback).\n"
                f"{eff_line}\n"
                "Dots mark the fixed policies from the companion chart. "
                "Excludes the "
                f"{meta['within_1d'] + meta['under_30d']} of "
                f"{meta['total_added']} additions public\n"
                f"under 30 days ({meta['within_1d']} under a day), where no "
                "score had time to help. "
                "Source: CISA KEV · FIRST EPSS · CVE List V5 / NVD."
            )
        fig.text(0.05, 0.02, foot, fontsize=foot_size,
                 color=COLORS["secondary"], ha="left", va="bottom",
                 linespacing=1.5)

        path = GRAPHS / (f"epss_gain_{ratio}_"
                         f"{pd.Timestamp.today().strftime('%Y-%m-%d')}.png")
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

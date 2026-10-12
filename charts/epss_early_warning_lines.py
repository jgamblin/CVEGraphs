#!/usr/bin/env python3
"""
EPSS Early Warning, per-CVE paths — one line per CVE into its KEV listing.

The line-graph companion to ``epss_early_warning``: same fixed cohort, same six
lookbacks, but every CVE draws its own faint path so the reader can see that the
individual trajectories are essentially horizontal. The cohort average rides on
top in navy.

Renders either metric, selected by ``render(metric=...)``:

* ``"epss"`` — the raw probability, on a LOG y-axis. Scores in this cohort span
  0.0001 to 0.94 and 20 of the 62 sit entirely below 0.01 at every lookback; on
  a linear axis those 20 collapse onto the baseline and the chart silently drops
  a third of its own sample. The cohort is bimodal (20 always under 0.01, 19
  always over 0.50), so the arithmetic mean parks in the sparse valley between
  the clumps. It is plotted because it is the honest summary of total expected
  exploitation probability and it is impressively flat, with the median drawn
  alongside and the footnote saying both are weak summaries of a two-clump
  cohort.
* ``"percentile"`` — the CVE's rank among all scored CVEs, as a percentage, on a
  LINEAR axis. No log scale needed, and it survives a model retrain in a way the
  raw score does not, so it is the robustness check on the flatness claim. It
  also reframes the finding: in RELATIVE terms EPSS already ranked this cohort
  very highly before CISA acted (median 86th percentile 90 days out). It is the
  absolute probability that stayed low, not the rank.

Data: processed/epss_early_warning.parquet + _meta.json from
scripts_precompute_epss_early_warning.py.

Renders one PNG per aspect ratio into ``graphs/``.
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "processed"
GRAPHS = ROOT / "graphs"

# A true light grey for the per-CVE paths: the navy ramp's palest stop still
# reads as blue and competes with the average line.
LINE_GREY = "#c2c7cc"

METRICS = {
    "epss": {
        "col": "epss",
        "mult": 1.0,
        "scale": "log",
        "ylim": (5e-5, 1.35),          # floor below the cohort min (9e-05)
        "yticks": [1e-4, 1e-3, 1e-2, 1e-1, 1.0],
        "ylabels": ["0.0001", "0.001", "0.01", "0.10", "1.0"],
        "ylabel": "EPSS score (log scale)",
        "fmt": lambda v: f"{v:.2f}",
        "slug": "epss_early_warning_lines",
        "sub_tail": "one grey line per CVE, cohort average in navy",
    },
    "percentile": {
        "col": "percentile",
        "mult": 100.0,
        "scale": "linear",
        "ylim": (0, 112),
        "yticks": [0, 20, 40, 60, 80, 100],
        "ylabels": ["0%", "20%", "40%", "60%", "80%", "100%"],
        "ylabel": "EPSS percentile",
        "fmt": lambda v: f"{v:.0f}%",
        "slug": "epss_early_warning_pct",
        "sub_tail": "EPSS percentile, one grey line per CVE, average in navy",
    },
}


def _load():
    df = pd.read_parquet(PROCESSED / "epss_early_warning.parquet")
    meta = json.loads((PROCESSED / "epss_early_warning_meta.json").read_text())
    return df, meta


def _foot_epss(ratio, meta, n, mv, wide):
    """Footnote for the raw-score render: the bimodality warning is the point."""
    always_low = int((wide < 0.01).all(axis=1).sum())
    always_high = int((wide > 0.50).all(axis=1).sum())
    if ratio == "wide":
        return (
            f"Of {meta['total_added']} CVEs added to KEV in {meta['kev_year']}, "
            f"{meta['same_day']} were added the same day the CVE went public "
            f"and {meta['within_1d']} within a day; {meta['under_min_age']} had "
            "under 90 days of public history.\n"
            f"The {n} shown are the same CVEs at every lookback. "
            f"{mv['flat_05']} of {mv['pairs']} moved under 0.05 over the full "
            f"90 days, {mv['crossed_10_up']} crossed 0.10 upward, "
            f"{mv['never_10']} never reached 0.10.\n"
            f"The cohort splits in two ({always_low} always under 0.01, "
            f"{always_high} always over 0.50), so the mean sits between the "
            "clumps and the median swings\n"
            "within the sparse middle; read the grey lines. Log scale. Scores "
            "read from production EPSS snapshots on the exact lookback dates.\n"
            "Source: CISA KEV · FIRST EPSS · CVE List V5."
        )
    return (
        f"Of {meta['total_added']} CVEs added to KEV in {meta['kev_year']}, "
        f"{meta['same_day']} were added the same day the CVE went public and "
        f"{meta['within_1d']} within a day;\n"
        f"{meta['under_min_age']} had under 90 days of public history. The {n} "
        "shown are the same CVEs at every lookback.\n"
        f"{mv['flat_05']} of {mv['pairs']} moved under 0.05 over the full 90 "
        f"days, {mv['crossed_10_up']} crossed 0.10 upward, {mv['never_10']} "
        "never reached 0.10.\n"
        f"The cohort splits in two ({always_low} always under 0.01, "
        f"{always_high} always over 0.50), so the mean sits between the clumps\n"
        "and the median swings within the sparse middle; read the grey lines. "
        "Log scale.\n"
        "Scores read from production snapshots on the exact lookback dates.\n"
        "Source: CISA KEV · FIRST EPSS · CVE List V5."
    )


def _foot_pct(ratio, meta, n, mv, wide):
    """Footnote for the percentile render: rank was already high going in."""
    hz = meta["horizons"]
    first, last = wide[hz[0]], wide[hz[-1]]
    d = last - first
    flat = int((d.abs() <= 5).sum())
    top10_first = (first >= 90).mean() * 100
    top10_last = (last >= 90).mean() * 100
    med_first, med_last = first.median(), last.median()
    if ratio == "wide":
        return (
            f"Of {meta['total_added']} CVEs added to KEV in {meta['kev_year']}, "
            f"{meta['same_day']} were added the same day the CVE went public "
            f"and {meta['within_1d']} within a day; {meta['under_min_age']} had "
            "under 90 days of public history.\n"
            f"The {n} shown are the same CVEs at every lookback. {flat} of {n} "
            "moved less than 5 percentile points over the full 90 days, and the "
            "median percentile sat at\n"
            f"{med_first:.0f}% 90 days out against {med_last:.0f}% the "
            "day before; the share in the top decile goes "
            f"{top10_first:.0f}% to {top10_last:.0f}%.\n"
            "Percentile is each CVE's rank among all scored CVEs, so unlike the "
            "raw score a model retrain does not move it: in relative terms EPSS "
            "had already\n"
            "ranked this cohort highly before CISA acted. Scores read on the "
            "exact lookback dates. Source: CISA KEV · FIRST EPSS · CVE List V5."
        )
    return (
        f"Of {meta['total_added']} CVEs added to KEV in {meta['kev_year']}, "
        f"{meta['same_day']} were added the same day the CVE went public and "
        f"{meta['within_1d']} within a day;\n"
        f"{meta['under_min_age']} had under 90 days of public history. The {n} "
        "shown are the same CVEs at every lookback.\n"
        f"{flat} of {n} moved less than 5 percentile points over the full 90 "
        f"days; the median percentile sat at {med_first:.0f}% 90 days out\n"
        f"against {med_last:.0f}% the day before, and the share in the top "
        f"decile goes {top10_first:.0f}% to {top10_last:.0f}%.\n"
        "Percentile is each CVE's rank among all scored CVEs, so unlike the raw "
        "score a model retrain does not\n"
        "move it: in relative terms EPSS already ranked this cohort highly "
        "before CISA acted.\n"
        "Scores read from production snapshots on the exact lookback dates.\n"
        "Source: CISA KEV · FIRST EPSS · CVE List V5."
    )


def render(nvd=None, ratios=DEFAULT_RATIOS, metric="epss"):
    """Render the per-CVE path chart for each ratio. Returns output paths.

    ``nvd`` is accepted for the shared make.py dispatch signature and ignored.
    ``metric`` picks the raw score (log axis) or the percentile (linear axis);
    see the module docstring for why each needs its own scale.
    """
    cfg = METRICS[metric]
    df, meta = _load()
    hz = meta["horizons"]                     # [90, 60, 30, 15, 7, 1]
    n = meta["cohort"]
    year = meta["kev_year"]
    mv = meta["movement"]

    # wide[cve_id][horizon], columns ordered 90 .. 1 (left to right)
    wide = df.pivot_table(index="cve_id", columns="horizon",
                          values=cfg["col"])[hz] * cfg["mult"]
    xs = list(range(len(hz)))
    mean = [wide[h].mean() for h in hz]
    median = [wide[h].median() for h in hz]

    title = "Every CVE's EPSS Path Into a KEV Listing"
    sub = (f"{n} CVEs added to KEV in {year} after 90+ days in public: "
           + cfg["sub_tail"])
    foot_fn = _foot_epss if metric == "epss" else _foot_pct

    out = []
    for ratio in ratios:
        fig = plt.figure(figsize=figsize_for(ratio))
        top = {"wide": 0.695, "square": 0.655, "portrait": 0.700}[ratio]
        bottom = {"wide": 0.360, "square": 0.375, "portrait": 0.320}[ratio]
        left = {"wide": 0.105, "square": 0.145, "portrait": 0.140}[ratio]
        ax = fig.subplots(gridspec_kw=dict(top=top, bottom=bottom, left=left,
                                           right=0.965))

        lab = {"wide": 12, "square": 10.5, "portrait": 11}[ratio]

        # ---- one faint path per CVE -----------------------------------------
        for cve in wide.index:
            ax.plot(xs, wide.loc[cve, hz].to_numpy(), color=LINE_GREY,
                    lw={"wide": 1.0, "square": 0.9, "portrait": 0.95}[ratio],
                    alpha=0.75, solid_capstyle="round", zorder=2)

        # ---- cohort median, then mean on top --------------------------------
        ax.plot(xs, median, color=COLORS["accent"], lw=2.0, ls=(0, (5, 2.5)),
                zorder=4)
        ax.plot(xs, mean, color=COLORS["primary"],
                lw={"wide": 3.2, "square": 2.8, "portrait": 3.0}[ratio],
                marker="o", markersize={"wide": 7, "square": 6,
                                        "portrait": 6.5}[ratio],
                markerfacecolor="white",
                markeredgewidth={"wide": 2.6, "square": 2.2,
                                 "portrait": 2.4}[ratio],
                markeredgecolor=COLORS["primary"], zorder=6)

        # Endpoint values on the average line. A white bbox and a short offset
        # keep them attached to the navy line: on a log axis a larger offset
        # drifts far enough to read against the gridline above instead.
        for x, v in ((xs[0], mean[0]), (xs[-1], mean[-1])):
            ax.annotate(cfg["fmt"](v), (x, v), xytext=(0, 10),
                        textcoords="offset points", ha="center",
                        fontsize=lab, fontweight="bold",
                        color=COLORS["primary"], zorder=7,
                        bbox=dict(boxstyle="round,pad=0.18", facecolor="white",
                                  edgecolor="none", alpha=0.9))

        ax.set_yscale(cfg["scale"])
        ax.set_ylim(*cfg["ylim"])
        ax.set_xlim(-0.35, len(hz) - 0.65)
        ax.set_yticks(cfg["yticks"])
        ax.set_yticklabels(cfg["ylabels"], fontsize=lab - 1.5)
        ax.minorticks_off()
        ax.set_xticks(xs)
        ax.set_xticklabels([str(h) for h in hz], fontsize=lab,
                           fontweight="bold")
        ax.set_xlabel("Days before the CVE was added to KEV",
                      fontsize=lab, fontweight="bold")
        ax.set_ylabel(cfg["ylabel"], fontsize=lab, fontweight="bold")
        ax.grid(axis="y", color=COLORS["grid"], linewidth=0.6, alpha=0.8)
        ax.grid(axis="x", visible=False)
        ax.set_axisbelow(True)
        ax.spines["left"].set_visible(False)
        ax.tick_params(axis="both", length=0)

        # ---- legend ---------------------------------------------------------
        handles = [
            plt.Line2D([0], [0], color=LINE_GREY, lw=1.6),
            plt.Line2D([0], [0], color=COLORS["primary"], lw=3.0, marker="o",
                       markersize=6, markerfacecolor="white",
                       markeredgewidth=2.4,
                       markeredgecolor=COLORS["primary"]),
            plt.Line2D([0], [0], color=COLORS["accent"], lw=2.0,
                       ls=(0, (5, 2.5))),
        ]
        labels = [f"Individual CVEs ({n})", "Cohort average (mean)",
                  "Cohort median"]
        ncol = {"wide": 3, "square": 2, "portrait": 2}[ratio]
        leg_y = {"wide": 0.775, "square": 0.745, "portrait": 0.780}[ratio]
        ax.legend(handles, labels, loc="upper center",
                  bbox_to_anchor=(0.525, leg_y), bbox_transform=fig.transFigure,
                  ncol=ncol, frameon=False, fontsize=lab - 0.5,
                  handlelength=2.4, columnspacing=1.6, labelspacing=0.7)

        t1 = {"wide": 26, "square": 19, "portrait": 20}[ratio]
        wsub = sub if ratio == "wide" else sub.replace(": ", ":\n")
        draw_header(fig, title, wsub, ratio, eyebrow_suffix="Exploitation",
                    title_size=t1)

        foot_size = {"wide": 9.5, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.035, foot_fn(ratio, meta, n, mv, wide),
                 fontsize=foot_size, color=COLORS["secondary"], ha="left",
                 va="bottom", linespacing=1.5)

        path = GRAPHS / (f"{cfg['slug']}_{ratio}_"
                         f"{pd.Timestamp.today().strftime('%Y-%m-%d')}.png")
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

#!/usr/bin/env python3
"""
EPSS around the KEV listing — 60 days before to 60 days after.

The sequel to ``epss_early_warning_lines``, drawn the same way (one faint grey
path per CVE, cohort mean in navy, log y-axis) but with the window extended past
day zero. The before half repeats the earlier finding: flat. The after half is
the point of the chart, and it is a step, not a ramp.

Day zero is the KEV date itself, so the score plotted there is that morning's
production run, before the listing could reach the model. The jump lands at +1,
the next daily run.

What the timing licenses, and what it does not: a one-day discontinuity
synchronized to CISA's publication calendar shows the score REACTING to the
listing rather than anticipating it, because real-world exploitation evidence
does not arrive as a step function on someone else's schedule. It does NOT by
itself establish that KEV membership is an EPSS input. That would need FIRST's
current v5 feature list, so both the on-image footnote and the caption stop at
the reaction claim and flag the mechanism as a separate question.

Data: processed/epss_kev_window.parquet + _meta.json from
cvegraphs.precompute.epss_kev_window.

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

DESCRIPTION = "Spaghetti lines: EPSS from 60 days before to 60 days after the KEV listing; the score steps at +1"

GRAPHS = OUTPUT

LINE_GREY = "#c2c7cc"
POST_TINT = "#eef1f4"      # faint panel behind the post-listing half

METRICS = {
    "epss": {
        "col": "epss",
        "mult": 1.0,
        "scale": "log",
        "ylim": (5e-5, 1.9),
        "yticks": [1e-4, 1e-3, 1e-2, 1e-1, 1.0],
        "ylabels": ["0.0001", "0.001", "0.01", "0.10", "1.0"],
        "ylabel": "EPSS score (log scale)",
        "fmt": lambda v: f"{v:.2f}",
        "tag_y": 1.6e-4,
        "bottom": {"wide": 0.275, "square": 0.315, "portrait": 0.265},
        "slug": "epss_kev_window",
        "title": "EPSS Around the KEV Listing",
        "title_size": {"wide": 26, "square": 19, "portrait": 20},
        "sub_tail": "EPSS score before and after the listing",
        "ylabel_tc": "EPSS Score (Log Scale)",
    },
    "percentile": {
        "col": "percentile",
        "mult": 100.0,
        "scale": "linear",
        "ylim": (0, 104),
        "yticks": [0, 20, 40, 60, 80, 100],
        "ylabels": ["0%", "20%", "40%", "60%", "80%", "100%"],
        "ylabel": "EPSS percentile",
        "fmt": lambda v: f"{v:.0f}%",
        "tag_y": 5,
        "bottom": {"wide": 0.275, "square": 0.315, "portrait": 0.265},
        "slug": "epss_kev_window_pct",
        "title": "EPSS Percentile Around the KEV Listing",
        "title_size": {"wide": 23, "square": 17, "portrait": 18},
        "sub_tail": "EPSS percentile, the rank among all scored CVEs",
        "ylabel_tc": "EPSS Percentile",
    },
}


def _load():
    df = pd.read_parquet(PROCESSED / "epss_kev_window.parquet")
    meta = json.loads((PROCESSED / "epss_kev_window_meta.json").read_text())
    return df, meta



def _foot(ratio, meta, n, wide, metric):
    """Three-line footnote: cohort, the day-0/+1 timing caveat, source.

    Deliberately does NOT cross-reference the before-only chart: that one has
    not shipped, so on a standalone image it is an orphan reference. It also
    does not repeat the post body; the numbers here are the ones a screenshot
    must carry on its own.
    """
    if metric == "percentile":
        pre, post = wide[0].median(), wide[1].median()
        step = (f"median percentile {pre:.0f}% to {post:.0f}%, top decile "
                f"{(wide[0] >= 90).mean() * 100:.0f}% to "
                f"{(wide[1] >= 90).mean() * 100:.0f}%")
    else:
        pre, post = wide[0].median(), wide[1].median()
        step = (f"median EPSS {pre:.2f} to {post:.2f}, share at or above 0.10 "
                f"{(wide[0] >= 0.10).mean() * 100:.0f}% to "
                f"{(wide[1] >= 0.10).mean() * 100:.0f}%")
    cohort = (f"The {n} shown are the {meta['kev_year']} KEV additions with 60 "
              "days of public history before the listing and 60 days of scores "
              f"after it, so they fall between {meta['kev_date_min']} and "
              f"{meta['kev_date_max']}.")
    timing = ("Day 0 is the KEV date, scored that morning; the move lands at "
              f"+1, the next daily run: {step}. A one-day step on CISA's "
              "publication calendar means the score is reacting to the "
              "listing, not anticipating it.")
    src = "Source: CISA KEV · FIRST EPSS · CVE List V5."
    if ratio == "wide":
        return (
            f"{cohort}\n"
            "Day 0 is the KEV date, scored that morning; the move lands at +1, "
            f"the next daily run: {step}.\n"
            "A one-day step on CISA's publication calendar means the score is "
            f"reacting to the listing, not anticipating it. {src}"
        )
    # narrow ratios: same three ideas, hand-wrapped
    return (
        f"The {n} shown are the {meta['kev_year']} KEV additions with 60 days "
        "of public history before the\n"
        "listing and 60 days of scores after it, so they fall between "
        f"{meta['kev_date_min']} and {meta['kev_date_max']}.\n"
        "Day 0 is the KEV date, scored that morning; the move lands at +1, the "
        f"next daily run:\n{step}.\n"
        "A one-day step on CISA's publication calendar means the score is "
        "reacting to the\n"
        f"listing, not anticipating it. {src}"
    )


def render(nvd=None, ratios=DEFAULT_RATIOS, metric="epss"):
    """Render the before/after window for each ratio. Returns output paths.

    ``nvd`` is accepted for the shared registry render signature and ignored.
    ``metric`` picks the raw score (log axis) or the percentile (linear axis).
    Both are derived from the parquet rather than the meta summary so the two
    metrics take one code path.
    """
    cfg = METRICS[metric]
    df, meta = _load()
    offs = meta["offsets"]
    n = meta["cohort"]
    year = meta["kev_year"]

    wide = df.pivot_table(index="cve_id", columns="offset",
                          values=cfg["col"])[offs] * cfg["mult"]
    xs = list(range(len(offs)))
    zero = offs.index(0)
    mean = [wide[h].mean() for h in offs]
    median = [wide[h].median() for h in offs]

    # Factual heading per house rule: it states what the chart shows, the
    # argument lives in the post copy. The old causal title also argued the
    # OPPOSITE thesis from the copy, and on LinkedIn the image travels alone.
    title = cfg["title"]
    # "61 CVEs added to KEV in 2026" reads standalone as though 61 were added
    # all year; 182 were. Name both numbers.
    sub = (f"{n} of the {meta['total_added']} CVEs added to KEV in {year} with "
           "a full 60-day window either side: " + cfg["sub_tail"])

    out = []
    for ratio in ratios:
        fig = plt.figure(figsize=figsize_for(ratio))
        top = {"wide": 0.695, "square": 0.655, "portrait": 0.700}[ratio]
        bottom = cfg["bottom"][ratio]
        left = {"wide": 0.105, "square": 0.145, "portrait": 0.140}[ratio]
        ax = fig.subplots(gridspec_kw=dict(top=top, bottom=bottom, left=left,
                                           right=0.965))

        lab = {"wide": 12, "square": 10.5, "portrait": 11}[ratio]

        # ---- post-listing panel + the day-zero rule -------------------------
        # Starts at zero + 0.5, not zero: the day-0 reading is that morning's
        # score, before the listing could reach the model, so it must not sit
        # inside a band labelled "after".
        ax.axvspan(zero + 0.5, len(offs) - 0.65, color=POST_TINT, zorder=0)
        ax.axvline(zero + 0.5, color=COLORS["neutral"], lw=1.3, ls=(0, (4, 3)),
                   alpha=0.9, zorder=3)

        # ---- top-decile reference (percentile render only) ------------------
        # Every headline number in the copy is a top-decile count, so the
        # threshold is drawn. Kept light grey rather than an alert colour: it is
        # a reference gridline, not a warning.
        if metric == "percentile":
            ax.axhline(90, color=COLORS["neutral"], lw=1.0, ls=(0, (2, 3)),
                       alpha=0.75, zorder=1)
            ax.annotate("Top Decile", (len(offs) - 0.72, 90), xytext=(0, 4),
                        textcoords="offset points", ha="right", va="bottom",
                        fontsize=lab - 2.5, color=COLORS["secondary"],
                        zorder=5)

        # ---- one faint path per CVE -----------------------------------------
        for cve in wide.index:
            ax.plot(xs, wide.loc[cve, offs].to_numpy(), color=LINE_GREY,
                    lw={"wide": 1.0, "square": 0.9, "portrait": 0.95}[ratio],
                    alpha=0.35, solid_capstyle="round", zorder=2)

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

        # Mean either side of the listing: the step is the story. Offset the two
        # labels in opposite directions so they clear each other and the rule.
        # Label BOTH summary lines either side of the listing. The post copy
        # leads on the median, so a chart that labels only the mean sends the
        # reader hunting for a number that is not drawn. Mean labels sit below
        # their line and median labels above theirs, so neither lands on the
        # other series.
        # Anchored at the LEFT edge and at +1, not at day 0: the post copy leads
        # on where the cohort already sat 60 days out, so that value has to be
        # readable on the image. The day-0 to +1 step numbers live in the
        # footnote, and the line shape shows the discontinuity.
        for x, dx, ha in ((0, 8, "left"), (zero + 1, 8, "left")):
            ax.annotate(f"Mean {cfg['fmt'](mean[x])}", (x, mean[x]),
                        xytext=(dx, -17), textcoords="offset points", ha=ha,
                        fontsize=lab - 0.5, fontweight="bold",
                        color=COLORS["primary"], zorder=7,
                        bbox=dict(boxstyle="round,pad=0.18",
                                  facecolor=POST_TINT, edgecolor="none",
                                  alpha=0.95))
            ax.annotate(f"Median {cfg['fmt'](median[x])}", (x, median[x]),
                        xytext=(dx, 9), textcoords="offset points", ha=ha,
                        fontsize=lab - 0.5, fontweight="bold",
                        color=COLORS["accent"], zorder=7,
                        bbox=dict(boxstyle="round,pad=0.18",
                                  facecolor=POST_TINT, edgecolor="none",
                                  alpha=0.95))

        # Names the tinted half, parked at its far edge: the mean rides high on
        # a log axis, so anywhere near the rule collides with the day-0 or +1
        # value labels.
        ax.annotate("After the KEV Listing", (len(offs) - 0.75, cfg["tag_y"]),
                    ha="right", va="bottom", fontsize=lab - 1, fontweight="bold",
                    color=COLORS["secondary"], zorder=7,
                    bbox=dict(boxstyle="round,pad=0.22", facecolor="white",
                              edgecolor="none", alpha=0.95))

        ax.set_yscale(cfg["scale"])
        ax.set_ylim(*cfg["ylim"])
        ax.set_xlim(-0.35, len(offs) - 0.65)
        ax.set_yticks(cfg["yticks"])
        ax.set_yticklabels(cfg["ylabels"], fontsize=lab - 1.5)
        ax.minorticks_off()
        ax.set_xticks(xs)
        ax.set_xticklabels([("0" if h == 0 else f"{h:+d}") for h in offs],
                           fontsize=lab - 1.5, fontweight="bold")
        ax.set_xlabel("Days From the KEV Listing Date "
                      "(Sampled Checkpoints, Not to Scale)",
                      fontsize=lab, fontweight="bold")
        ax.set_ylabel(cfg["ylabel_tc"], fontsize=lab, fontweight="bold")
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
        labels = [f"Individual CVEs ({n})", "Cohort Mean", "Cohort Median"]
        ncol = {"wide": 3, "square": 2, "portrait": 2}[ratio]
        leg_y = {"wide": 0.775, "square": 0.745, "portrait": 0.780}[ratio]
        ax.legend(handles, labels, loc="upper center",
                  bbox_to_anchor=(0.525, leg_y), bbox_transform=fig.transFigure,
                  ncol=ncol, frameon=False, fontsize=lab - 0.5,
                  handlelength=2.4, columnspacing=1.6, labelspacing=0.7)

        t1 = cfg["title_size"][ratio]
        wsub = sub if ratio == "wide" else sub.replace(": ", ":\n")
        draw_header(fig, title, wsub, ratio, eyebrow_suffix="Exploitation",
                    title_size=t1)

        # ---- footnote -------------------------------------------------------
        foot_size = {"wide": 9.5, "square": 8, "portrait": 8}[ratio]
        foot = _foot(ratio, meta, n, wide, metric)
        fig.text(0.05, 0.035, foot, fontsize=foot_size,
                 color=COLORS["secondary"], ha="left", va="bottom",
                 linespacing=1.5)

        path = GRAPHS / (f"{cfg['slug']}_{ratio}_"
                         f"{pd.Timestamp.today().strftime('%Y-%m-%d')}.png")
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

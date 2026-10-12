#!/usr/bin/env python3
"""
Agreement plot — same CVE, two official CVSS v3 scores.

Every CVE published this year that carries a v3 score from its OWNING CNA and
a second official score from NVD becomes one dot: x = the CNA's score,
y = NVD's. Perfect agreement is the diagonal. Dots are sized by how many CVEs
share that exact score pair (scores are quantized to 0.1, so pairs repeat a
lot), and colored by whether the two scores land in the same severity band.
CISA-ADP second scores exist in the pair table but are excluded here: 90%
duplicate the CNA's score exactly, so they are enrichment, not a re-score.

This is the missing cell in the scoring series: cna_spread compared different
bugs across CNAs, scorer_divergence compared versions within one scorer; this
holds the bug constant and varies only the scorer.

Data: processed/score_pairs.parquet (scripts_precompute_score_pairs.py).
Placeholder 0.0 scores (all-None vectors, ~19 records) are excluded: they
encode "no impact assessed", not an assessment.

Renders one PNG per aspect ratio into ``graphs/``.
"""

from pathlib import Path

import matplotlib.patheffects as pe
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
PAIRS = Path(__file__).resolve().parent.parent / "processed" / "score_pairs.parquet"
NVD_CVES = Path(__file__).resolve().parent.parent / "processed" / "nvd_cves.parquet"

BAND_EDGES = [4.0, 7.0, 9.0]  # Low <4, Medium 4-6.9, High 7-8.9, Critical 9+
BAND_NAMES = ["Low", "Medium", "High", "Critical"]


def _band(scores):
    return pd.cut(scores, [0, 3.95, 6.95, 8.95, 10.0], labels=BAND_NAMES)


def _load():
    """NVD pairs only. CISA-ADP second scores are NOT an independent opinion:
    90% of them duplicate the CNA's score exactly (the ADP enriches records
    that lack data rather than re-scoring), so including them would dilute a
    chart about disagreement with rows that were never a second assessment.
    The echo rate is recomputed here and surfaced in the footnote."""
    df = pd.read_parquet(PAIRS)
    adp = df[df["adp_score"].notna() & df["nvd_score"].isna()
             & (df["cna_score"] > 0) & (df["adp_score"] > 0)]
    adp_echo = (adp["adp_score"] == adp["cna_score"]).mean() if len(adp) else 0.0
    df = df[df["nvd_score"].notna()
            & (df["cna_score"] > 0) & (df["nvd_score"] > 0)].copy()
    df["second"] = df["nvd_score"]
    df["same_band"] = (
        _band(df["cna_score"]).astype(str) == _band(df["second"]).astype(str)
    )
    df.attrs["n_adp"] = len(adp)
    df.attrs["adp_echo"] = adp_echo
    # Selection-bias disclosure for the footnote: pairs exist only where NVD
    # re-scored, a minority slice of the year's v3-scored CVEs.
    year = int(df["year"].iloc[0])
    nvd = pd.read_parquet(NVD_CVES, columns=["year", "cvss_v3", "is_rejected"])
    scored = ((nvd["year"] == year) & (nvd["is_rejected"] != True)
              & nvd["cvss_v3"].notna()).sum()
    df.attrs["coverage"] = len(df) / scored if scored else 0.0
    return df


def _stats(df):
    n = len(df)
    diff = df["second"] - df["cna_score"]
    crit_one = int((( _band(df["cna_score"]) == "Critical")
                    ^ (_band(df["second"]) == "Critical")).sum())
    return {
        "n": n,
        "year": int(df["year"].iloc[0]),
        "exact": (diff == 0).mean(),
        "flip": (~df["same_band"]).mean(),
        "two_plus": (diff.abs() >= 2).mean(),
        "gov_higher": (diff > 0).mean(),
        "cna_higher": (diff < 0).mean(),
        "crit_one": crit_one,
        "n_adp": df.attrs["n_adp"],
        "adp_echo": df.attrs["adp_echo"],
        "coverage": df.attrs["coverage"],
    }


def render(nvd=None, ratios=DEFAULT_RATIOS):
    """Render the agreement plot for each ratio. Returns list of output paths.

    ``nvd`` is accepted for the shared make.py dispatch signature and ignored:
    this chart reads its own precomputed pair table.
    """
    df = _load()
    s = _stats(df)

    # Scores are quantized to 0.1, so aggregate to one dot per (x, y) pair.
    grid = (
        df.groupby(["cna_score", "second", "same_band"])
        .size()
        .reset_index(name="count")
    )
    cmax = grid["count"].max()

    title = "Same CVE, Two Official CVSS Scores"
    sub_flat = (
        f"{s['n']:,} CVEs published in {s['year']} scored by both their own "
        f"CNA and NVD"
    )
    # One decimal on the exact-match rate: rounding it to a whole percent
    # visibly breaks the on-canvas partition against the two corner shares.
    # (No honest one-decimal set is guaranteed to sum to exactly 100.0.)
    sub_stat = (
        f"{s['exact']:.1%} match exactly · "
        f"{s['flip']:.0%} land in different severity bands"
    )

    # The single largest band-flipped score pair, called out in red: it shows
    # the disagreement is a template, not a tail of odd records.
    flips = grid[~grid["same_band"]]
    top_flip = flips.loc[flips["count"].idxmax()]

    # One size formula everywhere (dots, red callout, size key) so the key is
    # a true reference. Marker s is area (points^2), so linear-in-count means
    # AREA is strictly proportional to CVE count; sqrt compression would
    # understate the 237-CVE pair, the chart's own headline anomaly.
    def dot_size(count):
        return 6 + 210 * (count / cmax)

    key_counts = (1, 50, int(top_flip["count"]))

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        ax.set_aspect("equal", adjustable="box")
        # Wide: the square plane cannot fill a 16:9 canvas, so anchor it to
        # the RIGHT edge (band labels close the composition) and give the
        # freed left column to the stat rail. Centered, the leftover width
        # pools on the right as dead space.
        if ratio == "wide":
            ax.set_anchor("E")
        ax.grid(False)

        # Tint the cells where both scorers land in the same band, whisper
        # light, with the band name set inside each cell like a watermark.
        # No band gridlines: the ticks sit at 4/7/9 and the cells' own edges
        # mark the boundaries, so full-length lines would just add wires.
        halo = [pe.withStroke(linewidth=3.5, foreground="white")]
        edges = [0] + BAND_EDGES + [10]
        for (lo, hi), name in zip(zip(edges[:-1], edges[1:]), BAND_NAMES):
            ax.add_patch(plt.Rectangle((lo, lo), hi - lo, hi - lo,
                                       facecolor=COLORS["primary"], alpha=0.08,
                                       edgecolor="none", zorder=1))
            # Lower-right corner of the cell: below the diagonal, the sparse
            # side by construction. Drawn ABOVE the dots with a white halo so
            # the name reads as a label, not an occluded rendering bug.
            ax.text(hi - 0.15, lo + 0.15, name.upper(), ha="right",
                    va="bottom", fontsize=8, color=COLORS["secondary"],
                    zorder=5.7, path_effects=halo)

        # The agreement line, drawn ABOVE the scatter (it is the chart's
        # central reference) and labeled in place in the near-empty Low cell.
        ax.plot([0, 10], [0, 10], color=COLORS["primary"], lw=1.3,
                linestyle=(0, (5, 4)), zorder=5.5)
        ax.text(1.65, 2.05, "Scores agree", rotation=45,
                rotation_mode="anchor", ha="center", va="bottom", fontsize=9,
                color=COLORS["primary"], zorder=5.6, path_effects=halo)

        # House palette: the story (band flips) gets the navy ink, agreement
        # recedes to grey, and red is reserved for one callout pair. The grey
        # dots get a mid-grey stroke so half the dataset does not fall below
        # the 3:1 graphical-object contrast floor at thumbnail size.
        from matplotlib.colors import to_rgba
        classes = (
            (True, to_rgba(COLORS["neutral"], 0.9), "#6b7f97", 0.6, 4),
            (False, to_rgba(COLORS["primary"], 0.7), "white", 0.7, 5),
        )
        for same, face, edge, elw, z in classes:
            g = grid[grid["same_band"] == same]
            ax.scatter(
                g["cna_score"], g["second"],
                s=dot_size(g["count"]),
                color=face, linewidths=elw, edgecolors=edge, zorder=z,
            )

        # The biggest band-flipped pair, in red with a white ring so it
        # survives grayscale and thumbnails. No leader and no chip: it is the
        # only red on the canvas, and a matching red glyph in the key strip
        # (or the wide rail) explains it without furniture on the data.
        tx, ty, tc = top_flip["cna_score"], top_flip["second"], top_flip["count"]
        band_of = lambda v: BAND_NAMES[sum(v >= e for e in BAND_EDGES)]
        flip_line = (f"{tc:,} CVEs share the largest band-flipped pair: "
                     f"CNA {tx} ({band_of(tx)}) · NVD {ty} ({band_of(ty)})")
        ax.scatter([tx], [ty], s=dot_size(tc),
                   color=COLORS["alert"], alpha=0.95, linewidths=2.0,
                   edgecolors="white", zorder=6)

        # Halves of the plane, unboxed, two-weight, in the genuinely empty
        # corners (axes fractions): bold claim line, quiet number line. One
        # decimal so the partition reconciles with the subtitle's 10.6%.
        for (xf, yf, ha, va, dy), claim, share in (
            ((0.025, 0.978, "left", "top", -0.040), "NVD Scores Higher",
             s["gov_higher"]),
            ((0.975, 0.062, "right", "bottom", -0.040), "CNA Scores Higher",
             s["cna_higher"]),
        ):
            ax.text(xf, yf, claim, transform=ax.transAxes, ha=ha, va=va,
                    fontsize=10.5, fontweight="bold", color=COLORS["text"],
                    zorder=8, path_effects=halo)
            ax.text(xf, yf + dy, f"{share:.1%} of pairs",
                    transform=ax.transAxes, ha=ha, va=va, fontsize=10,
                    color=COLORS["secondary"], zorder=8, path_effects=halo)

        legend_items = ((COLORS["primary"], 0.75, "Different Severity Band"),
                        (COLORS["neutral"], 0.6, "Same Severity Band"))
        if ratio == "wide":
            # Wide letterboxes the square plane, so the stat rail owns the
            # left column. Everything shares the header's x=0.05 margin.
            # Each label hugs its own number (tight gap) with wide gaps
            # BETWEEN blocks, so a skimmer can never bind a label to the
            # wrong number. The red-glyph row explains the red dot in the
            # plot; the in-plot callout is skipped on this ratio.
            # Label hugs its own number (~11px); the gap to the NEXT block is
            # ~6x that, so no skimmer can bind a label to the wrong number.
            x0 = 0.05
            for y, num, lab in ((0.69, f"{s['exact']:.1%}",
                                 "Exact Score Match"),
                                (0.525, f"{s['flip']:.0%}",
                                 "Different Severity Band"),
                                (0.36, f"{s['crit_one']:,}",
                                 "Critical to Only One Scorer")):
                fig.text(x0, y, num, fontfamily="Host Grotesk", fontsize=40,
                         color=COLORS["primary"], ha="left", va="bottom")
                fig.text(x0 + 0.002, y - 0.012, lab, fontsize=11.5,
                         color=COLORS["secondary"], ha="left", va="top")
            # A hairline rule separates the story numbers from the key.
            fig.add_artist(plt.Line2D([x0, 0.30], [0.30] * 2,
                                      color=COLORS["grid"], lw=1.0,
                                      transform=fig.transFigure))
            # The red pair, tied to the plot's red dot by the glyph. One
            # line: it may run right of the rail, into the open canvas
            # between rail and plot.
            fig.add_artist(plt.Line2D([x0 + 0.008], [0.262], marker="o",
                                      color=COLORS["alert"], alpha=0.95,
                                      markersize=np.sqrt(dot_size(tc)),
                                      linestyle="", markeredgecolor="white",
                                      markeredgewidth=1.5,
                                      transform=fig.transFigure))
            fig.text(x0 + 0.032, 0.262, flip_line,
                     fontsize=10.5, color=COLORS["text"], ha="left",
                     va="center")
            for i, (color, alpha, label) in enumerate(legend_items):
                y = 0.215 - i * 0.042
                fig.add_artist(plt.Line2D([x0 + 0.008], [y], marker="o",
                                          color=color, alpha=alpha,
                                          markersize=9, linestyle="",
                                          markeredgecolor="white",
                                          markeredgewidth=0.5,
                                          transform=fig.transFigure))
                fig.text(x0 + 0.028, y, label, fontsize=10.5,
                         color=COLORS["secondary"], ha="left", va="center")
            # Dot size key on one row, same formula as the plot.
            fig.text(x0, 0.128, "CVEs per Dot:", fontsize=10,
                     color=COLORS["secondary"], ha="left", va="center")
            kx = x0 + 0.085
            for c in key_counts:
                fig.add_artist(plt.Line2D([kx], [0.128], marker="o",
                                          color=COLORS["neutral"], alpha=0.9,
                                          markersize=np.sqrt(dot_size(c)),
                                          linestyle="",
                                          markeredgecolor="white",
                                          markeredgewidth=0.5,
                                          transform=fig.transFigure))
                fig.text(kx + 0.015, 0.128, f"{c:,}", fontsize=10,
                         color=COLORS["secondary"], ha="left", va="center")
                kx += 0.058
        else:
            # Square/portrait: nothing administrative lives inside the plot.
            # A slim two-row key strip sits between the x-axis label and the
            # footnote, left-aligned on the header margin. Row 1 explains the
            # red pair via a matching glyph (scaled-down swatch, not a size
            # reference); row 2 is the class legend plus the true-scale dot
            # size key, the only place markers use the real formula.
            strip_y1 = {"square": 0.142, "portrait": 0.132}[ratio]
            strip_y2 = {"square": 0.104, "portrait": 0.100}[ratio]
            fig.add_artist(plt.Line2D([0.058], [strip_y1], marker="o",
                                      color=COLORS["alert"], alpha=0.95,
                                      markersize=np.sqrt(dot_size(tc)) * 0.55,
                                      linestyle="", markeredgecolor="white",
                                      markeredgewidth=1.2,
                                      transform=fig.transFigure))
            fig.text(0.082, strip_y1, flip_line, fontsize=10,
                     color=COLORS["text"], ha="left", va="center")
            kx = 0.058
            for color, alpha, label, width in (
                    (COLORS["primary"], 0.75, "Different Severity Band", 0.205),
                    (COLORS["neutral"], 0.6, "Same Severity Band", 0.175)):
                fig.add_artist(plt.Line2D([kx], [strip_y2], marker="o",
                                          color=color, alpha=alpha,
                                          markersize=8, linestyle="",
                                          markeredgecolor="white",
                                          markeredgewidth=0.5,
                                          transform=fig.transFigure))
                fig.text(kx + 0.014, strip_y2, label, fontsize=9.5,
                         color=COLORS["secondary"], ha="left", va="center")
                kx += 0.014 + width
            kx += 0.025
            for c in key_counts:
                fig.add_artist(plt.Line2D([kx], [strip_y2], marker="o",
                                          color=COLORS["neutral"], alpha=0.9,
                                          markersize=np.sqrt(dot_size(c)),
                                          linestyle="",
                                          markeredgecolor="white",
                                          markeredgewidth=0.5,
                                          transform=fig.transFigure))
                fig.text(kx + 0.016, strip_y2, f"{c:,}", fontsize=9.5,
                         color=COLORS["secondary"], ha="left", va="center")
                kx += 0.060
            fig.text(kx + 0.008, strip_y2, "CVEs per Dot", fontsize=9.5,
                     color=COLORS["secondary"], ha="left", va="center")

        # A touch of margin so the dense 9.8/10.0 rows are not clipped by the
        # frame; both ranges stay equal so the diagonal stays at 45 degrees.
        ax.set_xlim(-0.2, 10.2)
        ax.set_ylim(-0.2, 10.2)
        # Ticks at the band boundaries, not even steps: on this chart 4.0 /
        # 7.0 / 9.0 are the meaningful positions (they are where a score
        # flip becomes a band flip), and they make the 7.3-to-9.8 pair
        # readable off the CNA axis directly.
        ax.set_xticks([0, 4, 7, 9, 10])
        ax.set_yticks([0, 4, 7, 9, 10])
        # Quiet ticks in secondary ink; "(CVSS v3)" appears once as data
        # context (the source line repeats it only as provenance).
        ax.tick_params(length=0, labelsize=11, labelcolor=COLORS["secondary"])
        ax.set_xlabel("CNA Score (CVSS v3)", fontsize=13)
        ax.set_ylabel("NVD Score", fontsize=13)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)

        # Wide's stat rail carries the percentages, so its subtitle stays
        # flat and the numbers appear exactly once.
        sub = sub_flat if ratio == "wide" else f"{sub_flat}\n{sub_stat}"
        top = {"wide": 0.80, "square": 0.805, "portrait": 0.82}[ratio]
        bottom = {"wide": 0.25, "square": 0.235, "portrait": 0.205}[ratio]
        # The right-hand band-label column is gone, so square/portrait get
        # the width back; wide keeps its rail geometry.
        left = 0.12 if ratio == "wide" else 0.10
        right = 0.90 if ratio == "wide" else 0.95
        fig.subplots_adjust(top=top, bottom=bottom, left=left, right=right)
        t1 = {"wide": 26, "square": 20, "portrait": 20}[ratio]
        draw_header(fig, title, sub, ratio, eyebrow_suffix="Scoring",
                    title_size=t1)

        foot_size = {"wide": 9.5, "square": 8.5, "portrait": 8.5}[ratio]
        # Two quiet lines. The dashed line and the dot sizes are explained
        # on-canvas (in-place label, size key), so the footnote carries only
        # what nothing else does: the shading, the selection-bias disclosure
        # (self-defense against "of course the re-scored subset disagrees"),
        # and provenance.
        foot = (f"Shaded cells = same severity band for both scorers. Pairs "
                f"cover the {s['coverage']:.0%} of {s['year']}'s v3-scored "
                f"CVEs NVD has re-scored.\n"
                f"Source: NVD, CVSS v3, CVEs published in {s['year']}; "
                f"CISA-ADP second scores excluded ({s['adp_echo']:.0%} "
                f"echo the CNA's).")
        fig.text(
            0.05, 0.036, foot,
            fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom",
            linespacing=1.5,
        )

        path = GRAPHS / f"score_disagreement_{ratio}_0000-00-00.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

#!/usr/bin/env python3
"""
EPSS Report Card — what EPSS and CVSS had flagged a month before KEV.

For every CVE CISA added to KEV this year that had been public at least 30
days, roll back to 30 days before its KEV date and ask what each of the four
common prioritization policies (CVSS 7.0+, CVSS 9.0+, EPSS 0.10+, EPSS 0.50+)
had already flagged. Two panels per policy: the share of the future KEV
entries it caught, and the share of the whole corpus it flags to do so.

The chart states the pooled facts; the story, including the fresh-versus-
backfill split that the post copy is built on (under a year old CVSS 9.0+
leads, over a year EPSS dominates), lives in the copy plus one factual
footnote line so a bare screenshot cannot be read against the post.

Data: processed/epss_report_card.parquet + _meta.json from
scripts_precompute_epss_report_card.py (historical EPSS snapshots at each
KEV-minus-30-days date). CVSS v3 comes from the CNA with NVD fallback so no
scored CVE drops out. Workload shares are measured on the same historical
snapshot dates, not today's model output.

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

BAR_H = 0.62
# row y-positions: CVSS pair above, EPSS pair below, with a group gap
ROW_Y = {"cvss7": 3.0, "cvss9": 2.0, "epss10": 0.7, "epss50": -0.3}


def _load():
    df = pd.read_parquet(PROCESSED / "epss_report_card.parquet")
    meta = json.loads((PROCESSED / "epss_report_card_meta.json").read_text())

    cv = pd.read_parquet(PROCESSED / "cvelist_v5.parquet",
                         columns=["cve_id", "cvss_v3"])
    nvd = pd.read_parquet(PROCESSED / "nvd_cves.parquet",
                          columns=["cve_id", "cvss_v3"]
                          ).rename(columns={"cvss_v3": "nvd_v3"})
    df = df.merge(cv, on="cve_id", how="left").merge(nvd, on="cve_id",
                                                     how="left")
    df["v3"] = df["cvss_v3"].fillna(df["nvd_v3"])

    corp = cv.merge(nvd, on="cve_id", how="outer")
    corpus_v3 = corp["cvss_v3"].fillna(corp["nvd_v3"]).dropna()
    return df, meta, corpus_v3


def _policies(df, meta, corpus_v3):
    """One dict per policy row: catch count/share, workload share/count."""
    fair = df[df["age_at_kev"] >= 30].dropna(subset=["v3", "epss_30d"])
    n = len(fair)
    n_v3, n_epss = len(corpus_v3), meta["epss_corpus_rows"]
    rows = {
        "cvss7": ("CVSS 7.0+", "High and Critical", fair.v3 >= 7.0,
                  float((corpus_v3 >= 7.0).mean()), n_v3),
        "cvss9": ("CVSS 9.0+", "Critical Only", fair.v3 >= 9.0,
                  float((corpus_v3 >= 9.0).mean()), n_v3),
        "epss10": ("EPSS 0.10+", "A Common Low Bar", fair.epss_30d >= 0.10,
                   meta["epss_workload_share"]["0.1"], n_epss),
        "epss50": ("EPSS 0.50+", "A 50% Probability",
                   fair.epss_30d >= 0.50,
                   meta["epss_workload_share"]["0.5"], n_epss),
    }
    out = {}
    for key, (name, note, mask, share, corp_n) in rows.items():
        catch = int(mask.sum())
        out[key] = {
            "name": name, "note": note,
            "catch": catch, "catch_pct": 100 * catch / n,
            "work_pct": 100 * share, "work_n": share * corp_n,
        }

    # fresh/backfill split for the footnote: the pooled totals invert on the
    # under-a-year cohort, and a bare screenshot must carry that fact
    fresh = fair[fair["age_at_kev"] < 365]
    back = fair[fair["age_at_kev"] >= 365]
    split = {
        "fresh_n": len(fresh), "back_n": len(back),
        "fresh_cvss9": int((fresh.v3 >= 9.0).sum()),
        "fresh_epss10": int((fresh.epss_30d >= 0.10).sum()),
        "back_cvss9": int((back.v3 >= 9.0).sum()),
        "back_epss10": int((back.epss_30d >= 0.10).sum()),
    }
    return out, n, split


def render(nvd=None, ratios=DEFAULT_RATIOS):
    """Render the report card for each ratio. Returns list of output paths.

    ``nvd`` is accepted for the shared make.py dispatch signature and ignored:
    everything comes from the precomputed report-card parquet plus the local
    CVE List / NVD mirrors.
    """
    df, meta, corpus_v3 = _load()
    pol, n, split = _policies(df, meta, corpus_v3)
    year = meta["kev_year"]

    title = "EPSS vs CVSS, One Month Before the KEV List"
    sub = (f"{n} CVEs added to KEV in {year} after 30+ days in public: "
           "what each policy had already flagged")

    out = []
    for ratio in ratios:
        fig = plt.figure(figsize=figsize_for(ratio))
        top = {"wide": 0.70, "square": 0.72, "portrait": 0.755}[ratio]
        bottom = {"wide": 0.26, "square": 0.26, "portrait": 0.235}[ratio]
        left = {"wide": 0.155, "square": 0.20, "portrait": 0.20}[ratio]
        axA, axB = fig.subplots(
            1, 2, sharey=True,
            gridspec_kw=dict(top=top, bottom=bottom, left=left, right=0.965,
                             wspace={"wide": 0.10, "square": 0.14,
                                     "portrait": 0.14}[ratio]))

        keys = ["cvss7", "cvss9", "epss10", "epss50"]
        ys = [ROW_Y[k] for k in keys]
        colors = [COLORS["light"], COLORS["light"],
                  COLORS["primary"], COLORS["primary"]]

        lab = {"wide": 12, "square": 10.5, "portrait": 11}[ratio]
        val = {"wide": 12.5, "square": 10.5, "portrait": 11}[ratio]

        # ---- panel A: catch rate -------------------------------------------
        axA.barh(ys, [pol[k]["catch_pct"] for k in keys], height=BAR_H,
                 color=colors, zorder=3)
        axA.set_xlim(0, 100)
        axA.set_title(f"Future KEV Entries Caught (of {n})",
                      loc="left", fontsize=lab, fontweight="bold",
                      color=COLORS["secondary"], pad=10)
        for k, y in zip(keys, ys):
            p = pol[k]
            txt = f"{p['catch']} · {p['catch_pct']:.0f}%"
            # in-bar labels ride the pale bars, so they use navy ink; white
            # fails contrast (1.9:1) on the light fill
            if p["catch_pct"] > 60:
                axA.text(p["catch_pct"] - 2, y, txt, ha="right", va="center",
                         fontsize=val, fontweight="bold",
                         color=COLORS["primary"], zorder=4)
            else:
                axA.text(p["catch_pct"] + 2, y, txt, ha="left", va="center",
                         fontsize=val, fontweight="bold",
                         color=COLORS["text"], zorder=4)

        # ---- panel B: workload ---------------------------------------------
        axB.barh(ys, [pol[k]["work_pct"] for k in keys], height=BAR_H,
                 color=colors, zorder=3)
        axB.set_xlim(0, 60)
        axB.set_title("Share of All Scored CVEs Flagged",
                      loc="left", fontsize=lab, fontweight="bold",
                      color=COLORS["secondary"], pad=10)
        for k, y in zip(keys, ys):
            p = pol[k]
            txt = f"{p['work_pct']:.0f}% ≈ {p['work_n'] / 1000:,.0f}K CVEs"
            if p["work_pct"] > 40:
                axB.text(p["work_pct"] - 1.5, y, txt, ha="right", va="center",
                         fontsize=val, fontweight="bold",
                         color=COLORS["primary"], zorder=4)
            else:
                axB.text(p["work_pct"] + 1.5, y, txt, ha="left", va="center",
                         fontsize=val, fontweight="bold",
                         color=COLORS["text"], zorder=4)

        # ---- shared cosmetics ----------------------------------------------
        for ax in (axA, axB):
            ax.set_ylim(-0.95, 3.62)
            ax.grid(axis="x", color=COLORS["grid"], linewidth=0.6, alpha=0.8)
            ax.grid(axis="y", visible=False)
            ax.set_axisbelow(True)
            ax.spines["left"].set_visible(False)
            ax.tick_params(axis="y", length=0)
            ax.set_xticks([0, 20, 40, 60] if ax is axB
                          else [0, 25, 50, 75, 100])
            ax.set_xticklabels([f"{t:.0f}%" for t in ax.get_xticks()],
                               fontsize=lab - 1.5)
        axA.set_yticks(ys)
        axA.set_yticklabels(
            [f"{pol[k]['name']}\n{pol[k]['note']}" for k in keys],
            fontsize=lab, linespacing=1.4)
        for tick, k in zip(axA.get_yticklabels(), keys):
            tick.set_color(COLORS["text"] if k.startswith("epss")
                           else COLORS["secondary"])

        t1 = {"wide": 26, "square": 17.5, "portrait": 19}[ratio]
        wsub = sub if ratio == "wide" else sub.replace(": ", ":\n")
        draw_header(fig, title, wsub, ratio, eyebrow_suffix="Exploitation",
                    title_size=t1)

        foot_size = {"wide": 9.5, "square": 8, "portrait": 8}[ratio]
        split_line = (
            f"Among additions under a year old, CVSS 9.0+ led "
            f"({split['fresh_cvss9']} vs {split['fresh_epss10']} of "
            f"{split['fresh_n']}); EPSS's edge is the year-plus backlog "
            f"({split['back_epss10']} vs {split['back_cvss9']} of "
            f"{split['back_n']})."
        )
        if ratio == "wide":
            foot = (
                f"Of {meta['total_added']} CVEs added to KEV in {year}, "
                f"{meta['within_1d']} hit KEV within a day of the CVE going "
                f"public and {meta['under_30d']} more within 30 days; the {n} "
                "shown were public 30+ days before their KEV date.\n"
                f"{split_line}\n"
                "EPSS scores and flag shares read from production snapshots "
                "30 days before each KEV date; CVSS shares from today's "
                "v3-scored corpus (CNA score, NVD fallback).\n"
                "Source: CISA KEV · FIRST EPSS · CVE List V5 / NVD."
            )
        else:
            foot = (
                f"Of {meta['total_added']} CVEs added to KEV in {year}, "
                f"{meta['within_1d']} hit KEV within a day of the CVE going "
                "public\n"
                f"and {meta['under_30d']} more within 30 days; the {n} shown "
                "were public 30+ days before their KEV date.\n"
                f"Among additions under a year old, CVSS 9.0+ led "
                f"({split['fresh_cvss9']} vs {split['fresh_epss10']} of "
                f"{split['fresh_n']}); EPSS's edge is\n"
                f"the year-plus backlog ({split['back_epss10']} vs "
                f"{split['back_cvss9']} of {split['back_n']}). EPSS scores "
                "and flag shares read from snapshots\n"
                "30 days before each KEV date; CVSS shares from today's "
                "v3-scored corpus (CNA score,\n"
                "NVD fallback). Source: CISA KEV · FIRST EPSS · CVE List V5 / NVD."
            )
        fig.text(
            0.05, 0.04, foot,
            fontsize=foot_size, color=COLORS["secondary"], ha="left",
            va="bottom", linespacing=1.5,
        )

        path = GRAPHS / (f"epss_report_card_{ratio}_"
                         f"{pd.Timestamp.today().strftime('%Y-%m-%d')}.png")
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

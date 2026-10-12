#!/usr/bin/env python3
"""
Detection Coverage — which KEV CVEs any open ruleset names, by vendor.

For every CVE on the CISA KEV list with a modern CVE ID, ask the narrow,
checkable question: does at least one rule in Emerging Threats Open, SigmaHQ or
Elastic detection-rules explicitly NAME this CVE ID? Group by CISA's own
``vendorProject`` and rank.

The shape is the story: perimeter and server software sits at the top (Apache,
Fortinet, Ivanti, Citrix), endpoint and mobile at the bottom, with several
vendors at a flat zero. Public detection knowledge is indexed like the
perimeter, not like KEV.

What this is NOT a measure of: whether those CVEs are detectable. Endpoint
detection is overwhelmingly behavioral and deliberately does not name CVEs
(SigmaHQ says so in its own docs), so a zero here means "no public ruleset
answers the question by CVE ID", never "nobody can see it". The footnote says
so on the image, because a screenshot travels without the post.

Data: processed/detection_rules.parquet + _meta.json from
scripts_precompute_detection_rules.py, joined to processed/kev_catalog.json.

Renders one PNG per aspect ratio into ``graphs/``.
"""

import json
from decimal import ROUND_HALF_UP, Decimal
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

# Scope, on PUBLICATION date rather than CVE-ID year. The ID year is only a proxy:
# 82 KEV entries carry a 2023-or-later ID but went public before this cutoff, and 4
# carry an older ID published well after it (CVE-2021-27137 was published in 2026).
# Publication is also this repo's standing cohort convention. Three full years keeps
# every ruleset in its own era, since an unscoped read of a catalog reaching back to
# CVE-2002 just measures "the ruleset had not been written yet".
MIN_PUBLISHED = "2023-08-01"
MIN_KEV_ENTRIES = 7  # vendors below this are too small to rank fairly

# Row track. #F6F7F9 is 1.07:1 against white and vanishes when LinkedIn
# downsamples the card to ~560px, taking the zero rows with it.
TRACK = "#e7eaef"
ZERO_STUB = 0.45  # data units, ~4px: a measured zero, not a blank row
# Two typographic columns for the value rail: percent right-aligned to PCT_X,
# then the count starting at CNT_X, so the separator and the "N of M" fragments
# line up down the page instead of tracking each bar's end.
# Narrow ratios need the column pushed further out: at xlim 133 a
# right-aligned "100%" at 106 lands within 3px of Apache's bar end.
PCT_X = {"wide": 106, "square": 110, "portrait": 110}
CNT_X = {"wide": 109, "square": 113, "portrait": 113}


def _pct_label(pct):
    """Percent, rounded HALF-UP.

    Python's format() rounds half to EVEN: three vendors here share denominator
    8 and land on exact .5, so f"{62.5:.0f}" gives 62 while f"{37.5:.0f}" gives
    38. On a chart whose whole authority is arithmetic, a reader who checks two
    rows finds the rule inconsistent.
    """
    return int(Decimal(pct).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _load():
    rules = pd.read_parquet(PROCESSED / "detection_rules.parquet")
    meta = json.loads((PROCESSED / "detection_rules_meta.json").read_text())
    kev = json.load(open(PROCESSED / "kev_catalog.json"))["vulnerabilities"]

    df = pd.DataFrame([{"cve_id": v["cveID"], "vendor": v["vendorProject"]}
                       for v in kev])
    # Publication date from the CVE List, falling back to NVD so a record missing
    # from one feed does not silently leave the cohort.
    cl = pd.read_parquet(PROCESSED / "cvelist_v5.parquet",
                         columns=["cve_id", "date_published"])
    nvd = pd.read_parquet(PROCESSED / "nvd_cves.parquet",
                          columns=["cve_id", "published"])
    df = df.merge(cl, on="cve_id", how="left").merge(nvd, on="cve_id", how="left")
    df["published"] = (pd.to_datetime(df["date_published"], utc=True, errors="coerce")
                       .fillna(pd.to_datetime(df["published"], utc=True, errors="coerce")))
    # KEV entries newer than the data snapshot have no record in either feed yet.
    # They are dropped rather than assumed; the count is reported so the drop is
    # never silent.
    n_undated = int(df["published"].isna().sum())
    df = df[df["published"] >= pd.Timestamp(MIN_PUBLISHED, tz="UTC")]
    named = set(rules.loc[rules["defensive"], "cve_id"])
    df["named"] = df["cve_id"].isin(named)
    return df, meta, n_undated


def _by_vendor(df):
    g = df.groupby("vendor")["named"].agg(["size", "sum"])
    g = g[g["size"] >= MIN_KEV_ENTRIES].copy()
    g["pct"] = g["sum"] / g["size"] * 100
    # Sort on the DISPLAYED figure, then by denominator, so three rows all
    # printing "71%" are not ordered by a 0.6pp difference the reader cannot
    # see, with the noisiest estimate (5 of 7) sitting above 17 of 24.
    g["_shown"] = g["pct"].map(_pct_label)
    # ascending so the highest coverage lands at the TOP of a barh axis
    return g.sort_values(["_shown", "size"], ascending=[True, True])


def render(nvd=None, ratios=DEFAULT_RATIOS):
    """Render the vendor coverage ranking. Returns list of output paths.

    ``nvd`` is accepted for the shared make.py dispatch signature and ignored;
    this chart reads the KEV catalog and the precomputed rule map.
    """
    df, meta, n_undated = _load()
    g = _by_vendor(df)
    total, hit = len(df), int(df["named"].sum())
    shown = int(g["size"].sum())
    # The vendors below the ranking floor, stated so the chart reconciles against
    # the headline instead of looking like a cherry-picked top slice.
    small = df[~df["vendor"].isin(g.index)]
    n_small = small["vendor"].nunique()
    small_n, small_hit = len(small), int(small["named"].sum())

    title = "KEV CVEs Named by an Open Detection Rule"
    pub_label = pd.Timestamp(MIN_PUBLISHED).strftime("%B %-d, %Y")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        y = range(len(g))

        # Full-width track so a zero-coverage vendor still occupies a visible
        # row. Without it the four vendors at 0% render as nothing at all,
        # which is exactly the finding the chart exists to show.
        ax.barh(y, [100] * len(g), color=TRACK, height=0.72, zorder=1)
        # A measured zero must read as a zero, not as missing data, so every row
        # carries a tick at x=0. Drawn as a rule ON the axis rather than a short
        # bar coming off it: a filled bar is the encoding for a small positive
        # value, which is the one thing these four rows are not.
        ax.vlines(0, -0.7, len(g) - 0.3, color=COLORS["primary"], linewidth=2.0,
                  zorder=4)
        # All bars navy. An earlier draft drew the four zero-coverage vendors in
        # alert red; five reviewers independently read that as "these vendors are
        # dangerously uncovered", which is the exact claim the footnote spends
        # three lines refuting. Emphasis now rides on the absent bar, the bold
        # weight and the literal "0 of 40" instead.
        ax.barh(y, g["pct"], color=COLORS["primary"], height=0.72, zorder=3)
        ax.set_axisbelow(True)

        # The measured values outrank the axis furniture, not the other way round.
        lab = {"wide": 10.5, "square": 11, "portrait": 11.5}[ratio]
        for i, (name, row) in enumerate(g.iterrows()):
            # Rate AND counts, in a fixed column past the track. Riding the bar
            # end put Apache's label across the track edge; a column also lets
            # the rates be read down the page against each other.
            bold = "bold" if row["pct"] == 0 else "normal"
            ax.text(PCT_X[ratio], i, f"{_pct_label(row['pct'])}%", va="center",
                    ha="right", fontsize=lab, color=COLORS["text"],
                    fontweight=bold, zorder=4)
            ax.text(CNT_X[ratio], i,
                    f"·  {int(row['sum'])} of {int(row['size'])}", va="center",
                    ha="left", fontsize=lab, color=COLORS["text"],
                    fontweight=bold, zorder=4)

        ax.set_yticks(list(y))
        ax.set_yticklabels(g.index, fontsize=lab + 0.5)
        for tick, p in zip(ax.get_yticklabels(), g["pct"]):
            if p == 0:
                tick.set_fontweight("bold")
        # Just enough headroom for the widest value label. The old 118 ran the
        # bottom spine 18% of the data span past the last gridline into nothing.
        # Headroom for the value-label column only. The spine is clipped to 100
        # just below so the axis never draws past the last gridline.
        # Must leave the label column room for the widest string ("25 of 113").
        # The narrow ratios have far less axes width per data unit, so they need
        # more nominal headroom, not less.
        ax.set_xlim(0, {"wide": 122, "square": 133, "portrait": 133}[ratio])
        ax.set_xticks([0, 25, 50, 75, 100])
        ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"])
        ax.tick_params(axis="x", labelsize=9.5, colors=COLORS["secondary"])
        # No interior gridlines. Drawn above the track they measured 1.08:1
        # against it and were invisible; drawn below it they were painted over.
        # Every row prints its own rate, so the lines were redundant anyway.
        # The tick labels stay and the baseline is darkened to carry the scale.
        ax.grid(axis="x", visible=False)
        ax.grid(axis="y", visible=False)
        ax.set_ylim(-0.7, len(g) - 0.3)
        ax.spines["left"].set_visible(False)
        # Stop the baseline at the last gridline: the label column past 100%
        # is not data space and an axis running into it reads as unfinished.
        ax.spines["bottom"].set_bounds(0, 100)
        ax.spines["bottom"].set_color("#aeb6c2")
        ax.tick_params(axis="y", length=0)

        # Two lines on every ratio: the one-line form overruns the canvas
        # even in wide once the totals are spelled out.
        # ONE line, hard cap. Two stacked grey bold lines read as a wall and
        # look wrong under the headline; the definition of "named" belongs under
        # the graph with the rest of the method, not in the deck.
        # BOTH figures, positive first. The bars encode the named share, so a
        # subtitle stated only in the negative points the opposite way from the
        # geometry (Apache reads 100% while the deck talks about the un-named).
        # Naming both also puts the copy's headline number on the image instead
        # of making the reader subtract. Footnote line 1 defines "named".
        miss = total - hit
        if ratio == "wide":
            sub = (f"Of the {total} CVEs on the CISA KEV list published since "
                   f"{pub_label}: {hit} are named by an open detection rule, "
                   f"{miss} are not")
        else:
            sub = (f"Of {total} KEV CVEs published since {pub_label}: {hit} named "
                   f"by an open rule, {miss} not")

        top = {"wide": 0.779, "square": 0.808, "portrait": 0.832}[ratio]
        bottom = {"wide": 0.235, "square": 0.192, "portrait": 0.163}[ratio]
        left = {"wide": 0.15, "square": 0.20, "portrait": 0.20}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom, left=left, right=0.97)
        t1 = {"wide": 25, "square": 19, "portrait": 18}[ratio]
        draw_header(fig, title, sub, ratio, eyebrow_suffix="Exploitation",
                    title_size=t1)

        foot_size = {"wide": 9, "square": 7.5, "portrait": 7.5}[ratio]
        # Two lines on every ratio. Wide has ~1470px of text width, the narrow
        # ratios ~990px, so the same string cannot serve both: the full source
        # list overruns portrait by a third.
        if ratio == "wide":
            foot = (f"\"Named\" means a rule file cites the CVE ID; endpoint rules "
                    f"match attacker behavior, not CVE numbers.\n"
                    f"Shows the {len(g)} vendors with {MIN_KEV_ENTRIES}+ CVEs in this "
                    f"cohort, {shown} of {total}; the other {n_small} name "
                    f"{small_hit} of their {small_n}. Vendors are CISA's "
                    f"vendorProject verbatim.\n"
                    f"Sources: CISA KEV, CVE List V5, Emerging Threats Open, SigmaHQ, "
                    f"Elastic detection-rules, retrieved {meta['fetched']}.")
        else:
            foot = (f"\"Named\" means a rule file cites the CVE ID; endpoint rules "
                    f"match behavior, not CVE numbers.\n"
                    f"{len(g)} vendors with {MIN_KEV_ENTRIES}+ CVEs shown, {shown} "
                    f"of {total}; the other {n_small} name {small_hit} of their "
                    f"{small_n}.\n"
                    f"Vendors are CISA's vendorProject verbatim. Sources: CISA KEV, "
                    f"CVE List V5, ET Open, SigmaHQ, Elastic, {meta['fetched']}.")
        fig.text(
            0.05, 0.04,
            foot,
            fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom",
            linespacing=1.6,
        )

        path = GRAPHS / f"detection_coverage_{ratio}_2026-01-01.png"
        out.append(stamp_and_save(fig, path))
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

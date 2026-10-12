#!/usr/bin/env python3
"""
CWE-787 (out-of-bounds write) as the ONLY weakness a CNA listed, by year.

An OOB write is usually the last link in a chain: an integer overflow (CWE-190)
produces a bad size (CWE-131) that produces the write. CVE records accept more
than one CWE, so a CNA can map the chain. This chart counts how often they do
not: CVEs whose CNA container names CWE-787 and nothing else, stacked against
CVEs that list CWE-787 alongside at least one other CWE.

Reads processed/cwe787.parquet (cvegraphs.precompute.cwe787), which carries the
full de-duplicated CWE list per record; the main parquet keeps only the first
CWE, which is enough for "alone" but undercounts "with a chain".

The ADP container is deliberately excluded from the series: when CISA adds
CWE-787 to a record the vendor left blank, that is a different failure (no
mapping at all), and the post is addressed to the vendors writing advisories.

Data: CVE List V5 CNA container, published and non-rejected, by publication date.
"""


import matplotlib.pyplot as plt
import pandas as pd

from cvegraphs.paths import OUTPUT, PROCESSED
from cvegraphs.rolling import current_year, data_asof
from cvegraphs.style import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

DESCRIPTION = "Stacked bars: CVEs whose CNA listed CWE-787 alone vs with another CWE, by year"

GRAPHS = OUTPUT
PARQUET = PROCESSED / "cwe787.parquet"

FIRST_YEAR = 2018  # 2017 has four records; the series is noise before this


def _load():
    df = pd.read_parquet(PARQUET)
    df = df[df["cna_has_787"]].copy()
    df["date_published"] = pd.to_datetime(df["published"], utc=True, errors="coerce")
    df["pub_year"] = df["date_published"].dt.year
    return df


def _series(df, asof):
    cur = current_year(asof)
    years = list(range(FIRST_YEAR, cur + 1))
    alone = {y: int(((df.pub_year == y) & (df.cna_n == 1)).sum()) for y in years}
    chain = {y: int(((df.pub_year == y) & (df.cna_n > 1)).sum()) for y in years}
    return years, alone, chain, cur


def render(nvd=None, ratios=DEFAULT_RATIOS):
    """Render for each ratio. ``nvd`` is accepted for the registry dispatch
    signature and ignored: this chart reads the CNA container of CVE List V5."""
    df = _load()
    asof = data_asof(df)
    years, alone, chain, cur = _series(df, asof)
    total_alone = int((df.cna_n == 1).sum())
    total_chain = int((df.cna_n > 1).sum())

    title = "CWE-787 Listed as a CVE's Only Weakness, by Year"
    sub_parts = [
        f"{total_alone:,} CVEs carry CWE-787 and nothing else",
        f"{total_chain:,} list it alongside another CWE",
    ]

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        a = [alone[y] for y in years]
        c = [chain[y] for y in years]
        w = 0.4
        xa = [y - w / 2 for y in years]
        xc = [y + w / 2 for y in years]
        # Side by side, not stacked: a label over a stacked bar reads as the stack
        # total, and the number the post is about is the navy bar on its own.
        ax.bar(xa, a, width=w, color=COLORS["primary"], edgecolor="white",
               linewidth=0.8, zorder=4, label="CWE-787 is the only CWE")
        ax.bar(xc, c, width=w, color=COLORS["light"], edgecolor="white",
               linewidth=0.8, zorder=4, label="CWE-787 plus another CWE")
        ax.set_axisbelow(True)

        ax.set_ylim(0, max(a) * 1.14)
        lab_size = {"wide": 11.5, "square": 10.5, "portrait": 10.5}[ratio]
        for y, x, av in zip(years, xa, a):
            ax.text(x, av, f"{av:,}", ha="center", va="bottom", fontsize=lab_size,
                    fontweight="bold",
                    color=COLORS["alert"] if y == cur else COLORS["primary"],
                    zorder=5)
        for x, cv in zip(xc, c):
            ax.text(x, cv, f"{cv:,}", ha="center", va="bottom",
                    fontsize=lab_size - 1.5, color=COLORS["secondary"], zorder=5)

        ax.set_xticks(years)
        labels = [str(y) for y in years]
        labels[-1] = f"{cur}\n(to {asof.strftime('%b %-d')})"
        ax.set_xticklabels(labels)
        ax.legend(loc="upper left", frameon=False, fontsize=11)

        sub = ("  ·  ".join(sub_parts) if ratio == "wide" else "\n".join(sub_parts))
        top = {"wide": 0.78, "square": 0.78, "portrait": 0.80}[ratio]
        bottom = {"wide": 0.24, "square": 0.20, "portrait": 0.17}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom, left=0.11, right=0.96)
        t1 = {"wide": 26, "square": 18, "portrait": 18}[ratio]
        draw_header(fig, title, sub, ratio, eyebrow_suffix="Weakness", title_size=t1)

        foot_size = {"wide": 9.5, "square": 8.5, "portrait": 8.5}[ratio]
        fig.text(
            0.05, 0.045,
            "Counts the CWEs in the CNA's own container; CWEs added later by CISA's ADP are not included.\n"
            "Source: CVE List V5, published and non-rejected, by publication date.",
            fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom",
            linespacing=1.5,
        )

        path = GRAPHS / f"cwe787_alone_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

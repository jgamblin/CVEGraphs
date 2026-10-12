#!/usr/bin/env python3
"""
How many Cisco CVEs cover more than one vulnerability.

A CVE ID is supposed to name one vulnerability. Cisco writes two kinds of record
that do not:

* The long-standing "Multiple vulnerabilities in the web-based management interface
  of X could allow ... a cross-site scripting (XSS) attack" - one CVE, several
  instances of the same bug class. A handful a quarter, for years.

* "Security Hardening Release" records, which began 2026-07-15. An engineering team
  runs an internal review, and every weakness class it turned up gets exactly ONE
  CVE: "The vulnerabilities tracked by CVE-2026-20313 are related to Improper link
  resolution before file access issues that are grouped under the Common Weakness
  Enumeration (CWE) CWE-1284." One CVE per CWE bucket per product.

The second kind is the reason this chart exists. It went from zero to 27 CVEs across
five advisories in five weeks, and the count of actual vulnerabilities behind those
27 IDs is nowhere in the record. Neither CVE List V5 nor NVD has a field for "how
many vulnerabilities does this CVE cover," so a rollup is declared in prose or not
at all - which is why the classifier here reads description text.

Deliberately NOT plotted: a vulnerability count for the rollup CVEs. Cisco does not
publish one, and inferring it (from CWE breadth, affected-product count, anything)
would be inventing a number. The honest chart counts CVE IDs and says the rest in
the footnote.

Splunk-family records are excluded from the plotted series. Cisco's CNA scope covers
Splunk, and those records keep Splunk's own house style and land in large quarterly
batches - 106 of them on 2026-08-19 - which would swamp the Cisco advisory series and
change what the denominator means. ClamAV records use Cisco phrasing and stay in.

Data: CVE List V5 raw clone via cvegraphs.precompute.cisco_rollup, by publication
date. Rejected records dropped.
"""


import matplotlib.pyplot as plt
import pandas as pd

from cvegraphs.paths import OUTPUT, PROCESSED
from cvegraphs.rolling import data_asof
from cvegraphs.style import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

DESCRIPTION = "Stacked bars: Cisco CVEs that bundle several vulnerabilities into one ID, by month"

GRAPHS = OUTPUT
SOURCE = PROCESSED / "cisco_rollup.parquet"

MONTHS = 12  # trailing months plotted, so the pre-program baseline is visible

# Stack order is bottom-up: the ordinary case first, the new behaviour on top where
# it reads against the white background.
SERIES = [
    ("single", "One vulnerability per CVE", COLORS["light"]),
    ("classic", 'Rollup: "multiple vulnerabilities", same bug class', COLORS["accent"]),
    ("hardening", "Rollup: hardening release, one CVE per CWE bucket", COLORS["alert"]),
]


def _load():
    if not SOURCE.exists():
        raise FileNotFoundError(
            f"{SOURCE} missing. Run `cvegraphs precompute cisco_rollup`."
        )
    return pd.read_parquet(SOURCE)


def _table(df, asof):
    """Monthly counts by bucket over the trailing window, Splunk-family dropped."""
    d = df[df["bucket"] != "splunk-family"].copy()
    # Whole months only: a partial first month would draw as a real dip.
    start = (asof.tz_convert("UTC").normalize().replace(day=1)
             - pd.DateOffset(months=MONTHS - 1))
    d = d[d["date_published"] >= start]
    d["m"] = d["date_published"].dt.to_period("M")

    months = pd.period_range(start.to_period("M"), asof.to_period("M"), freq="M")
    t = pd.crosstab(d["m"], d["bucket"]).reindex(months, fill_value=0)
    for key, _, _ in SERIES:
        if key not in t.columns:
            t[key] = 0
    return t[[k for k, _, _ in SERIES]]


def render(nvd=None, ratios=DEFAULT_RATIOS):
    df = _load()
    asof = data_asof(df)
    t = _table(df, asof)

    total = int(t.values.sum())
    rollups = int(t["classic"].sum() + t["hardening"].sum())
    hardening = int(t["hardening"].sum())
    n_adv = df.loc[df["bucket"] == "hardening", "advisory"].nunique()
    first = df.loc[df["bucket"] == "hardening", "date_published"].min()

    # The newest month is partial (the snapshot stops mid-month), so it is marked
    # rather than left to read as a finished month against eleven complete ones.
    partial = asof.day < asof.days_in_month
    labels = [p.strftime("%b") for p in t.index]
    # Year marker on January and on the first bar, so the axis stays readable.
    labels = [f"{lab}\n{p.year}" if p.month == 1 or i == 0 else lab
              for i, (lab, p) in enumerate(zip(labels, t.index))]
    if partial:
        # Stacked, not appended: " MTD" on one line widens the last tick enough to
        # collide with its neighbour on the 1080px-wide ratios.
        labels[-1] = labels[-1].split("\n")[0] + "\nMTD"

    title = "Cisco CVEs That Cover More Than One Vulnerability"
    # Wrapped by hand per ratio: the wide canvas fits ~100 characters a line, the
    # square and portrait ones about 72, and an over-long line silently runs off
    # the right edge rather than wrapping.
    SUBTITLES = {
        "wide": (
            f"Cisco-assigned CVEs for Cisco-branded products, by publication month. "
            f"{rollups} of {total} in the last 12 months\n"
            "are rollups — one CVE ID the record itself describes as covering "
            "several distinct vulnerabilities."
        ),
        "narrow": (
            "Cisco-assigned CVEs for Cisco-branded products, by publication "
            f"month.\n{rollups} of {total} in the last 12 months are rollups — one "
            "CVE ID that the\nrecord itself describes as covering several distinct "
            "vulnerabilities."
        ),
    }

    out = []
    for ratio in ratios:
        subtitle = SUBTITLES["wide" if ratio == "wide" else "narrow"]
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        x = range(len(t))
        bottom = [0] * len(t)
        for key, label, color in SERIES:
            vals = t[key].tolist()
            ax.bar(x, vals, bottom=bottom, color=color, label=label,
                   width=0.72, edgecolor="white", linewidth=0.8, zorder=3)
            bottom = [b + v for b, v in zip(bottom, vals)]

        # Value labels on the hardening segment only: it is the finding, and
        # labelling every segment turns a clean stack into a table.
        for i, (h, tot) in enumerate(zip(t["hardening"], bottom)):
            if h:
                ax.annotate(f"{int(h)}", (i, tot), textcoords="offset points",
                            xytext=(0, 6), ha="center", fontsize=13,
                            fontweight="bold", color=COLORS["alert"], zorder=6)

        ax.set_xticks(list(x))
        ax.set_xticklabels(labels)
        ax.set_ylabel("CVEs published")
        ax.set_ylim(0, max(bottom) * 1.22)
        ax.set_axisbelow(True)
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)

        ncol = 1 if ratio != "wide" else 1
        leg = ax.legend(loc="upper left", frameon=False, fontsize=10.5,
                        ncol=ncol, handlelength=1.6, labelspacing=0.5)
        leg.set_zorder(7)
        for s in leg.get_texts():
            s.set_color(COLORS["secondary"])

        top = {"wide": 0.76, "square": 0.74, "portrait": 0.77}[ratio]
        bottom_m = {"wide": 0.34, "square": 0.285, "portrait": 0.235}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom_m, left=0.10, right=0.96)
        t1 = {"wide": 25, "square": 18, "portrait": 18}[ratio]
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="CNA Practice",
                    title_size=t1)

        foot_size = {"wide": 9.5, "square": 8.5, "portrait": 8.5}[ratio]
        foot = "\n".join([
            f"The hardening releases are new: {hardening} CVEs across {n_adv} "
            f"advisories, none before {first.strftime('%b %-d, %Y')}.",
            'Each says its CVE tracks "vulnerabilities ... grouped under CWE-N" '
            "without ever stating how many.",
            "No CVE or NVD field records a per-CVE vulnerability count, so the real "
            "total is not recoverable.",
            f"Source: CVE List V5, through {asof.strftime('%b %-d, %Y')}"
            + (" — final month partial." if partial else ".")
            + " Splunk-family excluded, ClamAV included.",
        ])
        fig.text(0.05, 0.045, foot, fontsize=foot_size, color=COLORS["secondary"],
                 ha="left", va="bottom", linespacing=1.5)

        path = GRAPHS / f"cisco_rollup_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        out.append(stamp_and_save(fig, path))
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

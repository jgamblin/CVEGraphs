#!/usr/bin/env python3
"""
Which CNAs' CVEs NVD has marked Deferred, and which never are. Ranked, current year.

Since its Apr 15 2026 policy note NVD marks the CVEs it will not enrich as
``vulnStatus = Deferred`` (the public label is "Lowest Priority - not scheduled for
immediate enrichment"). Deferred means no CPE and no NVD-authored score. The
share is not a gradient across CNAs, it is a switch: the three WordPress CNAs sit at
99%+, the big-vendor CNAs sit at exactly 0.0%, and a handful of aggregators sit in
between. The dashed line is the all-CVE share and, as in `cwe_cna_rank`, it lands
where hardly any CNA lives.

Cohort: CVEs published in the current year that NVD has SETTLED, meaning Analyzed,
Modified or Deferred. Modified rows are Analyzed rows that were later updated (100%
carry a CPE and a score), so they count as enriched. Received, Awaiting Analysis and
Undergoing Analysis rows are excluded because their fate is not yet known; recent
months are therefore thinner than they will be.

Companion to `cwe_cna_rank` and `patch_tag` (same shape, same 250 floor).
Data: NVD status, joined to CVE List V5 for the assigning CNA; published and
non-rejected, by NVD publication date.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from data import load_cvelist, load_nvd
from rolling_config import current_year, data_asof, ytd_mask
from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"

# Volume floor on SETTLED rows, matching cwe_cna_rank / patch_tag so the three
# CNA-practice charts read as a set.
MIN_CVES = 250

SETTLED = ("Analyzed", "Modified", "Deferred")

CNA_NAMES = {
    "GitHub_M": "GitHub", "VulnCheck": "VulnCheck", "VulDB": "VulDB",
    "Patchstack": "Patchstack", "Wordfence": "Wordfence", "microsoft": "Microsoft",
    "mitre": "MITRE", "Chrome": "Chrome", "oracle": "Oracle", "Linux": "Linux",
    "apple": "Apple", "mozilla": "Mozilla", "WPScan": "WPScan", "adobe": "Adobe",
    "GitLab": "GitLab", "redhat": "Red Hat", "ibm": "IBM", "apache": "Apache",
    "icscert": "ICS-CERT", "zdi": "ZDI", "@huntr_ai": "huntr", "cisco": "Cisco",
    "dell": "Dell", "vmware": "VMware", "Joomla": "Joomla", "CPANSec": "CPANSec",
    "EEF": "Erlang (EEF)", "TR-CERT": "TR-CERT", "CERT-PL": "CERT-PL",
    "nvidia": "NVIDIA", "HCL": "HCL", "TuranSec": "TuranSec",
}


def _load(nvd=None):
    """NVD rows joined to their CNA. Inner join: a CVE that CVE List V5 has
    rejected but NVD has not yet caught up on is dropped, so the chart's totals
    and its per-CNA rows describe the same cohort."""
    n = nvd if nvd is not None else load_nvd()
    v5 = load_cvelist()[["cve_id", "assigner_short_name"]]
    return n.merge(v5, on="cve_id", how="inner")


def _rows(df, asof):
    """Per-CNA Deferred share of settled CVEs, current year to date, above the floor."""
    cur = current_year(asof)
    d = df[ytd_mask(df, cur, asof)]
    pending = int((~d["vuln_status"].isin(SETTLED)).sum())
    d = d[d["vuln_status"].isin(SETTLED)].copy()
    d["deferred"] = d["vuln_status"] == "Deferred"

    g = d.groupby("assigner_short_name").agg(n=("cve_id", "size"),
                                             rate=("deferred", "mean"))
    g["rate"] = 100 * g["rate"]
    # Worst at the top. Ties on 0.0% break on volume so the order is stable.
    g = g[g["n"] >= MIN_CVES].sort_values(["rate", "n"], ascending=[False, False])

    rows = [{"cna": CNA_NAMES.get(i, i), "rate": r["rate"], "n": int(r["n"])}
            for i, r in g.iterrows()]
    overall = 100 * d["deferred"].mean()
    return rows, overall, len(d), int(d["deferred"].sum()), int(g["n"].sum()), pending, cur


def render(nvd=None, ratios=DEFAULT_RATIOS):
    df = _load(nvd)
    asof = data_asof(df)
    rows, overall, total, deferred, covered, pending, cur = _rows(df, asof)

    zeros = [r for r in rows if r["rate"] < 0.05]
    # House rule: the heading states what the chart shows.
    title = f"NVD Deferred Share by CNA, {cur} to Date"
    subtitle = (
        f"Share of each CNA's settled {cur} CVEs that NVD marked Deferred: "
        f"no CPE, not scheduled.\n"
        f"The {len(rows)} CNAs shown each have {MIN_CVES}+ settled {cur} CVEs, "
        f"together {100 * covered / total:.0f}% of the {total:,} settled."
    )

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))

        n = len(rows)
        name_size = {"wide": 10, "square": 8.5, "portrait": 9}[ratio]
        val_size = {"wide": 9.5, "square": 8, "portrait": 8.5}[ratio]

        for i, r in enumerate(rows):
            y = n - 1 - i
            zero = r["rate"] < 0.05
            if not zero:
                ax.barh(y, r["rate"], height=0.66, color=COLORS["primary"],
                        edgecolor="white", linewidth=0.9, zorder=3)
                label = f"{r['rate']:.1f}%"
            else:
                # A true zero draws nothing; the label carries the value.
                label = "0.0%"
            ax.text(r["rate"] + 1.4 if not zero else 1.4, y, label,
                    fontsize=val_size, fontweight="bold",
                    color=COLORS["primary"] if not zero else COLORS["secondary"],
                    ha="left", va="center", zorder=4)
            ax.text(-0.012, y, r["cna"], transform=ax.get_yaxis_transform(),
                    fontsize=name_size, fontweight="bold", color=COLORS["text"],
                    ha="right", va="center")
            ax.text(1.10, y, f"{r['n']:,}", transform=ax.get_yaxis_transform(),
                    fontsize=val_size, color=COLORS["secondary"], ha="right",
                    va="center")

        # All-CVE share, drawn UNDER the bars (review 2026-09-08): over them it read
        # as perforation through the 99% bars. Below them it is a guide.
        ax.axvline(overall, color=COLORS["secondary"], linestyle=(0, (5, 4)),
                   linewidth=1.6, zorder=2, alpha=0.95)
        # Label goes low, beside the short bars, as in cwe_cna_rank: the top rows
        # are the 99% bars and leave no room right of the line.
        low_rows = sum(1 for r in rows if r["rate"] < overall)
        ax.text(overall + 1.8, max(low_rows / 2.0, 0.5),
                f"All Settled {cur} CVEs: {overall:.1f}%",
                fontsize=val_size + 0.5, fontweight="bold",
                color=COLORS["secondary"], ha="left", va="center", zorder=6,
                bbox=dict(facecolor="white", edgecolor="none", pad=1.6))

        ax.set_xlim(0, 118)
        ax.set_ylim(-0.7, n + 0.55)
        ax.set_yticks([])
        ax.set_xticks(range(0, 101, 20))
        ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="y", length=0)
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.grid(axis="y", visible=False)
        ax.set_axisbelow(True)

        # Right-column header.
        ax.text(1.10, n + 0.05, "Settled CVEs", transform=ax.get_yaxis_transform(),
                fontsize=val_size, color=COLORS["secondary"], ha="right",
                va="center")

        top = {"wide": 0.76, "square": 0.80, "portrait": 0.82}[ratio]
        bottom = {"wide": 0.17, "square": 0.14, "portrait": 0.13}[ratio]
        left = {"wide": 0.15, "square": 0.17, "portrait": 0.16}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom, left=left, right=0.88)
        t1 = {"wide": 26, "square": 19, "portrait": 20}[ratio]
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="Data Quality",
                    title_size=t1)

        foot_size = {"wide": 9.5, "square": 8, "portrait": 8.5}[ratio]
        fig.text(
            0.05, 0.035,
            f"Settled = Analyzed, Modified or Deferred ({deferred:,} Deferred); "
            f"excludes {pending:,} CVEs from {cur} still in NVD's queue.\n"
            "Source: NVD vulnerability status; CNA from CVE List V5. Counts published, "
            "non-rejected CVEs by publication date.",
            fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom",
            linespacing=1.5,
        )

        path = GRAPHS / f"nvd_deferred_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

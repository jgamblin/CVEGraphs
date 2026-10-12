#!/usr/bin/env python3
"""
Which CNAs label the fix. Ranked, current year.

The CVE record format lets a CNA tag each reference URL with what it is. One of
those tags is ``patch``: "the reference contains an update to the software that
fixes the vulnerability." It is the only machine-readable way a CVE record can say
"the fix is here". This chart shows, for every CNA publishing real volume this
year, the share of its CVEs that carry at least one reference tagged ``patch``.
Nothing else counts: an untagged commit URL or a vendor advisory that names the
fixed version is real fix information, but a machine cannot tell it apart from
the other references, which is the whole point of the tag.

Data: processed/patch_tag.parquet from scripts_precompute_patch_tag.py (CVE List
V5, published and non-rejected, by publication date).
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from rolling_config import current_year, data_asof, ytd_mask
from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

HERE = Path(__file__).resolve().parent.parent
GRAPHS = HERE / "graphs"
DATA = HERE / "processed" / "patch_tag.parquet"

# Same volume floor as cwe_cna_rank so the two CNA-practice charts are comparable.
MIN_CVES = 250

CNA_NAMES = {
    "GitHub_M": "GitHub", "VulnCheck": "VulnCheck", "VulDB": "VulDB",
    "Patchstack": "Patchstack", "Wordfence": "Wordfence", "microsoft": "Microsoft",
    "mitre": "MITRE", "Chrome": "Chrome", "oracle": "Oracle", "Linux": "Linux",
    "apple": "Apple", "mozilla": "Mozilla", "WPScan": "WPScan", "adobe": "Adobe",
    "GitLab": "GitLab", "redhat": "Red Hat", "ibm": "IBM", "apache": "Apache",
    "icscert": "ICS-CERT", "zdi": "ZDI", "cisco": "Cisco", "dell": "Dell",
    "vmware": "VMware", "Joomla": "Joomla", "TR-CERT": "TR-CERT",
    "EEF": "Erlang (EEF)", "CPANSec": "CPANSec",
}


def _load():
    if not DATA.exists():
        raise FileNotFoundError(
            f"{DATA} missing. Run: python scripts_precompute_patch_tag.py")
    df = pd.read_parquet(DATA)
    return df.rename(columns={"published": "date_published"})


def _rows(df, asof):
    cur = current_year(asof)
    d = df[ytd_mask(df, cur, asof)].copy()
    g = d.groupby("assigner_short_name").agg(
        n=("cve_id", "size"), tagged=("has_patch_tag", "mean"),
        k=("has_patch_tag", "sum"))
    g["tagged"] *= 100
    # Sort by rate then volume so ties are stable across refreshes.
    g = g[g["n"] >= MIN_CVES].sort_values(["tagged", "n"], ascending=[False, False])
    rows = [{"cna": CNA_NAMES.get(i, i), "tagged": r["tagged"], "n": int(r["n"]),
             "k": int(r["k"])}
            for i, r in g.iterrows()]
    overall = 100 * d["has_patch_tag"].mean()
    return rows, overall, len(d), int(g["n"].sum()), cur


def render(nvd=None, ratios=DEFAULT_RATIOS):
    df = _load()
    asof = data_asof(df)
    rows, overall, total, covered, cur = _rows(df, asof)

    title = f"Patch-Tagged References by CNA, {cur} to Date"
    subtitle = (f"Share of each CNA's {cur} CVEs with at least one reference tagged \"patch\".\n"
                f"{len(rows)} CNAs published {MIN_CVES}+ CVEs this year, "
                f"{100 * covered / total:.0f}% of all volume.")

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        n = len(rows)
        name_size = {"wide": 9.5, "square": 8, "portrait": 8.5}[ratio]
        val_size = {"wide": 9, "square": 7.5, "portrait": 8}[ratio]

        for i, r in enumerate(rows):
            y = n - 1 - i
            tagged, k = r["tagged"], r["k"]
            if k > 0:
                # Every non-zero value gets a visible bar, so a CNA that tagged a
                # handful of records is never drawn shorter than one that tagged none.
                ax.barh(y, max(tagged, 0.6), height=0.66, color=COLORS["primary"],
                        edgecolor="white", linewidth=0.9, zorder=3)
                label = f"{tagged:.1f}%" if tagged >= 0.05 else "<0.1%"
                ax.text(max(tagged, 0.6) + 1.4, y, label, fontsize=val_size,
                        fontweight="bold", color=COLORS["primary"],
                        ha="left", va="center", zorder=6)
            else:
                # A true zero draws nothing; the label carries the value.
                ax.text(1.4, y, "0.0%", fontsize=val_size, color=COLORS["secondary"],
                        ha="left", va="center", zorder=6)
            ax.text(-0.012, y, r["cna"], transform=ax.get_yaxis_transform(),
                    fontsize=name_size, fontweight="bold", color=COLORS["text"],
                    ha="right", va="center")
            ax.text(1.005, y, f"{r['n']:,}", transform=ax.get_yaxis_transform(),
                    fontsize=val_size, color=COLORS["secondary"], ha="left",
                    va="center")
        # Header for the right-hand count column.
        ax.text(1.005, n - 0.35, f"{cur} CVEs", transform=ax.get_yaxis_transform(),
                fontsize=val_size, color=COLORS["secondary"], ha="left", va="bottom")

        # Reference line sits behind the bars so it only shows in the empty field.
        ax.axvline(overall, color=COLORS["secondary"], linestyle=(0, (5, 4)),
                   linewidth=1.6, zorder=2, alpha=0.95)
        ax.text(overall + 1.8, n - 0.35, f"All {cur} CVEs: {overall:.0f}%",
                fontsize=val_size + 0.5, fontweight="bold",
                color=COLORS["secondary"], ha="left", va="bottom", zorder=6)

        ax.set_xlim(0, 118)
        ax.set_ylim(-0.7, n + 0.45)
        ax.set_yticks([])
        ax.set_xticks(range(0, 101, 20))
        ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f"{v:.0f}%"))
        for s in ("left", "right", "top"):
            ax.spines[s].set_visible(False)
        ax.tick_params(axis="y", length=0)
        ax.grid(axis="x", color=COLORS["grid"], lw=0.6, alpha=0.8)
        ax.grid(axis="y", visible=False)
        ax.set_axisbelow(True)

        top = {"wide": 0.745, "square": 0.79, "portrait": 0.815}[ratio]
        bottom = {"wide": 0.17, "square": 0.20, "portrait": 0.175}[ratio]
        left = {"wide": 0.15, "square": 0.18, "portrait": 0.17}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom, left=left, right=0.90)
        t1 = {"wide": 25, "square": 18, "portrait": 19}[ratio]
        draw_header(fig, title, subtitle, ratio,
                    eyebrow_suffix="Data Quality", title_size=t1)

        foot_size = {"wide": 9.5, "square": 8, "portrait": 8.5}[ratio]
        foot = ("Counts only references tagged \"patch\" in each record's CNA container; "
                "untagged fix links and vendor advisories are excluded.\n"
                "Source: CVE List V5, published and non-rejected, by publication date.")
        if ratio != "wide":
            foot = ("Counts only references tagged \"patch\" in each record's CNA container;\n"
                    "untagged fix links and vendor advisories are excluded.\n"
                    "Source: CVE List V5, published and non-rejected, by publication date.")
        fig.text(0.05, 0.03, foot, fontsize=foot_size, color=COLORS["secondary"],
                 ha="left", va="bottom", linespacing=1.35)

        path = GRAPHS / f"patch_tag_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        path = stamp_and_save(fig, path)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

#!/usr/bin/env python3
"""
KEV watch — confirmed exploitation over time.

Monthly additions to CISA's Known Exploited Vulnerabilities catalog over the
trailing 12 months, with the ransomware-linked share highlighted. Leads on
exploitation (the counterweight to raw volume), and the headline is the count
added in the last 30 days.
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from rolling_config import data_asof
from style_social import COLORS, DEFAULT_RATIOS, figsize_for, stamp_and_save

GRAPHS = Path(__file__).resolve().parent.parent / "graphs"
PROCESSED = Path(__file__).resolve().parent.parent / "processed"
MONTHS = 12


def render(nvd=None, ratios=DEFAULT_RATIOS):
    kev = json.load(open(PROCESSED / "kev_catalog.json"))
    kv = kev.get("vulnerabilities", [])
    catalog_total = len(kv)

    added = pd.to_datetime(pd.Series([e.get("dateAdded") for e in kv]), errors="coerce", utc=True)
    ransom = pd.Series([e.get("knownRansomwareCampaignUse") == "Known" for e in kv])
    df = pd.DataFrame({"added": added, "ransom": ransom}).dropna(subset=["added"])

    asof = data_asof(nvd) if nvd is not None else df["added"].max().normalize()
    asof_str = asof.strftime("%b %d, %Y")

    # Trailing 12 whole months ending with the current month.
    cur_period = asof.tz_convert(None).to_period("M")
    periods = [cur_period - i for i in range(MONTHS)][::-1]
    m = df["added"].dt.tz_convert(None).dt.to_period("M")
    monthly = df.assign(m=m).groupby("m")
    tot = monthly.size()
    ran = monthly["ransom"].sum()
    tot_v = [int(tot.get(p, 0)) for p in periods]
    ran_v = [int(ran.get(p, 0)) for p in periods]
    nonran_v = [t - r for t, r in zip(tot_v, ran_v)]

    last30 = int((df["added"] >= (asof - pd.Timedelta(days=30))).sum())
    last30_ran = int(df[(df["added"] >= (asof - pd.Timedelta(days=30)))]["ransom"].sum())

    title1 = f"CISA added {last30} CVEs to KEV in the last 30 days"
    title2 = f"{last30_ran} ransomware-linked  ·  {catalog_total:,} in the catalog"
    sub = "Confirmed exploited-in-the-wild, the counterweight to raw CVE volume."

    labels = [p.strftime("%b") for p in periods]
    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        x = range(len(periods))
        ax.bar(list(x), nonran_v, color=COLORS["primary"], edgecolor="white", label="Other")
        ax.bar(list(x), ran_v, bottom=nonran_v, color=COLORS["alert"],
               edgecolor="white", label="Ransomware-linked")
        for xi, t in zip(x, tot_v):
            if t:
                ax.text(xi, t, f"{t}", ha="center", va="bottom",
                        fontsize=11, fontweight="bold", color=COLORS["text"])

        ax.set_xticks(list(x))
        ax.set_xticklabels(labels, fontsize=12)
        ax.margins(y=0.16)
        ax.legend(loc="upper left", fontsize=11, frameon=False)

        ax.text(0.0, -0.12,
                f"Monthly KEV additions, trailing 12 months through {asof.strftime('%b %d')}. "
                f"Current month partial. Source: CISA KEV.",
                transform=ax.transAxes, fontsize=10.5, color=COLORS["neutral"], va="top")

        top = {"wide": 0.80, "square": 0.84, "portrait": 0.86}[ratio]
        fig.subplots_adjust(top=top, bottom=0.15, left=0.11, right=0.96)
        if ratio == "wide":
            fig.text(0.04, 0.95, f"{title1}. {title2}", fontsize=17, fontweight="bold",
                     color=COLORS["text"], ha="left", va="top")
            fig.text(0.04, 0.88, sub, fontsize=12, color=COLORS["secondary"], ha="left", va="top")
        else:
            fig.text(0.05, 0.965, title1, fontsize=18, fontweight="bold",
                     color=COLORS["text"], ha="left", va="top")
            fig.text(0.05, 0.920, title2, fontsize=13, fontweight="bold",
                     color=COLORS["alert"], ha="left", va="top")
            fig.text(0.05, 0.884, sub, fontsize=11, color=COLORS["secondary"], ha="left", va="top")

        path = GRAPHS / f"kev_{ratio}_{asof.strftime('%Y-%m-%d')}.png"
        stamp_and_save(fig, path, asof_str)
        out.append(path)
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

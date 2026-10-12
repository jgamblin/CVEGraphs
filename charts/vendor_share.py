#!/usr/bin/env python3
"""
Who is publishing the CVEs: the product's own vendor, or somebody else.

Monthly share of CVEs whose assigning CNA maintains the affected product
(Microsoft for Windows, Linux for the kernel, Oracle for its CPU), against
third-party CNAs that publish for products they do not own: GitHub's advisory
CNA, the WordPress plugin CNAs (Patchstack, Wordfence, WPScan), VulDB,
VulnCheck, MITRE, national CERTs, bug-bounty platforms and research firms.

The shape is the finding. Early 2026 growth was third-party (the vendor share
bottomed in March); since April the vendors have taken it back, and
September is the highest month in the series. A second line drops the three
biggest vendor publishers (Linux, Microsoft, Oracle) to show the turn is not
three batch calendars: without them the share still roughly doubles from its
January low and sits well above anything in 2025. stats() prints the figures.

Classification rules (THIRD_PARTY below):

* The test is whether the CNA maintains the product it assigns for, not
  whether the CNA is a company. So GitHub_M is third party (it publishes for
  repositories it does not maintain) and the Linux kernel CNA is a vendor.
* Ecosystem CNAs that mostly assign for community-maintained packages
  (Joomla and Drupal extensions, CPAN modules, Erlang/Hex packages) count as
  third party. Foundations that own their projects (Apache, OpenJS, PSF,
  Eclipse) count as vendors.
* Only CNAs explicitly listed in VENDOR or THIRD_PARTY are counted. Anything
  else is left out of both numerator and denominator, and stats() reports how
  much volume that is per month (under 3%), so an unlisted CNA can never tilt
  the line by defaulting to one side.

Data: CVE List V5, non-rejected, by publication month.
"""

from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.ticker import PercentFormatter

from data import load_cvelist
from rolling_config import data_asof
from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
)

HERE = Path(__file__).resolve().parent
GRAPHS = HERE.parent / "graphs"

START = pd.Period("2025-01", "M")
# Reference band: pooled vendor share before the 2022-2025 slide, same rules.
BASE_YEARS = (2017, 2021)
# Darker than COLORS["neutral"]: the stock grey read at about 2.6:1 in review.
GREY_LINE = "#7F93AD"
GREY_TEXT = "#5F7390"
# A trailing month with fewer days than this is dropped rather than drawn as a
# partial point; a longer one is kept and marked partial (dashed, hollow, "*").
MIN_PARTIAL_DAYS = 15
BIG_THREE = {"Linux", "microsoft", "oracle"}

# CNAs that publish for products they do not maintain.
THIRD_PARTY = {
    "GitHub_M", "VulDB", "Patchstack", "mitre", "VulnCheck", "Wordfence",
    "WPScan", "icscert", "zdi", "INCIBE", "jpcert", "TR-CERT", "CERT-PL",
    "@huntr_ai", "CPANSec", "CERTVDE", "hackerone", "EEF", "twcert", "talos",
    "certcc", "CIRCL", "TuranSec", "Nozomi", "cisa-cg", "NCSC.ch",
    "GovTech CSG", "Fluid Attacks", "SEC-VLab", "tenable", "rapid7", "snyk",
    "ENISA", "CERT-In", "DIVD", "securin", "INCD", "Gridware", "CSA",
    "Joomla", "drupal", "Checkmarx", "KrCERT/CC", "NCSC-NL", "ptsecurity",
    "Sonar", "GitHub_P", "cisa", "Secur0", "runZero", "Sonatype",
    "CyberDanube", "HiddenLayer", "HeroDevs", "sba-research", "ASRG", "SRA",
    "Bugcrowd", "ThinkstAppliedResearch", "Securifera", "seal", "BLSOPS",
    "redhat-cnalr",
}

# CNAs that maintain the products they assign for: every CNA with 45+ CVEs
# published since 2025 that is not listed above, plus the 2026 risers with 7+
# since May whose product ownership is unambiguous.
VENDOR = {
    "Linux", "microsoft", "oracle", "Chrome", "ibm", "adobe", "apple",
    "redhat", "apache", "cisco", "mozilla", "dell", "google_android", "GitLab",
    "nvidia", "intel", "qualcomm", "sap", "SamsungMobile", "siemens", "HCL",
    "huawei", "fortinet", "vmware", "hpe", "MediaTek", "Mattermost", "qnap",
    "jenkins", "mongodb", "Google_Devices", "JetBrains", "elastic", "AMD",
    "wikimedia-foundation", "TPLink", "AMZN", "f5", "juniper", "zephyr",
    "palo_alto", "canonical", "Liferay", "eclipse", "ivanti", "suse", "Go",
    "Rockwell", "openjs", "ProgressSoftware", "ConcreteCMS", "autodesk", "ABB",
    "OX", "DEVOLUTIONS", "PostgreSQL", "Arista", "schneider", "lenovo",
    "Foxit", "Gitea", "samsung.tv_appliance", "wolfSSL", "JFROG", "SICK AG",
    "Zohocorp", "WSO2", "WatchGuard", "Tanium", "fedora", "OpenHarmony", "hp",
    "Google", "Zoom", "synology", "GV", "imaginationtech", "Esri", "NI",
    "TYPO3", "Silabs", "GRAFANA", "freebsd", "Deltaww", "ASUS", "HashiCorp",
    "3DS", "Acronis", "sonicwall", "PSF", "trendmicro", "NLnet Labs",
    "Checkmk", "SolarWinds", "openssl", "curl", "OpenText", "XEN", "Unisoc",
    "Axis", "zte", "GoogleCloud", "isc", "Acer", "bcorg", "NETGEAR",
    "Absolute", "Zyxel", "Ubiquiti", "OpenVPN", "Okta", "RTI", "GEN",
    "rami.io", "SNOWFLAKE", "DSF", "checkpoint", "Kong", "Document Fdn.",
    "Docker", "php", "jci", "Zabbix", "Commvault", "hikvision", "PaperCut",
    "Hitachi", "ERIC", "Altium", "glibc", "Arm", "Temporal", "Kaspersky",
    "Zscaler", "atlassian", "ASUSTOR1", "Insyde", "Canon", "NetScaler",
    "Nokia", "bosch", "OTRS", "Perforce", "Tcpdump", "Octopus", "blackberry",
    "LY-Corporation", "Qt", "Hitachi Energy",
}


def _table():
    cl = load_cvelist().drop_duplicates("cve_id")
    cl = cl.assign(pub=pd.to_datetime(cl["date_published"], utc=True,
                                      errors="coerce")).dropna(subset=["pub"])
    asof = data_asof(cl)
    cl["period"] = cl["pub"].dt.tz_localize(None).dt.to_period("M")
    cna = cl["assigner_short_name"]
    cl["kind"] = "unclassified"
    cl.loc[cna.isin(VENDOR), "kind"] = "vendor"
    cl.loc[cna.isin(THIRD_PARTY), "kind"] = "third"
    yrs = cl["pub"].dt.year.between(*BASE_YEARS)
    k = cl.loc[yrs, "kind"].value_counts()
    baseline = k["vendor"] / (k["vendor"] + k["third"])
    cl = cl[cl["period"] >= START]
    cna = cl["assigner_short_name"]
    cl["big"] = cna.isin(BIG_THREE)

    t = pd.crosstab(cl["period"], cl["kind"])
    t["classified"] = t["vendor"] + t["third"]
    t["share"] = t["vendor"] / t["classified"]
    rest = cl[~cl["big"]]
    r = pd.crosstab(rest["period"], rest["kind"])
    t["share_ex_big"] = r["vendor"] / (r["vendor"] + r["third"])
    t["unclassified_pct"] = t["unclassified"] / (t["classified"] + t["unclassified"])
    t.attrs["baseline"] = baseline
    end = t.index[-1]
    t.attrs["partial"] = asof.normalize() < end.end_time.tz_localize(asof.tz).normalize()
    if t.attrs["partial"] and asof.day < MIN_PARTIAL_DAYS:
        t = t.iloc[:-1].copy()
        t.attrs.update(baseline=baseline, partial=False)
    return t, asof


def render(nvd=None, ratios=DEFAULT_RATIOS):
    t, asof = _table()
    x = list(range(len(t)))
    labels = [f"Jan\n{p.year}" if p.month == 1
              else (p.strftime("%b") if p.month in (4, 7, 10) else "")
              for p in t.index]
    partial = t.attrs["partial"]
    star = "*" if partial else ""
    labels[-1] = f"{t.index[-1].strftime('%b')}{star}"

    title = "Share of CVEs Published by the Product's Own Vendor"
    subtitle = "By publication month, CVE List V5; the rest are third-party CNAs"
    base = t.attrs["baseline"]
    last = len(t) - 1

    out = []
    for ratio in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(ratio))
        lw = {"wide": 3.2, "square": 2.8, "portrait": 2.8}[ratio]
        fs = {"wide": 11.5, "square": 10, "portrait": 10}[ratio]

        ax.axhline(base, color=COLORS["secondary"], lw=1.0, ls=(0, (5, 4)),
                   zorder=2, alpha=0.7)
        # The last month is partial: solid through the last full month, then
        # a dashed segment to a hollow marker so it does not read as final.
        for col, color, w, ms, z, lab in (
                ("share", COLORS["primary"], lw, lw * 1.6, 4, "All CNAs"),
                ("share_ex_big", GREY_LINE, lw * 0.9, lw * 1.3, 3,
                 "Excluding Linux kernel, Microsoft, Oracle")):
            y = t[col]
            if not partial:
                ax.plot(x, y, color=color, lw=w, zorder=z, marker="o", ms=ms,
                        label=lab)
                continue
            ax.plot(x[:last], y.iloc[:last], color=color, lw=w, zorder=z,
                    marker="o", ms=ms, label=lab)
            ax.plot(x[last - 1:], y.iloc[last - 1:], color=color, lw=w,
                    zorder=z, ls=(0, (2, 1.5)))
            ax.plot(x[last], y.iloc[last], color=color, marker="o", ms=ms,
                    mfc="white", mec=color, mew=w * 0.7, zorder=z + 1)

        # Direct labels on the two endpoints only. The March trough is in the
        # copy: floated between the lines it read as belonging to either one.
        for col, color in (("share", COLORS["primary"]),
                           ("share_ex_big", GREY_TEXT)):
            ax.annotate(f"{t[col].iloc[-1]:.0%}{star}", (last, t[col].iloc[-1]),
                        textcoords="offset points", xytext=(8, 0), ha="left",
                        va="center", fontsize=fs + 1, fontweight="bold",
                        color=color, zorder=6)
        ax.text(0, base + 0.015,
                f"{BASE_YEARS[0]}–{BASE_YEARS[1]} average, {base:.0%}",
                fontsize=fs - 1.5, color=COLORS["secondary"], ha="left",
                va="bottom")

        ax.set_xticks(x)
        ax.set_xticklabels(labels, fontsize={"wide": 10.5, "square": 9.5,
                                             "portrait": 9.5}[ratio])
        ax.tick_params(axis="x", length=0)
        ax.yaxis.set_major_formatter(PercentFormatter(1.0, decimals=0))
        ax.set_ylim(0, 0.7)
        ax.set_xlim(-0.6, len(t) - 0.1 + {"wide": 0.9, "square": 1.4,
                                          "portrait": 1.4}[ratio])
        ax.set_axisbelow(True)
        ax.grid(axis="y", color=COLORS["grid"], lw=0.6, alpha=0.8)
        for side in ("top", "right"):
            ax.spines[side].set_visible(False)

        leg = ax.legend(loc="lower left", frameon=False, fontsize=fs - 0.5,
                        handlelength=1.8, labelspacing=0.45)
        for txt in leg.get_texts():
            txt.set_color(COLORS["secondary"])

        top = {"wide": 0.77, "square": 0.78, "portrait": 0.82}[ratio]
        bottom_m = {"wide": 0.17, "square": 0.16, "portrait": 0.13}[ratio]
        left_m = {"wide": 0.075, "square": 0.105, "portrait": 0.115}[ratio]
        fig.subplots_adjust(top=top, bottom=bottom_m, left=left_m, right=0.965)
        draw_header(fig, title, subtitle, ratio, eyebrow_suffix="CNA Share",
                    title_size={"wide": 26, "square": 19, "portrait": 19}[ratio])

        foot = {"wide": 9.5, "square": 8.0, "portrait": 8.0}[ratio]
        note = "A CVE counts as the vendor's when its CNA maintains the product."
        if partial:
            note = f"*Partial month, through {asof:%b %-d, %Y}. " + note
        fig.text(0.05, 0.055, note,
                 fontsize=foot, color=COLORS["secondary"], ha="left",
                 va="bottom")

        path = GRAPHS / f"vendor_share_{ratio}_{asof:%Y-%m-%d}.png"
        out.append(stamp_and_save(fig, path))
    return out


def stats():
    t, asof = _table()
    yr = t[t.index.year == t.index[-1].year]
    return {
        "asof": asof.date(),
        "latest_share": round(100 * t["share"].iloc[-1], 1),
        "latest_ex_big": round(100 * t["share_ex_big"].iloc[-1], 1),
        "trough_month": str(yr["share"].idxmin()),
        "trough_share": round(100 * yr["share"].min(), 1),
        "trough_ex_big": round(100 * yr["share_ex_big"].min(), 1),
        "trough_ex_big_month": str(yr["share_ex_big"].idxmin()),
        "prior_max_share": round(100 * t["share"].iloc[:-1].max(), 1),
        "prior_max_month": str(t["share"].iloc[:-1].idxmax()),
        "max_unclassified_pct": round(100 * t["unclassified_pct"].max(), 1),
        "table": t[["vendor", "third", "unclassified", "share",
                    "share_ex_big"]].round(3).to_string(),
    }


if __name__ == "__main__":
    for key, val in stats().items():
        print(f"{key:>20}: {val}")
    for p in render():
        print(p)

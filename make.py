#!/usr/bin/env python3
"""
CVEGraphs render CLI.

    python make.py pace        # render one chart (all aspect ratios)
    python make.py all         # render the whole shelf
    python make.py list        # list available charts

Charts register themselves in CHARTS below. Each render() returns the list of
output paths written to graphs/.
"""

import sys

from data import load_nvd
from rolling_config import data_asof, today_utc
from charts import (
    calendar_heatmap,
    camp_week,
    chrome_day,
    credit_rise,
    daily_rate,
    cna,
    cna_bump,
    cna_burst,
    cna_metric_table,
    cna_spread,
    cvss_epss_gap,
    cvss_epss_scatter,
    cvss_v4_adoption,
    exploited_cwe,
    kev_severity,
    kev_timing,
    foxit_batch,
    product_id,
    cwe_circles,
    cwe_kev,
    cwe_spread,
    epss_funnel,
    kev,
    pace,
    ridgeline_severity,
    scorer_divergence,
    second_burst,
    two_year_overtake,
    waffle_exploit,
    yoy_month_growth,
)

# name -> (module, one-line description)
CHARTS = {
    "pace": (pace, "YTD pace tracker: CVEs so far this year, apples-to-apples"),
    "daily_rate": (daily_rate, "Line: CVEs published per day this year, 7-day rolling average"),
    "yoy_month_growth": (yoy_month_growth, "Ranked bars: biggest year-over-year jumps in monthly CVE volume"),
    "two_year_overtake": (two_year_overtake, "Line: calendar day each year passes the full CVE total from two years earlier"),
    "credit_rise": (credit_rise, "Bars: share of CVEs that credit a finder/reporter, by year (2% -> 51%)"),
    "epss_funnel": (epss_funnel, "Exploitation signal: EPSS + KEV vs total volume"),
    "cna": (cna, "CNA leaderboard: who publishes this year's CVEs"),
    "kev": (kev, "KEV watch: confirmed exploitation over the trailing 12 months"),
    "chrome_day": (chrome_day, "Chrome Day vs Patch Tuesday: biggest single-day drops"),
    "cvss_epss_gap": (cvss_epss_gap, "CVSS vs EPSS: severe on paper, quiet in the wild"),
    "cvss_epss_scatter": (cvss_epss_scatter, "Scatter: 2026 critical (9.0+) CVEs, CVSS vs EPSS; how few clear the danger band"),
    "scorer_divergence": (scorer_divergence, "Dumbbell: same bug, different scorer, different CVSS v4-v3 shift"),
    "cvss_v4_adoption": (cvss_v4_adoption, "Stacked bars: CVSS v4 adoption by year, 3 heavy-adopter CNAs vs the rest"),
    "cna_spread": (cna_spread, "Range chart: one weakness class (XSS), how CNAs disagree on CVSS"),
    "cna_metric_table": (cna_metric_table, "Table: underlying CVSS v3 metrics behind the XSS spread, by CNA"),
    "cwe_spread": (cwe_spread, "Range chart: top 10 CWEs, CVSS v3 80% range and median"),
    "cwe_kev": (cwe_kev, "Bars: KEV (exploited) rate by CWE vs CVSS median"),
    "exploited_cwe": (exploited_cwe, "Bars: which weakness classes carry the most KEV (exploited) CVEs"),
    "kev_severity": (kev_severity, "Bubble strip: full CVSS v3 spread of KEV (exploited) CVEs, by weakness class"),
    "kev_timing": (kev_timing, "Bars: how old a CVE is when CISA adds it to KEV (age at exploitation)"),
    "foxit_batch": (foxit_batch, "CVSS dot-plot (one-off): Foxit PDF Editor's 28-CVE single-day memory-safety batch"),
    "product_id": (product_id, "Bars: how CVEs identify affected products (CPE vs PURL vs free text)"),
    "calendar_heatmap": (calendar_heatmap, "Calendar heatmap: a year of daily CVE publishing"),
    "camp_week": (camp_week, "Strip plot: CVE volume in Black Hat / DEF CON week vs the 12 nearby weeks, 2016-2025"),
    "waffle_exploit": (waffle_exploit, "Waffle: 1,000 CVEs, how few are exploited"),
    "ridgeline_severity": (ridgeline_severity, "Ridgeline: CVSS distribution by year"),
    "cna_bump": (cna_bump, "Bump chart: monthly CNA rank flow"),
    "second_burst": (second_burst, "Ranked bars: largest verifiable single-second CVE publishing bursts"),
    "cna_burst": (cna_burst, "Ranked bars: biggest single-day CVE batches by one CNA (modern era)"),
    "cwe_circles": (cwe_circles, "Circle pack: CWEs sized by count, colored by CVSS"),
}


def _warn_if_stale(nvd, max_age=2):
    """Charts stamp today's date, so guard against a fresh stamp on stale data."""
    age = (today_utc() - data_asof(nvd)).days
    if age > max_age:
        bar = "!" * 70
        print(f"\n{bar}")
        print(f"  WARNING: data is {age} days old (latest CVE {data_asof(nvd).date()}).")
        print("  Charts stamp TODAY's date, so this puts a fresh stamp on stale data.")
        print("  Run  python refresh_data.py  before rendering to post.")
        print(f"{bar}\n")


def _render(name, nvd):
    module, _ = CHARTS[name]
    print(f"Rendering {name} ...")
    for path in module.render(nvd=nvd):
        print(f"  wrote {path}")


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0

    cmd = argv[0]
    if cmd == "list":
        for name, (_, desc) in CHARTS.items():
            print(f"  {name:12s} {desc}")
        return 0

    # Load data once and share it across every chart in this run.
    nvd = load_nvd()
    _warn_if_stale(nvd)

    if cmd == "all":
        for name in CHARTS:
            _render(name, nvd)
        return 0

    if cmd in CHARTS:
        _render(cmd, nvd)
        return 0

    print(f"Unknown chart '{cmd}'. Try: {', '.join(CHARTS)} | all | list")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

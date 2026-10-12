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
    daily_count,
    cna,
    cna_bump,
    cna_burst,
    cna_peak_day,
    cna_weekend,
    cna_top_days,
    cna_metric_table,
    cisco_rollup,
    cna_spread,
    cvss_epss_gap,
    cvss_epss_scatter,
    cvss_v4_adoption,
    exploited_cwe,
    kev_severity,
    kev_timing,
    kev_fast_listing,
    kev_weekend,
    kev_triage,
    foxit_batch,
    product_id,
    cwe_circles,
    cwe_cna_rank,
    cwe_kev,
    cwe_provenance,
    cwe787_alone,
    cwe_spread,
    detection_breadth,
    detection_coverage,
    epss_early_warning,
    epss_early_warning_lines,
    epss_early_warning_pct,
    epss_funnel,
    epss_gain,
    epss_kev_window,
    epss_kev_window_pct,
    epss_report_card,
    eu_kev_evidence,
    eu_kev_overlay,
    ghsa_output,
    kev,
    earliest_overtake,
    pace,
    nvd_deferred,
    patch_tuesday,
    vendor_share,
    month_pace,
    patch_tag,
    ridgeline_severity,
    score_disagreement,
    scorer_divergence,
    second_burst,
    two_year_overtake,
    waffle_exploit,
    yoy_month_growth,
)

# name -> (module, one-line description)
CHARTS = {
    "earliest_overtake": (earliest_overtake, "Lollipop: the earliest a year passed the previous year's full CVE total, top 10"),
    "pace": (pace, "YTD pace tracker: CVEs so far this year, apples-to-apples"),
    "daily_count": (daily_count, "Bars + line: CVEs published each day this year with the 7-day rolling average"),
    "daily_rate": (daily_rate, "Line: CVEs published per day this year, 7-day rolling average"),
    "yoy_month_growth": (yoy_month_growth, "Ranked bars: biggest year-over-year jumps in monthly CVE volume"),
    "two_year_overtake": (two_year_overtake, "Line: calendar day each year passes the full CVE total from two years earlier"),
    "credit_rise": (credit_rise, "Bars: share of CVEs that credit a finder/reporter, by year (2% -> 51%)"),
    "epss_funnel": (epss_funnel, "Exploitation signal: EPSS + KEV vs total volume"),
    "epss_report_card": (epss_report_card, "Paired bars: what EPSS and CVSS had flagged 30 days before each 2026 KEV addition"),
    "epss_gain": (epss_gain, "Gain curves: coverage vs effort for EPSS and CVSS against 2026 KEV additions, split by age"),
    "epss_early_warning": (epss_early_warning, "Stacked bands: EPSS score at 90/60/30/15/7/1 days before each 2026 KEV addition, fixed cohort"),
    "epss_early_warning_lines": (epss_early_warning_lines, "Spaghetti lines: one path per CVE across the six lookbacks, cohort average in navy (log scale)"),
    "epss_kev_window": (epss_kev_window, "Spaghetti lines: EPSS from 60 days before to 60 days after the KEV listing; the score steps at +1"),
    "epss_early_warning_pct": (epss_early_warning_pct, "Percentile view of the before-only paths: linear axis, retrain-proof robustness check"),
    "epss_kev_window_pct": (epss_kev_window_pct, "Percentile view of the before/after window: the step is a move within the top of the distribution"),
    "cna": (cna, "CNA leaderboard: who publishes this year's CVEs"),
    "kev": (kev, "KEV watch: confirmed exploitation over the trailing 12 months"),
    "kev_fast_listing": (kev_fast_listing, "Stacked bars: KEV additions per month since Jul 2022, split by whether the CVE was under a week old"),
    "kev_weekend": (kev_weekend, "Bars: KEV additions by day of the week, with every weekend addition listed"),
    "kev_triage": (kev_triage, "Unit dots: 2026 KEV additions by week, split by whether CISA also requires forensic triage"),
    "chrome_day": (chrome_day, "Chrome Day vs Patch Tuesday: biggest single-day drops"),
    "cvss_epss_gap": (cvss_epss_gap, "CVSS vs EPSS: severe on paper, quiet in the wild"),
    "cvss_epss_scatter": (cvss_epss_scatter, "Scatter: 2026 critical (9.0+) CVEs, CVSS vs EPSS; how few clear the danger band"),
    "scorer_divergence": (scorer_divergence, "Dumbbell: same bug, different scorer, different CVSS v4-v3 shift"),
    "score_disagreement": (score_disagreement, "Agreement plot: same CVE scored by its CNA and by NVD/CISA, band flips in red"),
    "cvss_v4_adoption": (cvss_v4_adoption, "Stacked bars: CVSS v4 adoption by year, 3 heavy-adopter CNAs vs the rest"),
    "cna_spread": (cna_spread, "Range chart: one weakness class (XSS), how CNAs disagree on CVSS"),
    "cna_metric_table": (cna_metric_table, "Table: underlying CVSS v3 metrics behind the XSS spread, by CNA"),
    "cwe_spread": (cwe_spread, "Range chart: top 10 CWEs, CVSS v3 80% range and median"),
    "cwe_kev": (cwe_kev, "Bars: KEV (exploited) rate by CWE vs CVSS median"),
    "cwe_cna_rank": (cwe_cna_rank, "Ranked bars: CWE coverage by CNA this year, best to worst"),
    "cwe787_alone": (cwe787_alone, "Stacked bars: CVEs whose CNA listed CWE-787 alone vs with another CWE, by year"),
    "cwe_provenance": (cwe_provenance, "Lines: share of CVEs whose own CNA supplied the CWE, KEV vs all, by year"),
    "detection_coverage": (detection_coverage, "Ranked bars: share of KEV CVEs each vendor has that an open-source rule names by CVE ID"),
    "detection_breadth": (detection_breadth, "Bars: distinct CVE IDs named by each open ruleset, defensive vs offense-side"),
    "exploited_cwe": (exploited_cwe, "Bars: which weakness classes carry the most KEV (exploited) CVEs"),
    "kev_severity": (kev_severity, "Bubble strip: full CVSS v3 spread of KEV (exploited) CVEs, by weakness class"),
    "eu_kev_evidence": (eu_kev_evidence, "Table: EU KEV entries that differ from CISA KEV, graded by evidence"),
    "eu_kev_overlay": (eu_kev_overlay, "Step lines: ENISA EUVD exploited list overlaid on CISA KEV, cumulative"),
    "kev_timing": (kev_timing, "Bars: how old a CVE is when CISA adds it to KEV (age at exploitation)"),
    "foxit_batch": (foxit_batch, "CVSS dot-plot (one-off): Foxit PDF Editor's 28-CVE single-day memory-safety batch"),
    "nvd_deferred": (nvd_deferred, "Ranked bars: share of each CNA's settled CVEs that NVD marked Deferred (no CPE, no NVD score)"),
    "patch_tag": (patch_tag, "Ranked bars: share of each CNA's CVEs with a reference tagged patch, plus untagged fix links"),
    "product_id": (product_id, "Bars: how CVEs identify affected products (CPE vs PURL vs free text)"),
    "calendar_heatmap": (calendar_heatmap, "Calendar heatmap: a year of daily CVE publishing"),
    "camp_week": (camp_week, "Strip plot: CVE volume in Black Hat / DEF CON week vs the 12 nearby weeks, 2016-2025"),
    "waffle_exploit": (waffle_exploit, "Waffle: 1,000 CVEs, how few are exploited"),
    "ridgeline_severity": (ridgeline_severity, "Ridgeline: CVSS distribution by year"),
    "cna_bump": (cna_bump, "Bump chart: monthly CNA rank flow"),
    "second_burst": (second_burst, "Ranked bars: largest verifiable single-second CVE publishing bursts"),
    "patch_tuesday": (patch_tuesday, "Stacked bars: CVEs on each of the last 24 Patch Tuesdays, memory safety vs everything else"),
    "cna_burst": (cna_burst, "Ranked bars: biggest single-day CVE batches by one CNA (modern era)"),
    "cna_peak_day": (cna_peak_day, "Ranked bars: each CNA's biggest single publishing day, Oracle and Microsoft highlighted"),
    "cna_weekend": (cna_weekend, "Timesheet grid: CVEs by day of week for the 16 largest CNAs, weekend columns in red"),
    "cna_top_days": (cna_top_days, "Ranked bars: biggest single-CNA days, 2017 to date (a CNA can repeat)"),
    "cwe_circles": (cwe_circles, "Circle pack: CWEs sized by count, colored by CVSS"),
    "vendor_share": (vendor_share, "Lines: monthly share of CVEs published by the product's own vendor CNA, with and without Linux/Microsoft/Oracle"),
    "month_pace": (month_pace, "Cumulative lines: CVEs by day of month for each month this year, against the monthly record"),
    "cisco_rollup": (cisco_rollup, "Stacked bars: Cisco CVEs that bundle several vulnerabilities into one ID, by month"),
    "ghsa_output": (ghsa_output, "Bars: advisories GitHub reviewed into its database each month, against the 2025 average"),
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

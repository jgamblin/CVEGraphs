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
from charts import (
    calendar_heatmap,
    chrome_day,
    cna,
    cna_bump,
    cna_metric_table,
    cna_spread,
    cvss_epss_gap,
    cwe_circles,
    cwe_spread,
    epss_funnel,
    kev,
    pace,
    ridgeline_severity,
    scorer_divergence,
    waffle_exploit,
)

# name -> (module, one-line description)
CHARTS = {
    "pace": (pace, "YTD pace tracker: CVEs so far this year, apples-to-apples"),
    "epss_funnel": (epss_funnel, "Exploitation signal: EPSS + KEV vs total volume"),
    "cna": (cna, "CNA leaderboard: who publishes this year's CVEs"),
    "kev": (kev, "KEV watch: confirmed exploitation over the trailing 12 months"),
    "chrome_day": (chrome_day, "Chrome Day vs Patch Tuesday: biggest single-day drops"),
    "cvss_epss_gap": (cvss_epss_gap, "CVSS vs EPSS: severe on paper, quiet in the wild"),
    "scorer_divergence": (scorer_divergence, "Dumbbell: same bug, different scorer, different CVSS v4-v3 shift"),
    "cna_spread": (cna_spread, "Range chart: one weakness class (XSS), how CNAs disagree on CVSS"),
    "cna_metric_table": (cna_metric_table, "Table: underlying CVSS v3 metrics behind the XSS spread, by CNA"),
    "cwe_spread": (cwe_spread, "Range chart: top 10 CWEs, CVSS v3 80% range and median"),
    "calendar_heatmap": (calendar_heatmap, "Calendar heatmap: a year of daily CVE publishing"),
    "waffle_exploit": (waffle_exploit, "Waffle: 1,000 CVEs, how few are exploited"),
    "ridgeline_severity": (ridgeline_severity, "Ridgeline: CVSS distribution by year"),
    "cna_bump": (cna_bump, "Bump chart: monthly CNA rank flow"),
    "cwe_circles": (cwe_circles, "Circle pack: CWEs sized by count, colored by CVSS"),
}


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

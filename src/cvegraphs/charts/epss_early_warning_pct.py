#!/usr/bin/env python3
"""
EPSS Early Warning, per-CVE paths, PERCENTILE view.

A thin registration wrapper: the implementation lives in
``charts.epss_early_warning_lines``, which renders either metric. This module
exists so the registry can dispatch the percentile version by name, since the
shelf maps one name to one module.

Percentile is each CVE's rank among all scored CVEs, so a model retrain cannot
move it the way it moves the raw probability. That makes this the robustness
check on the flatness finding, and it reframes it: in relative terms EPSS had
already ranked this cohort highly long before CISA acted.
"""

from cvegraphs.charts.epss_early_warning_lines import render as _render
from cvegraphs.style import DEFAULT_RATIOS

DESCRIPTION = "Percentile view of the before-only paths: linear axis, retrain-proof robustness check"


def render(nvd=None, ratios=DEFAULT_RATIOS):
    return _render(nvd=nvd, ratios=ratios, metric="percentile")


if __name__ == "__main__":
    for p in render():
        print(p)

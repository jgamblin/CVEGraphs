#!/usr/bin/env python3
"""
EPSS around the KEV listing, PERCENTILE view.

A thin registration wrapper: the implementation lives in
``charts.epss_kev_window``, which renders either metric. This module exists so
the registry can dispatch the percentile version by name, since the shelf maps
one name to one module.

The percentile view changes what the post-listing step means. In raw-score terms
the median goes 0.09 to 0.51 and looks like a discovery. In rank terms the
cohort was already at the 93rd percentile the day before the listing and moves
to the 98th, so the step is a shuffle within the top of the distribution rather
than EPSS noticing these CVEs for the first time. Both readings are true of the
same data; this one is the harder to overclaim from.
"""

from cvegraphs.charts.epss_kev_window import render as _render
from cvegraphs.style import DEFAULT_RATIOS

DESCRIPTION = "Percentile view of the before/after window: the step is a move within the top of the distribution"


def render(nvd=None, ratios=DEFAULT_RATIOS):
    return _render(nvd=nvd, ratios=ratios, metric="percentile")


if __name__ == "__main__":
    for p in render():
        print(p)

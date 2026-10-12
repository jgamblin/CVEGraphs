"""Data rules that have a testable home in code. See docs/data-rules.md for the
full list; most are applied inline in the chart that needs them."""

import pandas as pd

from cvegraphs.charts import nvd_deferred


def test_deferred_share_counts_only_settled_records():
    # Deferred is only meaningful among records NVD has finished with; a
    # CVE still Awaiting Analysis must not dilute (or inflate) the share.
    asof = pd.Timestamp("2026-10-09", tz="UTC")
    n = nvd_deferred.MIN_CVES
    rows = (
        [("big", "Deferred")] * n + [("big", "Analyzed")] * n
        + [("big", "Awaiting Analysis")] * (5 * n)
    )
    df = pd.DataFrame({
        "cve_id": [f"CVE-2026-{i}" for i in range(len(rows))],
        "assigner_short_name": [r[0] for r in rows],
        "vuln_status": [r[1] for r in rows],
        "published": pd.Timestamp("2026-06-01", tz="UTC"),
    })
    out, overall, settled, deferred, covered, pending, cur = nvd_deferred._rows(df, asof)
    assert (settled, deferred, pending, cur) == (2 * n, n, 5 * n, 2026)
    assert overall == 50.0 and out[0]["rate"] == 50.0

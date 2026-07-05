#!/usr/bin/env python3
"""
Data loading for CVEGraphs.

Reads the processed NVD / CVE List V5 parquet snapshots. Prefers a local
``processed/`` directory (populated by ``refresh_data.py``); during bring-up it
falls back to the proven snapshot in the sibling H12026CVEBlog repo so charts
can render on real data immediately.

Schema (NVD parquet): cve_id, year, cve_year, published, modified, description,
cvss_v2, cvss_v3, cvss_v4, severity, cwe, cpe_count, has_cpe, vendor, product,
ref_count, vuln_status, is_rejected.
"""

from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
LOCAL = HERE / "processed"  # this repo's own authoritative data copy


def _source_dir():
    """Directory to read parquet from.

    The local ``processed/`` copy is authoritative: this repo keeps its OWN data
    so it never silently depends on a sibling checkout. If the local copy is
    missing we fail loudly and point at refresh_data.py rather than quietly
    reading from the seed repo.
    """
    if (LOCAL / "nvd_cves.parquet").exists():
        return LOCAL
    raise FileNotFoundError(
        f"No local snapshot at {LOCAL}. Run `python refresh_data.py` to populate "
        "this repo's own copy of the data before rendering."
    )


def load_nvd(include_rejected=False, with_epss=False):
    """Load the NVD CVE frame, rejected rows dropped by default.

    with_epss=True left-joins EPSS ``epss`` and ``percentile`` columns by CVE id
    (NaN for CVEs that have no EPSS score yet).
    """
    df = pd.read_parquet(_source_dir() / "nvd_cves.parquet")
    if not include_rejected and "is_rejected" in df.columns:
        df = df[~df["is_rejected"]]
    if with_epss:
        epss = load_epss()[["cve_id", "epss", "percentile"]]
        df = df.merge(epss, on="cve_id", how="left")
    return df


def load_epss():
    """Load the EPSS score frame (cve_id, epss, percentile, score_date, ...)."""
    return pd.read_parquet(_source_dir() / "epss.parquet")


def load_cvelist(include_rejected=False):
    """Load the CVE List V5 frame, rejected rows dropped by default."""
    df = pd.read_parquet(_source_dir() / "cvelist_v5.parquet")
    if not include_rejected and "is_rejected" in df.columns:
        df = df[~df["is_rejected"]]
    return df


if __name__ == "__main__":
    nvd = load_nvd()
    print(f"Source: {_source_dir()}")
    print(f"NVD rows (published): {len(nvd):,}")
    print(f"Newest published: {nvd['published'].max()}")

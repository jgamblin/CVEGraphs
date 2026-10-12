#!/usr/bin/env python3
"""
Precompute per-CVE product-identifier flags from the raw CVE List V5 clone.

Cohort is CVEs PUBLISHED in the latest year, not CVE-<year>-* IDs: a CVE
published in 2026 can carry a 2025 (or older) ID, and counting by ID year
undercounts the real year's volume by ~18% (it would read ~31.5k vs the ~38k
that cve.icu and everyone else means by "2026 CVEs"). So we take the published
set from the CVE List parquet and read only those raw records for their
CNA-authored CPE / PURL flags.

Writes processed/product_id_cve_flags.parquet: cve_id, year (publication year),
cpe_cna (a CNA-container `cpe:2.3`/`cpe:/` string), purl (a `pkg:` string). The
product_id chart joins this to NVD's enriched has_cpe on the same cohort.
"""

import json
import os

import pandas as pd

from cvegraphs.paths import DATA, PROCESSED

ROOT = DATA / "cvelistV5" / "cves"
CVELIST = PROCESSED / "cvelist_v5.parquet"
OUT_FLAGS = PROCESSED / "product_id_cve_flags.parquet"


def _latest_year(cl):
    """Most recent publication year with real volume (ignores stray future dates)."""
    yr = pd.to_datetime(cl["date_published"], utc=True, errors="coerce").dt.year
    counts = yr[cl["is_rejected"] != True].value_counts()
    return int(counts[counts >= 1000].index.max())


def main():
    cl = pd.read_parquet(CVELIST, columns=["cve_id", "date_published", "is_rejected"])
    year = _latest_year(cl)
    pub_year = pd.to_datetime(cl["date_published"], utc=True, errors="coerce").dt.year
    target = set(cl[(pub_year == year) & (cl["is_rejected"] != True)]["cve_id"])
    print(f"  target: {len(target):,} CVEs published in {year}")

    # Walk the clone by filename (cheap); only open the raw JSON for target CVEs.
    rows = []
    for dirpath, _, files in os.walk(ROOT):
        for name in files:
            if not (name.startswith("CVE-") and name.endswith(".json")):
                continue
            cid = name[:-5]
            if cid not in target:
                continue
            try:
                d = json.load(open(os.path.join(dirpath, name)))
            except Exception:
                continue
            blob = json.dumps(d.get("containers", {}).get("cna", {}))
            rows.append((cid, year,
                         ("cpe:2.3" in blob) or ("cpe:/" in blob),
                         "pkg:" in blob))

    df = pd.DataFrame(rows, columns=["cve_id", "year", "cpe_cna", "purl"]).drop_duplicates("cve_id")
    OUT_FLAGS.parent.mkdir(exist_ok=True)
    df.to_parquet(OUT_FLAGS, index=False)
    print(f"wrote {OUT_FLAGS} ({len(df):,} rows for {year}): "
          f"CPE {100 * df['cpe_cna'].mean():.1f}%, PURL {100 * df['purl'].mean():.1f}%")


if __name__ == "__main__":
    main()

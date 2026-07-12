#!/usr/bin/env python3
"""
Precompute per-year product-identifier coverage from the raw CVE List V5 clone.

For each publication year, count how many non-rejected CVE records carry, in the
CNA container as authored:
  - CPE (an affected[].cpes entry or a cpeApplicability block)
  - PURL (a "pkg:" package URL string)
  - any package-style id (PURL, packageName, or collectionURL)
  - nothing machine-readable (a bare vendor/product free-text record)

Writes processed/product_id_coverage.parquet. Cheap enough to re-run after a
refresh; kept separate from the main parquet build so it can evolve on its own.
"""

import json
import glob
import os
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE / "data" / "cvelistV5" / "cves"
OUT = HERE / "processed" / "product_id_coverage.parquet"
OUT_FLAGS = HERE / "processed" / "product_id_cve_flags.parquet"
YEARS = ["2022", "2023", "2024", "2025", "2026"]


def scan_year(yr, collect=False):
    n = cpe = purl = fam = bare = 0
    flags = []
    for fp in glob.glob(os.path.join(ROOT, yr, "**", "CVE-*.json"), recursive=True):
        try:
            d = json.load(open(fp))
        except Exception:
            continue
        if d.get("cveMetadata", {}).get("state") == "REJECTED":
            continue
        cna = d.get("containers", {}).get("cna", {})
        blob = json.dumps(cna)
        n += 1
        has_cpe = ("cpe:2.3" in blob) or ("cpe:/" in blob)
        has_purl = "pkg:" in blob
        has_fam = has_purl or ('"packageName"' in blob) or ('"collectionURL"' in blob)
        if has_cpe:
            cpe += 1
        if has_purl:
            purl += 1
        if has_fam:
            fam += 1
        if not (has_cpe or has_fam):
            bare += 1
        if collect:
            cid = d.get("cveMetadata", {}).get("cveId")
            if cid:
                flags.append((cid, has_cpe, has_purl))
    agg = {"year": int(yr), "records": n, "cpe": cpe, "purl": purl,
           "pkg_family": fam, "bare": bare}
    return (agg, flags) if collect else agg


def main():
    rows = []
    latest = max(int(y) for y in YEARS)
    for yr in YEARS:
        collect = int(yr) == latest  # keep per-CVE flags for the newest year
        res = scan_year(yr, collect=collect)
        r, flags = res if collect else (res, None)
        if r["records"]:
            rows.append(r)
            print(f"  {yr}: {r['records']:,} records, "
                  f"CPE {r['cpe']/r['records']*100:.1f}%, "
                  f"PURL {r['purl']/r['records']*100:.1f}%, "
                  f"bare {r['bare']/r['records']*100:.1f}%")
        if collect and flags:
            fdf = pd.DataFrame(flags, columns=["cve_id", "cpe_cna", "purl"]).drop_duplicates("cve_id")
            fdf["year"] = int(yr)
            OUT_FLAGS.parent.mkdir(exist_ok=True)
            fdf.to_parquet(OUT_FLAGS, index=False)
            print(f"wrote {OUT_FLAGS} ({len(fdf):,} rows for {yr})")
    df = pd.DataFrame(rows)
    OUT.parent.mkdir(exist_ok=True)
    df.to_parquet(OUT, index=False)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()

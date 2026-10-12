#!/usr/bin/env python3
"""
Precompute per-CVE credit counts from the raw CVE List V5 clone.

The CVE.org record carries a `containers.cna.credits[]` array naming who found or
reported the bug. That field is NOT in our processed parquet, so we walk the raw
JSON once and record, per non-rejected CVE, how many credit entries it has and how
many are discoverer roles (finder / reporter).

Caveat baked into the data, not fixed here: entry count != people count. Some CNAs
write one credit entry per person; others (e.g. F5 on CVE-2026-42533) cram a dozen
names into a single free-text entry. So `n_credits` is a floor on the number of
people credited, and the `credit_rise` chart uses it only to ask "does the record
credit anyone at all," where the entry/name distinction does not matter.

Writes processed/credits_flags.parquet: cve_id, year (CVE-ID year), n_credits,
n_finder.
"""

import glob
import json

import pandas as pd

from cvegraphs.paths import DATA, PROCESSED

ROOT = DATA / "cvelistV5" / "cves"
OUT = PROCESSED / "credits_flags.parquet"

FINDER_ROLES = {"finder", "reporter"}


def main():
    rows = []
    for f in glob.glob(str(ROOT / "**" / "*.json"), recursive=True):
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if not isinstance(d, dict):
            continue
        meta = d.get("cveMetadata", {})
        if not isinstance(meta, dict):
            continue
        cid = meta.get("cveId")
        if not cid or not cid.startswith("CVE-") or meta.get("state") == "REJECTED":
            continue
        cna = d.get("containers", {}).get("cna", {})
        if not isinstance(cna, dict):
            continue
        cr = cna.get("credits", []) or []
        if not isinstance(cr, list):
            cr = []
        n_finder = sum(1 for c in cr if isinstance(c, dict)
                       and (c.get("type") or "finder") in FINDER_ROLES)
        try:
            year = int(cid.split("-")[1])
        except (IndexError, ValueError):
            year = None
        rows.append((cid, year, len(cr), n_finder))

    df = pd.DataFrame(rows, columns=["cve_id", "year", "n_credits", "n_finder"])
    df = df.dropna(subset=["year"])
    df["year"] = df["year"].astype(int)
    OUT.parent.mkdir(exist_ok=True)
    df.to_parquet(OUT, index=False)
    print(f"[credits] wrote {OUT} ({len(df):,} CVEs, "
          f"{100 * (df['n_credits'] > 0).mean():.1f}% credited)")


if __name__ == "__main__":
    main()

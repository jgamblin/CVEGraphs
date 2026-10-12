#!/usr/bin/env python3
"""
Precompute the full CNA-supplied CWE list for every CVE that names CWE-787.

The main parquet keeps only the FIRST CWE a CNA listed plus a raw count, which
is enough to find records where CWE-787 is the only weakness (if it is the only
one it is also the first) but undercounts records that list CWE-787 alongside a
root cause (CWE-190, CWE-131 ...) when 787 is not written first. This script
scans the raw CVE List V5 clone and writes one row per published CVE whose CNA
container names CWE-787, with the de-duplicated CWE list, so the ``cwe787_alone``
chart can split "CWE-787 alone" from "CWE-787 with a chain" exactly.

The ADP container (CISA) is read too, but only to count how often the vendor
wrote nothing and CISA added CWE-787 for them. The chart is about the CNA's own
mapping, so those rows are kept out of the main series.

Writes processed/cwe787.parquet: cve_id, assigner_short_name, published,
cna_cwes, cna_n, cna_has_787, adp_cwes, adp_has_787.
"""

import json
import re
import sys
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
ROOT = HERE / "data" / "cvelistV5" / "cves"
OUT = HERE / "processed" / "cwe787.parquet"

CWE_IN_TEXT = re.compile(r"\bCWE-\d+", re.IGNORECASE)


def _cwes(container):
    """De-duplicated CWE ids in a container, accepting `cweId` or a literal
    "CWE-<n>" in the description (same rule as refresh_data.py)."""
    out = []
    for pt in container.get("problemTypes", []) or []:
        for d in pt.get("descriptions", []) or []:
            c = d.get("cweId")
            if not c:
                m = CWE_IN_TEXT.search(d.get("description") or "")
                c = m.group(0).upper() if m else None
            if c and c not in out:
                out.append(c)
    return out


def _one(path):
    try:
        text = path.read_text()
    except Exception:  # noqa: BLE001 - a broken file is skipped, not fatal
        return None
    if "787" not in text:  # cheap pre-filter; the JSON parse below is the real test
        return None
    rec = json.loads(text)
    meta = rec.get("cveMetadata", {})
    if meta.get("state") != "PUBLISHED":
        return None
    containers = rec.get("containers", {})
    cna_cwes = _cwes(containers.get("cna", {}))
    adp_cwes = []
    for adp in containers.get("adp", []) or []:
        for c in _cwes(adp):
            if c not in adp_cwes:
                adp_cwes.append(c)
    if "CWE-787" not in cna_cwes and "CWE-787" not in adp_cwes:
        return None
    return {
        "cve_id": meta.get("cveId"),
        "assigner_short_name": meta.get("assignerShortName", ""),
        "published": meta.get("datePublished"),
        "cna_cwes": "|".join(cna_cwes),
        "cna_n": len(cna_cwes),
        "cna_has_787": "CWE-787" in cna_cwes,
        "adp_cwes": "|".join(adp_cwes),
        "adp_has_787": "CWE-787" in adp_cwes,
    }


def main():
    files = list(ROOT.rglob("CVE-*.json"))
    print(f"[cwe787] scanning {len(files):,} records ...", file=sys.stderr)
    rows = [r for r in map(_one, files) if r]
    df = pd.DataFrame(rows)
    df["published"] = pd.to_datetime(df["published"], utc=True, errors="coerce", format="mixed")
    OUT.parent.mkdir(exist_ok=True)
    df.to_parquet(OUT, index=False)
    print(f"[cwe787] wrote {OUT} ({len(df):,} rows, "
          f"{int(df.cna_has_787.sum()):,} with CWE-787 from the CNA)", file=sys.stderr)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Precompute Cisco's rollup-vs-single-issue CVE split from the raw CVE List V5 clone.

A "rollup" CVE is one CVE ID that the record itself says covers more than one
vulnerability. Cisco writes two kinds:

* ``classic``  - the long-standing house phrasing, "Multiple vulnerabilities in the
  web-based management interface of X could allow ... to conduct a cross-site
  scripting (XSS) attack". One CVE, several instances of the SAME bug class. Cisco
  has done this for years at a rate of a handful a quarter.

* ``hardening`` - the "Security Hardening Release" program, first seen 2026-07-15.
  The description is boilerplate: an engineering team "conducted a comprehensive
  internal security review ... that addresses multiple internally discovered
  vulnerabilities", then "The vulnerabilities tracked by CVE-YYYY-NNNNN are related
  to <weakness> ... grouped under the Common Weakness Enumeration (CWE) CWE-N".
  One CVE per CWE bucket per product, each holding an UNDISCLOSED number of bugs.
  The record never states the count, so the true vulnerability total behind these
  CVEs is not recoverable from CVE data at all.

Why the description text and not a structured field: neither CVE List V5 nor NVD has
a "how many vulnerabilities does this CVE cover" field. The rollup is declared in
prose or nowhere, so prose is the only available signal.

Cisco's CNA scope also covers Splunk, ClamAV and Talos-branded products. Splunk-family
records keep Splunk's own house style ("In Splunk Enterprise versions below ...") and
arrive in large quarterly batches - 106 on 2026-08-19 alone - which swamps the Cisco
advisory series. They are tagged ``splunk-family`` here and the chart excludes them so
the denominator is Cisco-branded product advisories. ClamAV records use the standard
Cisco phrasing and stay in.

Writes processed/cisco_rollup.parquet: cve_id, date_published, bucket, cwe, advisory,
title, n_products.
"""

import glob
import json
import os
import re
from pathlib import Path

import pandas as pd

from cvegraphs.paths import DATA, PROCESSED

# The repo keeps its own cvelistV5 clone under data/, refreshed by `cvegraphs refresh`,
# and that stays the default so this script never silently depends on a checkout
# elsewhere on the machine. CVEGRAPHS_CVELIST_DIR points it at a different clone
# when you maintain one shared copy outside the repo and do not want to re-sync the
# in-repo one (or pay for a full `cvegraphs refresh` run) just to rebuild this dataset.
# Point it at the clone root, not at cves/.
_override = os.environ.get("CVEGRAPHS_CVELIST_DIR", "").strip()
CLONE = Path(_override).expanduser() if _override else DATA / "cvelistV5"
ROOT = CLONE / "cves"
OUT = PROCESSED / "cisco_rollup.parquet"

ASSIGNER = "cisco"
# Only years that can plausibly hold a recently published Cisco record. Cisco does
# not back-publish old IDs; the oldest CVE-ID year seen on a Cisco record published
# in the last two years is the prior calendar year.
SCAN_YEARS = ("2024", "2025", "2026")

HARDENING_MARK = "ongoing commitment to proactive security"
MULTI_OPENER = re.compile(r"^\s*(multiple|two|three|several)\s+vulnerabilit", re.I)
ADVISORY_RE = re.compile(r"CiscoSecurityAdvisory/(cisco-sa-[A-Za-z0-9_-]+)")


def classify(desc):
    """rollup kind, or the single/Splunk label, from the description prose."""
    if HARDENING_MARK in desc:
        return "hardening"
    if MULTI_OPENER.search(desc):
        return "classic"
    if desc.strip().lower().startswith("a vulnerability"):
        return "single"
    return "splunk-family"


def _clone_stamp():
    """Best-effort 'clone @ commit date' label for the run log."""
    import subprocess
    try:
        d = subprocess.run(["git", "-C", str(CLONE), "log", "-1", "--format=%cI"],
                           capture_output=True, text=True, timeout=10)
        head = d.stdout.strip()[:10] if d.returncode == 0 else "unknown"
    except Exception:
        head = "unknown"
    return f"{CLONE} @ {head}"


def main():
    if not ROOT.is_dir():
        raise FileNotFoundError(
            f"No cvelistV5 checkout at {ROOT}. Run `cvegraphs refresh`, or set "
            "CVEGRAPHS_CVELIST_DIR to an existing clone root."
        )
    print(f"  [cisco_rollup] source: {_clone_stamp()}")
    rows = []
    for y in SCAN_YEARS:
        for f in glob.glob(str(ROOT / y / "**" / "CVE-*.json"), recursive=True):
            try:
                d = json.load(open(f))
            except Exception:
                continue
            if not isinstance(d, dict):
                continue
            meta = d.get("cveMetadata", {})
            if not isinstance(meta, dict):
                continue
            if (meta.get("assignerShortName") or "").lower() != ASSIGNER:
                continue
            if meta.get("state") == "REJECTED":
                continue
            cna = d.get("containers", {}).get("cna", {})
            if not isinstance(cna, dict):
                continue

            desc = ""
            for x in cna.get("descriptions", []) or []:
                if isinstance(x, dict) and (x.get("lang") or "").startswith("en"):
                    desc = x.get("value") or ""
                    break
            if not desc:
                continue

            cwe = ""
            for pt in cna.get("problemTypes", []) or []:
                for x in (pt.get("descriptions", []) or []) if isinstance(pt, dict) else []:
                    if isinstance(x, dict) and x.get("cweId"):
                        cwe = x["cweId"]
                        break
                if cwe:
                    break

            advisory = ""
            for r in cna.get("references", []) or []:
                m = ADVISORY_RE.search(r.get("url", "") if isinstance(r, dict) else "")
                if m:
                    advisory = m.group(1)
                    break

            products = {a.get("product") for a in (cna.get("affected", []) or [])
                        if isinstance(a, dict) and a.get("product")}

            rows.append((
                meta.get("cveId"),
                meta.get("datePublished"),
                classify(desc),
                cwe,
                advisory,
                cna.get("title") or "",
                len(products),
            ))

    df = pd.DataFrame(rows, columns=["cve_id", "date_published", "bucket", "cwe",
                                     "advisory", "title", "n_products"])
    df["date_published"] = pd.to_datetime(df["date_published"], format="mixed",
                                          utc=True, errors="coerce")
    df = df.dropna(subset=["cve_id", "date_published"]).sort_values("date_published")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(OUT, index=False)
    print(f"  [cisco_rollup] {len(df):,} Cisco-assigned records -> {OUT.name}")
    print("  " + df["bucket"].value_counts().to_string().replace("\n", "\n  "))
    return df


if __name__ == "__main__":
    main()

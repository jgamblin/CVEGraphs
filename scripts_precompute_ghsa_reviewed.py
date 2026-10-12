#!/usr/bin/env python3
"""
Precompute the GitHub-reviewed advisory table for the ``ghsa_output`` chart.

Source is the public github/advisory-database repo (CC-BY-4.0). Only the
``advisories/github-reviewed`` tree is needed, so this keeps a shallow, sparse,
blobless clone of just that tree in ``data/advisory-database`` (about 36K files,
not the full 378K) and refreshes it in place. It never reads a sibling checkout,
matching the rule that this repo owns its data.

One row per reviewed advisory. The chart counts rows by review month; the CVE
alias and ecosystem columns are kept for follow-up cuts.

Field notes, checked 2026-09-28:
  * ``database_specific.github_reviewed_at`` is the curation timestamp. Our May
    2026 count on it (1,608) sits close to GitHub's own blog figure of 1,560
    reviewed advisories in May, so it tracks their output. It is the review
    time, not the first-seen time: an advisory that sat in the unreviewed tree
    first keeps its earlier ``published``.
  * The database only holds outcomes. Rejected reports and duplicates (part of
    GitHub's "6,000 advisory decisions per month") leave no row, so this
    measures published output, not total effort.
  * Withdrawn advisories are kept: the review happened.

Outputs:
  processed/ghsa_reviewed.parquet     id, published, reviewed_at, withdrawn,
                                      cve, ecosystem
  processed/ghsa_reviewed_meta.json   snapshot commit + time, row counts

Run: python scripts_precompute_ghsa_reviewed.py   (network required)
"""

import json
import subprocess
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
PROCESSED = ROOT / "processed"
REPO = ROOT / "data" / "advisory-database"
URL = "https://github.com/github/advisory-database.git"
TREE = "advisories/github-reviewed"


def _git(*args, cwd=REPO):
    return subprocess.run(["git", *args], cwd=cwd, check=True,
                          capture_output=True, text=True).stdout.strip()


def _sync():
    """Clone on first run, otherwise fast-forward to upstream main."""
    if not (REPO / ".git").exists():
        REPO.parent.mkdir(parents=True, exist_ok=True)
        print(f"  [ghsa] cloning {TREE} (sparse, shallow) ...")
        _git("clone", "--depth", "1", "--filter=blob:none", "--sparse", URL,
             str(REPO), cwd=REPO.parent)
        _git("sparse-checkout", "set", TREE)
    else:
        # History is shallow and upstream force-pushes, so reset rather than
        # merge. Safe: nothing in this clone is ever edited by hand.
        _git("fetch", "--depth", "1", "origin", "main")
        _git("reset", "--hard", "FETCH_HEAD")
    return _git("log", "-1", "--format=%H %cI")


def _row(path):
    d = json.loads(path.read_text())
    ds = d.get("database_specific", {})
    cves = [a for a in d.get("aliases", []) if a.startswith("CVE-")]
    ecos = sorted({a["package"]["ecosystem"] for a in d.get("affected", [])
                   if a.get("package")})
    return {
        "id": d["id"],
        "published": d.get("published"),
        "reviewed_at": ds.get("github_reviewed_at"),
        "withdrawn": d.get("withdrawn"),
        "cve": cves[0] if cves else None,
        "ecosystem": ecos[0] if ecos else None,
    }


def main():
    commit, committed = _sync().split(" ", 1)
    rows = [_row(p) for p in (REPO / TREE).rglob("*.json")]
    df = pd.DataFrame(rows)
    for c in ("published", "reviewed_at", "withdrawn"):
        df[c] = pd.to_datetime(df[c], utc=True, format="ISO8601")
    df = df.dropna(subset=["reviewed_at"])
    PROCESSED.mkdir(exist_ok=True)
    df.to_parquet(PROCESSED / "ghsa_reviewed.parquet", index=False)
    meta = {
        "commit": commit,
        "committed": committed,
        "rows": len(df),
        "with_cve": int(df.cve.notna().sum()),
        "newest_review": df.reviewed_at.max().isoformat(),
    }
    (PROCESSED / "ghsa_reviewed_meta.json").write_text(json.dumps(meta, indent=2))
    print(f"  [ghsa] {len(df):,} reviewed advisories at {commit[:10]} "
          f"({committed}); newest review {meta['newest_review']}")


if __name__ == "__main__":
    main()

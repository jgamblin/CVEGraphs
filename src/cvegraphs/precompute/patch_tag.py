#!/usr/bin/env python3
"""
Precompute reference-tag facts per CVE from the raw CVE List V5 clone.

The parquet built by `cvegraphs refresh` keeps only ``ref_count``; the reference tags
(the machine-readable labels a CNA puts on each URL: ``patch``, ``vendor-advisory``,
``exploit`` ...) never made it in. This script scans every published record and
writes one row per CVE so the ``patch_tag`` chart can ask two questions:

  * does the CNA container carry at least one reference tagged ``patch``?
  * does the record carry a URL that is recognisably a fix commit or changeset,
    whether or not anyone labelled it?

The second column is the honesty check for the first: a record with an untagged
git.kernel.org commit is not "missing the patch", it is missing the label.

Writes processed/patch_tag.parquet: cve_id, assigner_short_name, published,
n_refs, has_any_tag, has_patch_tag, has_fix_url, has_vendor_advisory,
has_release_notes, tagset.
"""

import concurrent.futures
import json
import re
import sys

import pandas as pd

from cvegraphs.paths import DATA, PROCESSED

ROOT = DATA / "cvelistV5" / "cves"
OUT = PROCESSED / "patch_tag.parquet"

# URL shapes that point at the fix itself: a commit, changeset, merge/pull request
# or a raw patch file. Deliberately conservative: an advisory or release-notes page
# is NOT a fix URL here even though it usually names the fixed version.
FIX_URL = re.compile(
    r"(git\.kernel\.org/[^\s]*?/c/[0-9a-f]{7,}"          # kernel.org short commit links
    r"|git\.kernel\.org/[^\s]*?/commit/"
    r"|github\.com/[^/]+/[^/]+/(commit|pull|compare)/"
    r"|gitlab\.[^/]+/.+?/(-/)?(commit|merge_requests)/"
    r"|bitbucket\.org/.+?/commits?/"
    r"|/commit/[0-9a-f]{7,}|/commits/[0-9a-f]{7,}"
    r"|/changeset/\d+|plugins\.trac\.wordpress\.org/changeset"
    r"|/patch/|\.patch(\?|$)|\.diff(\?|$)"
    r"|gerrit\.[^/]+/.*/\+/\d+"
    r"|codereview|chromium-review\.googlesource\.com/c/)",
    re.I,
)


def _one(path):
    try:
        with open(path) as fh:
            rec = json.load(fh)
    except Exception:  # noqa: BLE001 - a broken file is skipped, not fatal
        return None
    meta = rec.get("cveMetadata", {})
    if meta.get("state") != "PUBLISHED":
        return None
    cna = rec.get("containers", {}).get("cna", {})
    refs = cna.get("references") or []
    tags = set()
    for r in refs:
        tags.update(r.get("tags") or [])
    urls = [r.get("url") or "" for r in refs]
    return {
        "cve_id": meta.get("cveId"),
        "assigner_short_name": meta.get("assignerShortName", ""),
        "published": meta.get("datePublished"),
        "n_refs": len(refs),
        "has_any_tag": any(r.get("tags") for r in refs),
        "has_patch_tag": "patch" in tags,
        "has_fix_url": any(FIX_URL.search(u) for u in urls),
        "has_vendor_advisory": "vendor-advisory" in tags,
        "has_release_notes": "release-notes" in tags,
        "tagset": "|".join(sorted(tags)),
    }


def main():
    files = list(ROOT.rglob("CVE-*.json"))
    print(f"[patch_tag] scanning {len(files):,} records ...", file=sys.stderr)
    with concurrent.futures.ProcessPoolExecutor() as ex:
        rows = [r for r in ex.map(_one, files, chunksize=2000) if r]
    df = pd.DataFrame(rows)
    df["published"] = pd.to_datetime(df["published"], utc=True, errors="coerce")
    OUT.parent.mkdir(exist_ok=True)
    df.to_parquet(OUT, index=False)
    print(f"[patch_tag] wrote {OUT} ({len(df):,} published rows)", file=sys.stderr)


if __name__ == "__main__":
    main()

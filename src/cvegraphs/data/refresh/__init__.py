"""
Self-contained weekly data refresh for CVEGraphs.

Builds this repo's OWN copy of the processed data from upstream feeds, so the
repo is rebuildable anywhere without depending on a sibling checkout:

    NVD JSON            https://nvd.handsonhacking.org/nvd.json      -> processed/nvd_cves.parquet
    CVE List V5 (git)   github.com/CVEProject/cvelistV5              -> processed/cvelist_v5.parquet
    CISA KEV catalog    cisa.gov feed                                -> processed/kev_catalog.json
    ENISA EUVD exploited euvdservices.enisa.europa.eu API             -> processed/euvd_kev.json
    CVEForecast feed    cveforecast.org/data.json                    -> processed/forecast.json
    EPSS scores (V5)    empiricalsec/epss_scores (daily, production)  -> processed/epss.parquet

then runs every derived dataset in cvegraphs.precompute. Raw downloads land in
./data and processed output in ./processed (both gitignored, both large).

Usage:
    cvegraphs refresh                  # full refresh (download + process + feeds + precompute)
    cvegraphs refresh --process-only   # reprocess existing ./data, skip downloads
    cvegraphs refresh --feeds-only     # only KEV + forecast + EPSS + CWE feeds (fast)
    cvegraphs refresh --force          # force NVD re-download

Stages live in sibling modules: nvd.py, cvelist.py, feeds.py (common.py holds
the shared setup).
"""

import argparse

from cvegraphs import precompute
from cvegraphs.data.refresh.cvelist import clone_or_update_cvelist, process_cvelist
from cvegraphs.data.refresh.feeds import fetch_feeds
from cvegraphs.data.refresh.nvd import download_nvd, process_nvd, reconcile_nvd_v4


def main(argv=None):
    ap = argparse.ArgumentParser(prog="cvegraphs refresh",
                                 description="Rebuild CVEGraphs data from upstream feeds")
    ap.add_argument("--process-only", action="store_true",
                    help="reprocess existing ./data, skip downloads")
    ap.add_argument("--feeds-only", action="store_true",
                    help="only fetch KEV + forecast feeds")
    ap.add_argument("--force", action="store_true", help="force NVD re-download")
    args = ap.parse_args(argv)

    print("=" * 60)
    print("CVEGraphs data refresh")
    print("=" * 60)

    if args.feeds_only:
        fetch_feeds()
        return 0

    if not args.process_only:
        print("\n[1/3] Downloading sources ...")
        download_nvd(force=args.force)
        clone_or_update_cvelist()

    print("\n[2/3] Processing to parquet ...")
    nvd_df = process_nvd()
    cvelist_df = process_cvelist()
    # NVD's mirrored v4 is unreliable; prefer the CNA's authoritative CVE List v4.
    reconcile_nvd_v4(nvd_df, cvelist_df)

    # Derived datasets that scan the raw clones. Must run on every refresh or a
    # chart renders a fresh date over stale numbers.
    failed = precompute.run_stage("parse")

    print("\n[3/3] Fetching feeds ...")
    fetch_feeds()
    # These need kev_catalog.json from the feed fetch.
    failed += precompute.run_stage("feeds")

    if failed:
        print(f"\nDone with {len(failed)} failed precompute step(s): {', '.join(failed)}.")
        print("Their charts still read the previous output; rerun with `cvegraphs precompute <name>`.")
    else:
        print("\nDone. Data is in ./processed. Render with: cvegraphs render all")
    return 0

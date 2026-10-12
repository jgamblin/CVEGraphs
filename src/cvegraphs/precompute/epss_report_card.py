#!/usr/bin/env python3
"""
Precompute the EPSS report card for this year's KEV additions.

For every CVE CISA added to KEV in the current year, roll the clock back and
ask what EPSS said BEFORE CISA acted:

  * ``epss_30d`` / ``pct_30d``  — EPSS score and percentile at the snapshot on
    or just before ``dateAdded - 30 days`` (the forward-looking, fair test).
  * ``epss_1d`` / ``pct_1d``    — the day-before-KEV score (robustness only;
    by then EPSS has usually absorbed the same news CISA is reacting to).
  * ``e10_lead_days`` etc.      — how many days before KEV the CVE first
    crossed EPSS 0.10 / 0.50 / the 90th percentile, on a weekly lattice.

Also records, per KEV-minus-30d snapshot, the share of the whole corpus at or
above each EPSS threshold. Averaged over the fair set, that is the honest
"workload" denominator: what fraction of all CVEs that policy flags on the
day you would have had to act. The CVSS workload equivalent is computed by
the chart from the local corpus (CVE List v3 with NVD fallback), which is
stable; EPSS shares move with the model version so they must be historical.

Snapshots come from the empiricalsec/epss_scores mirror (production daily
files, same source `cvegraphs refresh` uses). Every snapshot touched is slimmed
to the tracked CVEs and cached in ``processed/epss_history_cache/`` so
re-runs are cheap; full downloads are discarded after slimming.

Outputs:
  processed/epss_report_card.parquet   one row per KEV addition this year
  processed/epss_report_card_meta.json cohort counts + workload shares

Run: cvegraphs precompute epss_report_card   (network required)
"""

import gzip
import io
import json
import time
from datetime import date, timedelta

import pandas as pd
import requests

from cvegraphs.paths import PROCESSED

CACHE = PROCESSED / "epss_history_cache"
CACHE.mkdir(parents=True, exist_ok=True)

EPSS_URL = ("https://raw.githubusercontent.com/empiricalsec/epss_scores/main/"
            "{year}/epss_scores-{d}.csv.gz")

KEV_YEAR = 2026
LEAD_START = date(KEV_YEAR - 1, 1, 6)   # weekly lattice begins here (a Monday)
EPSS_THRESHOLDS = (0.01, 0.10, 0.50)    # corpus-share thresholds recorded per snapshot
WALKBACK = 5                             # days to walk back when a date is missing


def _load_kev():
    kev = json.load(open(PROCESSED / "kev_catalog.json"))
    rows = [{
        "cve_id": v["cveID"],
        "vendor": v["vendorProject"],
        "product": v["product"],
        "date_added": pd.Timestamp(v["dateAdded"]),
        "ransomware": v.get("knownRansomwareCampaignUse", ""),
    } for v in kev["vulnerabilities"]
        if v["dateAdded"].startswith(str(KEV_YEAR))]
    return pd.DataFrame(rows)


def _parse_full(content):
    raw = gzip.decompress(content).decode()
    lines = [l for l in raw.splitlines() if not l.startswith("#")]
    df = pd.read_csv(io.StringIO("\n".join(lines)))
    df.columns = [c.strip().lower() for c in df.columns]
    df = df.rename(columns={"cve": "cve_id"})
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    df["percentile"] = pd.to_numeric(df["percentile"], errors="coerce")
    return df[["cve_id", "epss", "percentile"]]


def _slim_and_shares(full, ids, dd):
    """Cache the tracked-CVE rows and the corpus threshold shares for date dd."""
    slim = full[full.cve_id.isin(ids)].copy()
    slim["snap_date"] = dd.isoformat()
    slim.to_parquet(CACHE / f"slim-{dd.isoformat()}.parquet", index=False)
    shares = {str(t): float((full.epss >= t).mean()) for t in EPSS_THRESHOLDS}
    shares["rows"] = int(len(full))
    (CACHE / f"shares-{dd.isoformat()}.json").write_text(json.dumps(shares))
    return slim, shares


def snapshot(d, ids, need_shares=False):
    """(slim_df, shares|None, actual_date) for the snapshot on/just before d.

    Serves from the cache when possible; otherwise downloads, slims, records
    corpus shares, and drops the full file. Legacy full parquets left in the
    cache dir by earlier runs are consumed (slimmed) and deleted.
    """
    for i in range(WALKBACK):
        dd = d - timedelta(days=i)
        slim_p = CACHE / f"slim-{dd.isoformat()}.parquet"
        shares_p = CACHE / f"shares-{dd.isoformat()}.json"
        full_p = CACHE / f"{dd.isoformat()}.parquet"

        if slim_p.exists() and (not need_shares or shares_p.exists()):
            slim = pd.read_parquet(slim_p)
            missing = ids - set(slim.cve_id)
            # A slim cached against an older KEV catalog may lack newly added
            # CVEs; only a re-slim from the full file can rule them present.
            if not missing or not full_p.exists():
                shares = (json.loads(shares_p.read_text())
                          if shares_p.exists() else None)
                return slim, shares, dd

        if full_p.exists():
            full = pd.read_parquet(full_p)
            slim, shares = _slim_and_shares(full, ids, dd)
            full_p.unlink()
            return slim, shares, dd

        resp = requests.get(EPSS_URL.format(year=dd.year, d=dd.isoformat()),
                            timeout=30)
        if resp.status_code == 200:
            full = _parse_full(resp.content)
            slim, shares = _slim_and_shares(full, ids, dd)
            return slim, shares, dd
        time.sleep(0.2)
    return None, None, None


def main():
    kev = _load_kev()
    ids = set(kev.cve_id)
    print(f"[report card] {len(kev)} CVEs added to KEV in {KEV_YEAR}")

    # ---- weekly lattice for lead times -------------------------------------
    frames = []
    d = LEAD_START
    end = max(kev.date_added).date()
    while d <= end:
        slim, _, actual = snapshot(d, ids)
        if slim is not None:
            frames.append(slim)
        d += timedelta(days=7)
    ts = pd.concat(frames, ignore_index=True)
    ts["snap_date"] = pd.to_datetime(ts.snap_date)
    ts = ts.drop_duplicates(["cve_id", "snap_date"])
    print(f"[report card] weekly lattice: {ts.snap_date.nunique()} snapshots")

    # ---- per-entry point-in-time scores ------------------------------------
    rows, shares_by_cve = [], {}
    for r in kev.itertuples():
        added = r.date_added.date()
        s30, shares30, d30 = snapshot(added - timedelta(days=30), ids,
                                      need_shares=True)
        s1, _, d1 = snapshot(added - timedelta(days=1), ids)

        def _val(slim, col):
            if slim is None:
                return None
            hit = slim[slim.cve_id == r.cve_id]
            return float(hit[col].iloc[0]) if len(hit) else None

        if shares30:
            shares_by_cve[r.cve_id] = shares30

        row = {
            "cve_id": r.cve_id, "vendor": r.vendor, "product": r.product,
            "date_added": r.date_added, "ransomware": r.ransomware,
            "epss_30d": _val(s30, "epss"), "pct_30d": _val(s30, "percentile"),
            "snap_30d": pd.Timestamp(d30) if d30 else pd.NaT,
            "epss_1d": _val(s1, "epss"), "pct_1d": _val(s1, "percentile"),
            "snap_1d": pd.Timestamp(d1) if d1 else pd.NaT,
        }

        pre = ts[(ts.cve_id == r.cve_id) & (ts.snap_date < r.date_added)]
        for name, mask in [("e10", pre.epss >= 0.10),
                           ("e50", pre.epss >= 0.50),
                           ("p90", pre.percentile >= 0.90)]:
            hit = pre[mask]
            first = hit.snap_date.min() if len(hit) else pd.NaT
            row[f"{name}_first"] = first
            row[f"{name}_lead_days"] = (
                (r.date_added - first).days if pd.notna(first) else None)
        rows.append(row)

    df = pd.DataFrame(rows)
    df.to_parquet(PROCESSED / "epss_report_card.parquet", index=False)

    # ---- CVE publication dates (fair-set flag) ------------------------------
    cv = pd.read_parquet(PROCESSED / "cvelist_v5.parquet",
                         columns=["cve_id", "date_published"])
    df = df.merge(cv, on="cve_id", how="left")
    pub = pd.to_datetime(df.date_published, utc=True).dt.tz_localize(None)
    df["age_at_kev"] = (df.date_added - pub.dt.normalize()).dt.days

    same_day = int((df.age_at_kev <= 0).sum())
    within_1d = int((df.age_at_kev <= 1).sum())
    under_30 = int(((df.age_at_kev > 1) & (df.age_at_kev < 30)).sum())
    fair = df[df.age_at_kev >= 30]
    df.to_parquet(PROCESSED / "epss_report_card.parquet", index=False)

    # workload shares from the fair-set snapshots only, per the docstring:
    # they are the denominator for the fair-set head-to-head
    shares = pd.DataFrame([shares_by_cve[c] for c in fair.cve_id
                           if c in shares_by_cve])
    meta = {
        "kev_year": KEV_YEAR,
        "total_added": int(len(df)),
        "same_day": same_day,
        "within_1d": within_1d,
        "under_30d": under_30,
        "fair_set": int(len(fair)),
        "fair_scored": int(fair.epss_30d.notna().sum()),
        # workload: corpus share >= threshold, averaged over the actual
        # KEV-minus-30d snapshots (one sample per fair-set entry, so busy KEV
        # days weigh their own decision date more heavily)
        "epss_workload_share": {
            str(t): float(shares[str(t)].mean()) for t in EPSS_THRESHOLDS},
        "epss_corpus_rows": int(shares["rows"].mean()),
        "lattice_weeks": int(ts.snap_date.nunique()),
        "generated": date.today().isoformat(),
    }
    (PROCESSED / "epss_report_card_meta.json").write_text(
        json.dumps(meta, indent=2))

    print(f"[report card] wrote processed/epss_report_card.parquet "
          f"({len(df)} rows) and epss_report_card_meta.json")
    print(f"[report card] cohort: {same_day} same-day ({within_1d} within a "
          f"day), {under_30} under 30d, {len(fair)} fair set "
          f"({meta['fair_scored']} with EPSS at -30d)")
    for t in EPSS_THRESHOLDS:
        print(f"[report card]   corpus share EPSS >= {t}: "
              f"{meta['epss_workload_share'][str(t)]:.2%}")


if __name__ == "__main__":
    main()

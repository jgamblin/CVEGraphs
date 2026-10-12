#!/usr/bin/env python3
"""
Precompute the EPSS early-warning curve for this year's KEV additions.

Tests EPSS as an alarm rather than as a score: for every CVE CISA added to KEV
this year that had been public at least 90 days, read the production EPSS
score at six fixed lookbacks before its KEV date --- 90, 60, 30, 15, 7 and 1
day out --- and ask whether the alarm was already ringing, and whether it got
louder as CISA's decision approached.

The cohort is FIXED at the 90-day bar. Only 62 of this year's 182 additions
had 90 days of public history to look back on; the shorter horizons would each
admit more CVEs (82 at 30 days, 149 at 1 day) and letting the cohort grow as
the horizon shortens would make the curve rise because its *membership*
changed, not because EPSS learned anything. Same CVEs at every horizon, or the
comparison is not a comparison.

Snapshot dates are EXACT where the mirror has that day's file, walking back at
most a few days when it does not; ``snap_lag`` records the slip per row so the
chart can state the real precision instead of assuming it. Percentile is
carried alongside the raw score because an EPSS model retrain inside a 90-day
window moves raw probabilities without new evidence about the CVE, and the
percentile survives recalibration better.

Snapshots come from the empiricalsec/epss_scores mirror (the same production
daily files refresh_data.py uses). Each one touched is slimmed to this year's
KEV CVEs and cached in ``processed/epss_history_cache/`` in the same format
scripts_precompute_epss_report_card.py writes, so the two scripts share a
cache; full downloads are discarded after slimming. Model version per snapshot
lands in a ``mv-<date>.json`` sidecar so the slim schema stays unchanged.

Outputs:
  processed/epss_early_warning.parquet    one row per (CVE, horizon)
  processed/epss_early_warning_meta.json  cohort counts + per-horizon summary

Run: python scripts_precompute_epss_early_warning.py   (network required)
"""

import concurrent.futures
import gzip
import io
import json
import re
from datetime import date, timedelta
from pathlib import Path

import pandas as pd
import requests

ROOT = Path(__file__).resolve().parent
PROCESSED = ROOT / "processed"
CACHE = PROCESSED / "epss_history_cache"
CACHE.mkdir(parents=True, exist_ok=True)

EPSS_URL = ("https://raw.githubusercontent.com/empiricalsec/epss_scores/main/"
            "{year}/epss_scores-{d}.csv.gz")

KEV_YEAR = 2026
MIN_AGE = 90                      # days public before KEV to enter the cohort
HORIZONS = (90, 60, 30, 15, 7, 1)  # days before the KEV date
WALKBACK = 4                      # days to walk back when a date is missing
WORKERS = 4                       # parallel snapshot downloads

# EPSS score bands used by the chart. Ordered low to high; the label is what
# the legend shows. 0.10 and 0.50 are the two thresholds the report card
# already uses, so the two charts stay legible against each other.
BANDS = [
    (0.00, 0.01, "Under 0.01"),
    (0.01, 0.10, "0.01 - 0.10"),
    (0.10, 0.50, "0.10 - 0.50"),
    (0.50, 1.01, "0.50 and up"),
]


def _load_cohort():
    """This year's KEV additions, with age at KEV and the fixed-cohort flag."""
    kev = json.load(open(PROCESSED / "kev_catalog.json"))
    rows = [{
        "cve_id": v["cveID"],
        "vendor": v["vendorProject"],
        "product": v["product"],
        "date_added": pd.Timestamp(v["dateAdded"]),
        "ransomware": v.get("knownRansomwareCampaignUse", ""),
    } for v in kev["vulnerabilities"]
        if v["dateAdded"].startswith(str(KEV_YEAR))]
    df = pd.DataFrame(rows)

    cv = pd.read_parquet(PROCESSED / "cvelist_v5.parquet",
                         columns=["cve_id", "date_published"])
    df = df.merge(cv, on="cve_id", how="left")
    pub = pd.to_datetime(df.date_published, utc=True).dt.tz_localize(None)
    # KEV dateAdded is date-only, so normalize publication to a calendar date
    # before differencing or same-day additions read as negative age.
    df["age_at_kev"] = (df.date_added - pub.dt.normalize()).dt.days
    return df


def _parse_full(content):
    """(df[cve_id, epss, percentile], model_version) from a gzipped EPSS CSV."""
    raw = gzip.decompress(content).decode()
    model = None
    for line in raw.splitlines():
        if line.startswith("#"):
            m = re.search(r"model_version:\s*([^\s,]+)", line)
            if m:
                model = m.group(1)
            continue
        break
    lines = [l for l in raw.splitlines() if not l.startswith("#")]
    df = pd.read_csv(io.StringIO("\n".join(lines)))
    df.columns = [c.strip().lower() for c in df.columns]
    df = df.rename(columns={"cve": "cve_id"})
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    df["percentile"] = pd.to_numeric(df["percentile"], errors="coerce")
    return df[["cve_id", "epss", "percentile"]], model


def _fetch_one(dd, ids):
    """Download, slim, and cache the snapshot for exactly ``dd``.

    Returns True when a slim landed. Written in the same schema as the report
    card's cache so both scripts can read it; the model version goes to a
    sidecar rather than into the slim.
    """
    slim_p = CACHE / f"slim-{dd.isoformat()}.parquet"
    if slim_p.exists():
        return True
    resp = requests.get(EPSS_URL.format(year=dd.year, d=dd.isoformat()),
                        timeout=60)
    if resp.status_code != 200:
        return False
    full, model = _parse_full(resp.content)
    slim = full[full.cve_id.isin(ids)].copy()
    slim["snap_date"] = dd.isoformat()
    slim.to_parquet(slim_p, index=False)
    if model:
        (CACHE / f"mv-{dd.isoformat()}.json").write_text(
            json.dumps({"model_version": model}))
    return True


def _warm(dates, ids):
    """Pre-fetch every needed snapshot date in parallel. Returns dates missing."""
    todo = [d for d in sorted(dates)
            if not (CACHE / f"slim-{d.isoformat()}.parquet").exists()]
    print(f"[early warning] {len(dates)} snapshot dates needed, "
          f"{len(dates) - len(todo)} already cached, {len(todo)} to fetch")
    missing = set()
    if not todo:
        return missing
    with concurrent.futures.ThreadPoolExecutor(WORKERS) as ex:
        futs = {ex.submit(_fetch_one, d, ids): d for d in todo}
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            d = futs[fut]
            try:
                if not fut.result():
                    missing.add(d)
            except Exception as e:                     # network / parse hiccup
                print(f"  [warn] {d.isoformat()}: {e}")
                missing.add(d)
            if i % 10 == 0:
                print(f"  fetched {i}/{len(todo)}")
    return missing


def _read_snapshot(dd):
    """(slim_df, model_version|None) for exactly ``dd``, or (None, None)."""
    slim_p = CACHE / f"slim-{dd.isoformat()}.parquet"
    if not slim_p.exists():
        return None, None
    mv_p = CACHE / f"mv-{dd.isoformat()}.json"
    model = (json.loads(mv_p.read_text())["model_version"]
             if mv_p.exists() else None)
    return pd.read_parquet(slim_p), model


def main():
    kev = _load_cohort()
    cohort = kev[kev.age_at_kev >= MIN_AGE].copy()
    ids = set(kev.cve_id)          # slim against ALL of this year's KEV ids
    print(f"[early warning] {len(kev)} CVEs added to KEV in {KEV_YEAR}; "
          f"{len(cohort)} public {MIN_AGE}+ days before their KEV date")

    # ---- every exact target date, plus walkback candidates ------------------
    targets = {}
    for r in cohort.itertuples():
        for h in HORIZONS:
            targets[(r.cve_id, h)] = (
                pd.Timestamp(r.date_added) - pd.Timedelta(days=h)).date()
    _warm(set(targets.values()), ids)

    # ---- resolve each (CVE, horizon) to a real snapshot --------------------
    cache = {}

    def _snap(d0):
        """(slim, model, actual_date) for d0, walking back if d0 is absent."""
        for i in range(WALKBACK):
            dd = d0 - timedelta(days=i)
            if dd not in cache:
                cache[dd] = _read_snapshot(dd)
            slim, model = cache[dd]
            if slim is None and i == 0:
                # not pre-warmed (upstream gap); try to pull the fallback day
                _fetch_one(dd, ids)
                cache[dd] = _read_snapshot(dd)
                slim, model = cache[dd]
            if slim is not None:
                return slim, model, dd
        return None, None, None

    rows, models = [], set()
    for r in cohort.itertuples():
        for h in HORIZONS:
            tgt = targets[(r.cve_id, h)]
            slim, model, actual = _snap(tgt)
            hit = slim[slim.cve_id == r.cve_id] if slim is not None else None
            if model:
                models.add(model)
            rows.append({
                "cve_id": r.cve_id,
                "vendor": r.vendor,
                "product": r.product,
                "date_added": r.date_added,
                "age_at_kev": r.age_at_kev,
                "ransomware": r.ransomware,
                "horizon": h,
                "target_date": pd.Timestamp(tgt),
                "snap_date": pd.Timestamp(actual) if actual else pd.NaT,
                "snap_lag": (tgt - actual).days if actual else None,
                "model_version": model,
                "epss": (float(hit.epss.iloc[0])
                         if hit is not None and len(hit) else None),
                "percentile": (float(hit.percentile.iloc[0])
                               if hit is not None and len(hit) else None),
            })

    df = pd.DataFrame(rows)
    df.to_parquet(PROCESSED / "epss_early_warning.parquet", index=False)

    # ---- per-horizon summary ----------------------------------------------
    per = {}
    for h in HORIZONS:
        s = df[df.horizon == h]
        e = s.epss.dropna()
        per[str(h)] = {
            "scored": int(len(e)),
            "median": float(e.median()),
            "q25": float(e.quantile(0.25)),
            "q75": float(e.quantile(0.75)),
            "share_10": float((s.epss >= 0.10).mean()),
            "share_50": float((s.epss >= 0.50).mean()),
            "share_p90": float((s.percentile >= 0.90).mean()),
            "bands": {lab: int(((e >= lo) & (e < hi)).sum())
                      for lo, hi, lab in BANDS},
            "max_snap_lag": int(s.snap_lag.max()) if s.snap_lag.notna().any() else None,
        }

    # ---- per-CVE movement across the full window ---------------------------
    wide = df.pivot_table(index="cve_id", columns="horizon", values="epss")
    both = wide[[90, 1]].dropna()
    delta = both[1] - both[90]
    movement = {
        "pairs": int(len(both)),
        "median_delta": float(delta.median()),
        "rose_05": int((delta > 0.05).sum()),
        "flat_05": int((delta.abs() <= 0.05).sum()),
        "fell_05": int((delta < -0.05).sum()),
        "crossed_10_up": int(((both[90] < 0.10) & (both[1] >= 0.10)).sum()),
        "never_10": int(((both[90] < 0.10) & (both[1] < 0.10)).sum()),
        "already_10_at_90": int((both[90] >= 0.10).sum()),
    }

    meta = {
        "kev_year": KEV_YEAR,
        "total_added": int(len(kev)),
        "min_age": MIN_AGE,
        "cohort": int(len(cohort)),
        "same_day": int((kev.age_at_kev <= 0).sum()),
        "within_1d": int((kev.age_at_kev <= 1).sum()),
        "under_min_age": int((kev.age_at_kev < MIN_AGE).sum()),
        "horizons": list(HORIZONS),
        "bands": [lab for _, _, lab in BANDS],
        "per_horizon": per,
        "movement": movement,
        "model_versions": sorted(models),
        "max_snap_lag": int(df.snap_lag.max()) if df.snap_lag.notna().any() else None,
        "generated": date.today().isoformat(),
    }
    (PROCESSED / "epss_early_warning_meta.json").write_text(
        json.dumps(meta, indent=2))

    print(f"[early warning] wrote processed/epss_early_warning.parquet "
          f"({len(df)} rows) and epss_early_warning_meta.json")
    print(f"[early warning] cohort {len(cohort)} of {len(kev)} additions; "
          f"model versions in window: {', '.join(sorted(models)) or 'unknown'}")
    for h in HORIZONS:
        p = per[str(h)]
        print(f"[early warning]   -{h:>2}d  scored {p['scored']:>3}  "
              f"median {p['median']:.4f}  >=0.10 {p['share_10']:.1%}  "
              f">=0.50 {p['share_50']:.1%}  max lag {p['max_snap_lag']}")
    print(f"[early warning] across the 90 days: {movement['flat_05']} of "
          f"{movement['pairs']} moved under +/-0.05, "
          f"{movement['crossed_10_up']} crossed 0.10 upward, "
          f"{movement['never_10']} never reached 0.10")


if __name__ == "__main__":
    main()

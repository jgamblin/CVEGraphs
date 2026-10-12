#!/usr/bin/env python3
"""
Precompute EPSS scores in a window either side of the KEV listing date.

The `epss_early_warning` pair stops at the KEV date and shows EPSS is flat on
the way in. This asks the obvious follow-up: does the score move once CISA
publishes the listing? Same construction, but the offsets run from 60 days
before the KEV date to 60 days after, with the listing day itself at zero.

Cohort (both bounds are required, or the window has holes):
  * public at least 60 days before the KEV date, so the -60 end exists at all;
  * KEV date at least 60 days before the newest EPSS snapshot, so the +60 end
    exists too.

That second bound means the cohort is necessarily the earlier part of the year
(no recent addition can have 60 days of future scores yet), and it makes this a
DIFFERENT, overlapping cohort from the 62 in `epss_early_warning` --- do not
quote counts across the two charts as if they were the same set.

Read the result with care: EPSS's published feature set includes exploitation
evidence, and KEV membership is one of the signals in that family, so a rise
after day zero is at least partly the model ingesting CISA's decision rather
than discovering anything. The chart's job is to size that step, not to call it
prediction. Confirm the current v5 feature list against FIRST's model
documentation before any published claim leans on the mechanism.

Snapshots come from the empiricalsec/epss_scores mirror and share the cache in
``processed/epss_history_cache/`` with the other EPSS precomputes, reusing the
low-level fetch helpers so the caching behaviour cannot drift between scripts.

Outputs:
  processed/epss_kev_window.parquet    one row per (CVE, offset)
  processed/epss_kev_window_meta.json  cohort counts + per-offset summary

Run: cvegraphs precompute epss_kev_window   (network required)
"""

import concurrent.futures
import json
from datetime import date, timedelta

import pandas as pd
import requests

from cvegraphs.paths import PROCESSED
from cvegraphs.precompute.epss_early_warning import (
    CACHE,
    EPSS_URL,
    _fetch_one,
    _read_snapshot,
)

KEV_YEAR = 2026
MIN_AGE = 60        # days public before KEV, so the -60 offset exists
POST = 60           # days of post-listing history required
WALKBACK = 4
WORKERS = 4

# Signed offsets in days from the KEV date; 0 is the listing day itself.
OFFSETS = (-60, -30, -15, -7, -1, 0, 1, 7, 15, 30, 60)

# Date the current production EPSS model superseded the previous one. Used for
# the date-based retrain-exposure check, which is reliable where the
# model_version column (partial, see main) is not.
MODEL_CUTOVER = "2026-06-15"

BANDS = [
    (0.00, 0.01, "Under 0.01"),
    (0.01, 0.10, "0.01 - 0.10"),
    (0.10, 0.50, "0.10 - 0.50"),
    (0.50, 1.01, "0.50 and up"),
]


def _probe_latest(max_back=12):
    """Newest date the mirror actually serves, walking back from today.

    Needed before the cohort can be chosen, so it probes the URL directly
    rather than going through the slim cache.
    """
    today = date.today()
    for i in range(max_back):
        d = today - timedelta(days=i)
        try:
            r = requests.head(EPSS_URL.format(year=d.year, d=d.isoformat()),
                              timeout=20, allow_redirects=True)
            if r.status_code == 200:
                return d
        except requests.RequestException:
            pass
    raise RuntimeError("no EPSS snapshot found in the probe window")


def _load_cohort(latest):
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
    # KEV dateAdded is date-only; normalize publication to a calendar date.
    df["age_at_kev"] = (df.date_added - pub.dt.normalize()).dt.days

    cutoff = pd.Timestamp(latest) - pd.Timedelta(days=POST)
    df["in_cohort"] = (df.age_at_kev >= MIN_AGE) & (df.date_added <= cutoff)
    return df, cutoff


def _cached(d):
    return (CACHE / f"slim-{d.isoformat()}.parquet").exists()


def _warm(dates, ids):
    todo = [d for d in sorted(dates) if not _cached(d)]
    print(f"[kev window] {len(dates)} snapshot dates needed, "
          f"{len(dates) - len(todo)} cached, {len(todo)} to fetch")
    if not todo:
        return
    with concurrent.futures.ThreadPoolExecutor(WORKERS) as ex:
        futs = {ex.submit(_fetch_one, d, ids): d for d in todo}
        for i, fut in enumerate(concurrent.futures.as_completed(futs), 1):
            try:
                fut.result()
            except Exception as e:
                print(f"  [warn] {futs[fut].isoformat()}: {e}")
            if i % 10 == 0:
                print(f"  fetched {i}/{len(todo)}")


def main():
    latest = _probe_latest()
    kev, cutoff = _load_cohort(latest)
    cohort = kev[kev.in_cohort].copy()
    ids = set(kev.cve_id)
    print(f"[kev window] newest EPSS snapshot {latest.isoformat()}; "
          f"KEV date cutoff {cutoff.date()}")
    print(f"[kev window] {len(kev)} CVEs added to KEV in {KEV_YEAR}; "
          f"{len(cohort)} have both 60 days of public history before the "
          "listing and 60 days of scores after it")

    targets = {}
    for r in cohort.itertuples():
        for h in OFFSETS:
            targets[(r.cve_id, h)] = (
                pd.Timestamp(r.date_added) + pd.Timedelta(days=h)).date()
    _warm(set(targets.values()), ids)

    cache = {}

    def _snap(d0):
        """(slim, model, actual) for d0, walking BACK if the day is missing.

        Walking back (never forward) keeps every reading a real point-in-time
        score: a forward fill could smuggle in post-dated information.
        """
        for i in range(WALKBACK):
            dd = d0 - timedelta(days=i)
            if dd not in cache:
                cache[dd] = _read_snapshot(dd)
                if cache[dd][0] is None:
                    _fetch_one(dd, ids)
                    cache[dd] = _read_snapshot(dd)
            if cache[dd][0] is not None:
                return (*cache[dd], dd)
        return None, None, None

    rows, models = [], set()
    for r in cohort.itertuples():
        for h in OFFSETS:
            tgt = targets[(r.cve_id, h)]
            slim, model, actual = _snap(tgt)
            hit = slim[slim.cve_id == r.cve_id] if slim is not None else None
            if model:
                models.add(model)
            rows.append({
                "cve_id": r.cve_id, "vendor": r.vendor, "product": r.product,
                "date_added": r.date_added, "age_at_kev": r.age_at_kev,
                "ransomware": r.ransomware,
                "offset": h,
                "target_date": pd.Timestamp(tgt),
                "snap_date": pd.Timestamp(actual) if actual else pd.NaT,
                "snap_lag": (tgt - actual).days if actual else None,
                # PARTIAL BY DESIGN: only snapshots this run downloaded carry
                # an mv-<date>.json sidecar, so rows served from a pre-existing
                # cached slim are None. Never infer "the model changed" by
                # comparing this column across offsets, a None-vs-value pair
                # reads as a difference; use the date-based boundary check in
                # the meta ("model_boundary") instead.
                "model_version": model,
                "epss": (float(hit.epss.iloc[0])
                         if hit is not None and len(hit) else None),
                "percentile": (float(hit.percentile.iloc[0])
                               if hit is not None and len(hit) else None),
            })

    df = pd.DataFrame(rows)
    df.to_parquet(PROCESSED / "epss_kev_window.parquet", index=False)

    per = {}
    for h in OFFSETS:
        s = df[df.offset == h]
        e = s.epss.dropna()
        per[str(h)] = {
            "scored": int(len(e)),
            "mean": float(e.mean()),
            "median": float(e.median()),
            "share_10": float((s.epss >= 0.10).mean()),
            "share_50": float((s.epss >= 0.50).mean()),
            "bands": {lab: int(((e >= lo) & (e < hi)).sum())
                      for lo, hi, lab in BANDS},
            "max_snap_lag": (int(s.snap_lag.max())
                             if s.snap_lag.notna().any() else None),
        }

    wide = df.pivot_table(index="cve_id", columns="offset", values="epss")
    pre, post = wide[-1], wide[60]          # day before listing vs 60 days after
    both = pd.concat([pre.rename("pre"), post.rename("post")], axis=1).dropna()
    d = both.post - both.pre
    step = {
        "pairs": int(len(both)),
        "median_delta": float(d.median()),
        "mean_delta": float(d.mean()),
        "rose_05": int((d > 0.05).sum()),
        "flat_05": int((d.abs() <= 0.05).sum()),
        "fell_05": int((d < -0.05).sum()),
        "crossed_10_up": int(((both.pre < 0.10) & (both.post >= 0.10)).sum()),
        "still_under_10": int(((both.pre < 0.10) & (both.post < 0.10)).sum()),
    }

    # Date-based retrain exposure. Robust where model_version is not: it asks
    # which snapshots fall on/after the known model cutover rather than relying
    # on the partially populated column. The day0 -> +1 count is the one that
    # matters, since a nonzero value would make the step a recalibration
    # artifact instead of a reaction to the listing.
    sd = df.pivot_table(index="cve_id", columns="offset", values="snap_date",
                        aggfunc="first")
    bound = pd.Timestamp(MODEL_CUTOVER)
    per_offset_after = {
        str(h): int((pd.to_datetime(sd[h]) >= bound).sum()) for h in OFFSETS}
    step_crosses = int(((pd.to_datetime(sd[0]) < bound)
                        & (pd.to_datetime(sd[1]) >= bound)).sum())
    clean_ids = sd.index[pd.to_datetime(sd[max(OFFSETS)]) < bound]
    model_boundary = {
        "cutover": MODEL_CUTOVER,
        "snapshots_on_new_model_by_offset": per_offset_after,
        "step_day0_to_plus1_crossing": step_crosses,
        "cves_entirely_pre_cutover": int(len(clean_ids)),
    }

    meta = {
        "kev_year": KEV_YEAR,
        "model_boundary": model_boundary,
        "total_added": int(len(kev)),
        "min_age": MIN_AGE,
        "post_days": POST,
        "cohort": int(len(cohort)),
        "latest_snapshot": latest.isoformat(),
        "kev_date_cutoff": cutoff.date().isoformat(),
        "kev_date_min": cohort.date_added.min().date().isoformat(),
        "kev_date_max": cohort.date_added.max().date().isoformat(),
        "offsets": list(OFFSETS),
        "bands": [lab for _, _, lab in BANDS],
        "per_offset": per,
        "step": step,
        "model_versions": sorted(models),
        "max_snap_lag": (int(df.snap_lag.max())
                         if df.snap_lag.notna().any() else None),
        "generated": date.today().isoformat(),
    }
    (PROCESSED / "epss_kev_window_meta.json").write_text(
        json.dumps(meta, indent=2))

    print(f"[kev window] wrote processed/epss_kev_window.parquet "
          f"({len(df)} rows) and epss_kev_window_meta.json")
    for h in OFFSETS:
        p = per[str(h)]
        sign = f"{h:+d}" if h else "  0"
        print(f"[kev window]  {sign:>4}d  scored {p['scored']:>3}  "
              f"mean {p['mean']:.4f}  median {p['median']:.4f}  "
              f">=0.10 {p['share_10']:.1%}  lag {p['max_snap_lag']}")
    print(f"[kev window] retrain check (cutover {MODEL_CUTOVER}): "
          f"{step_crosses} CVEs cross it between day 0 and +1; "
          f"{len(clean_ids)} have an entirely pre-cutover window")
    print(f"[kev window] day -1 to +60: median change "
          f"{step['median_delta']:+.4f}, {step['rose_05']} rose, "
          f"{step['flat_05']} flat, {step['fell_05']} fell; "
          f"{step['crossed_10_up']} crossed 0.10 upward, "
          f"{step['still_under_10']} still under 0.10")


if __name__ == "__main__":
    main()

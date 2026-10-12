#!/usr/bin/env python3
"""Numbers behind "The model we need" in papers/short-lived-cves.html.

Parses every Microsoft-assigned CVE record published 2024 to 2026 from the
cvelistV5 clone, pulls the CVSS temporal exploit-maturity flag (E:U/P/F), the
component and impact type from Microsoft's title, joins CISA KEV, and runs the
"dumbest version" of a short-lived CVE model: a KEV-rate lookup by component and
impact trained on 2024 to 2025, scored on the nine 2026 Patch Tuesday releases.

Run from the repo root:  python3 papers/src/short_lived_cves/backtest_lookalike.py
"""
import glob
import json
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))
from data import load_cvelist  # noqa: E402

IMP = r"(Elevation of Privilege|Remote Code Execution|Information Disclosure|Denial of Service|Spoofing|Security Feature Bypass|Tampering)"
PTS = pd.to_datetime(["2026-01-13", "2026-02-10", "2026-03-10", "2026-04-14", "2026-05-12",
                      "2026-06-09", "2026-07-14", "2026-08-11", "2026-09-08"])
SHRINK = 5.0   # pseudo-count toward the impact-level rate
SEED = 0       # random tie-break, fixed


def parse():
    cve = load_cvelist()
    cve["pub"] = pd.to_datetime(cve.date_published, utc=True, errors="coerce")
    ms = cve[(cve.assigner_short_name == "microsoft") & (cve.pub.dt.year >= 2024)]
    kev = pd.DataFrame(json.load(open(ROOT / "processed/kev_catalog.json"))["vulnerabilities"])
    k = pd.to_datetime(kev.set_index("cveID").dateAdded)
    rows = []
    for _, r in ms.iterrows():
        y = r.cve_id.split("-")[1]
        f = glob.glob(str(ROOT / f"data/cvelistV5/cves/{y}/*/{r.cve_id}.json"))
        if not f:
            continue
        cna = json.load(open(f[0]))["containers"]["cna"]
        title = cna.get("title", "") or ""
        vec = ""
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):   # first match wins; v3.1 preferred
            for m in cna.get("metrics", []):
                if key in m and not vec:
                    vec = m[key].get("vectorString", "") or ""
        g = lambda pat: (re.search(pat, vec).group(1) if re.search(pat, vec) else "")  # noqa: E731
        imp = re.search(IMP, title)
        comp = re.sub(r"\s*" + IMP + r"\s*Vulnerability.*$", "", title).strip()
        rows.append(dict(cve_id=r.cve_id, pub=r.pub, year=r.pub.year, title=title, comp=comp,
                         impact=imp.group(1) if imp else "Other", E=g(r"/E:([UPFHXA])"),
                         AV=g(r"/AV:([NALP])"), cvss=r["cvss_v3"], cwe=r["cwe"]))
    d = pd.DataFrame(rows)
    d["kev"] = d.cve_id.map(k)
    d["lag"] = (d.kev.dt.normalize() - d.pub.dt.tz_convert(None).dt.normalize()).dt.days
    d["kevflag"] = d.kev.notna()
    d["day"] = d.pub.dt.tz_convert(None).dt.normalize()
    return d


def main():
    d = parse()
    out = {}
    out["records_2024_26"] = len(d)
    out["kev_2024_26"] = int(d.kevflag.sum())
    out["base_rate"] = round(d.kevflag.mean(), 4)
    byE = d.groupby("E").agg(n=("kevflag", "size"), k=("kevflag", "sum"))
    out["E"] = byE.to_dict("index")
    d26 = d[d.year == 2026]
    day0 = d26[d26.kevflag & (d26.lag <= 0)]
    out["kev26_day0_total"] = len(day0)
    out["kev26_day0_EF"] = int((day0.E == "F").sum())
    out["cvss_median_all"] = d26.cvss.median()
    out["cvss_median_kev"] = d26[d26.kevflag].cvss.median()
    out["cvss_ge9_share_all"] = round((d26.cvss >= 9).mean(), 3)
    out["cvss_ge9_share_kev"] = round((d26[d26.kevflag].cvss >= 9).mean(), 3)
    s8 = d26[d26.day == PTS[-1]]
    out["sept_n"] = len(s8)
    out["sept_ge78"] = int((s8.cvss >= 7.8).sum())
    out["sept_ge9"] = int((s8.cvss >= 9).sum())
    # component history
    g = d.groupby(["comp", "impact"]).agg(n=("kevflag", "size"), k=("kevflag", "sum"))
    out["sharepoint_rce"] = g.loc[("Microsoft SharePoint", "Remote Code Execution")].to_dict()
    out["afd_eop"] = g.loc[("Windows Ancillary Function Driver for WinSock", "Elevation of Privilege")].to_dict()
    out["clfs_eop"] = g.loc[("Windows Common Log File System Driver", "Elevation of Privilege")].to_dict()
    # backtest
    train, test = d[d.year < 2026], d[d.year == 2026].copy()
    imp_rate = train.groupby("impact").kevflag.mean()
    base = train.kevflag.mean()
    gt = train.groupby(["comp", "impact"]).agg(n=("kevflag", "size"), k=("kevflag", "sum"))

    def look(row):
        prior = imp_rate.get(row.impact, base)
        if (row.comp, row.impact) in gt.index:
            n, kk = gt.loc[(row.comp, row.impact)]
            return (kk + SHRINK * prior) / (n + SHRINK)
        return prior

    test["look"] = test.apply(look, axis=1)
    test["eflag"] = test.E.map({"F": 2, "P": 1}).fillna(0)
    test["combo"] = test.eflag * 10 + test["look"]
    test["rand"] = np.random.default_rng(SEED).random(len(test))
    pt = test[test.day.isin(PTS)]
    out["pt_n"] = len(pt)
    out["pt_kev"] = int(pt.kevflag.sum())
    hard = pt[pt.kevflag & (pt.E != "F")]
    out["hard_n"] = len(hard)
    out["hard_day0"] = int((hard.lag <= 0).sum())
    out["hard_lags"] = sorted(int(x) for x in hard.lag)
    out["hard_rows"] = hard.sort_values("pub")[["cve_id", "title", "E", "cvss", "lag"]].to_dict("records")

    def evaluate(scorer, K):
        hits = hard_hits = 0
        for p in PTS:
            rel = pt[pt.day == p].copy()
            rel["s"] = (rel.cvss.fillna(0) if scorer == "cvss" else rel[scorer]) + rel.rand * 1e-9
            top = rel.sort_values("s", ascending=False).head(K)
            hits += int(top.kevflag.sum())
            hard_hits += int((top.kevflag & (top.E != "F")).sum())
        return hits, hard_hits

    out["backtest"] = {sc: {K: evaluate(sc, K) for K in (10, 25)} for sc in ("rand", "cvss", "eflag", "look", "combo")}
    # multi-seed means (CVSS has massive ties; a single seed is a single draw)
    means = {}
    for sc in ("rand", "cvss", "eflag", "look", "combo"):
        acc = {10: [0, 0], 25: [0, 0]}
        for seed in range(200):
            test["rand"] = np.random.default_rng(seed).random(len(test))
            pt_s = test[test.day.isin(PTS)]
            for K in (10, 25):
                hits = hard_hits = 0
                for p in PTS:
                    rel = pt_s[pt_s.day == p].copy()
                    rel["s"] = (rel.cvss.fillna(0) if sc == "cvss" else rel[sc]) + rel.rand * 1e-9
                    top = rel.sort_values("s", ascending=False).head(K)
                    hits += int(top.kevflag.sum()); hard_hits += int((top.kevflag & (top.E != "F")).sum())
                acc[K][0] += hits; acc[K][1] += hard_hits
        means[sc] = {K: (round(acc[K][0] / 200, 1), round(acc[K][1] / 200, 1)) for K in (10, 25)}
    out["backtest_200seed_means"] = means
    test["rand"] = np.random.default_rng(SEED).random(len(test))
    # flag revision risk: E:F KEV records listed after publication day
    ef_kev = d[(d.E == "F") & d.kevflag]
    out["ef_kev_lag_gt0"] = int((ef_kev.lag > 0).sum())
    out["ef_kev_lags_gt0"] = sorted(int(x) for x in ef_kev.lag[ef_kev.lag > 0])
    # SharePoint across all title variants
    sp = d[d.comp.str.contains("SharePoint") & (d.impact == "Remote Code Execution")]
    out["sharepoint_rce_all_titles"] = {"n": len(sp), "k": int(sp.kevflag.sum()), "titles": sorted(sp.comp.unique().tolist())}
    sp_hard = hard[hard.comp.str.contains("SharePoint")]
    out["hard_sharepoint_n"] = len(sp_hard)
    out["hard_sharepoint_cwes"] = sp_hard.cwe.tolist()
    out["hard_within14"] = int((hard.lag <= 14).sum())
    out["hard_within14_sharepoint"] = int(((hard.lag <= 14) & hard.comp.str.contains("SharePoint")).sum())
    out["hard_after14_sharepoint"] = int(((hard.lag > 14) & hard.comp.str.contains("SharePoint")).sum())
    # NTFS info-disclosure in TRAINING set
    ntfs = train[(train.comp == "Windows NTFS") & (train.impact == "Information Disclosure")]
    out["ntfs_id_train"] = {"n": len(ntfs), "k": int(ntfs.kevflag.sum())}
    out["expected_random_hits10"] = round(sum(10 * grp.kevflag.sum() / len(grp) for _, grp in pt.groupby("day")), 2)
    sept = pt[pt.day == PTS[-1]].copy()
    sept["s"] = sept.combo + sept.rand * 1e-9
    out["sept_top10_combo"] = sept.sort_values("s", ascending=False).head(10)[["cve_id", "title", "E", "look", "kevflag"]].to_dict("records")
    # EPSS the day after publication, for the 2026 KEV cohort scored by the report card
    snaps = {Path(f).name[5:15]: f for f in glob.glob(str(ROOT / "processed/epss_history_cache/slim-*.parquet"))}
    late = d26[d26.kevflag & (d26.lag >= 2)]
    ep = []
    for _, r in late.iterrows():
        pub = r.pub.tz_convert(None).normalize()
        got = None
        for off in range(1, 8):   # day after publication, else the first snapshot within a week
            key = (pub + pd.Timedelta(days=off)).strftime("%Y-%m-%d")
            if key in snaps:
                sn = pd.read_parquet(snaps[key]); row = sn[sn.cve_id == r.cve_id]
                if len(row):
                    got = dict(cve_id=r.cve_id, snap_offset_days=off, epss=round(float(row.epss.iloc[0]), 4), percentile=round(float(row.percentile.iloc[0]), 3), kev_lag=int(r.lag)); break
        ep.append(got or dict(cve_id=r.cve_id, snap_offset_days=None, epss=None, percentile=None, kev_lag=int(r.lag)))
    out["epss_day_after"] = ep
    scored = [e for e in ep if e["epss"] is not None]
    out["epss_day_after_scored"] = len(scored)
    out["epss_day_after_ge_0_1"] = sum(e["epss"] >= 0.1 for e in scored)
    out["epss_day_after_median"] = round(float(np.median([e["epss"] for e in scored])), 4) if scored else None
    kevfile = json.load(open(ROOT / "processed/kev_catalog.json"))
    out["kev_catalog_released"] = kevfile.get("dateReleased")
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()

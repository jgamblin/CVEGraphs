"""Small feeds: CISA KEV, ENISA EUVD exploited, CVEForecast, production EPSS, MITRE CWE pillars."""

import csv
import datetime
import gzip
import io
import json
import re
import time
import zipfile

import pandas as pd
import requests

from cvegraphs.data.refresh.common import OUTPUT_DIR, _fetch_json

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
# ENISA EU Vulnerability Database: the exploited (EU KEV) subset, paged 100 at a time.
EUVD_EXPLOITED_URL = "https://euvdservices.enisa.europa.eu/api/search?exploited=true&page={page}&size=100"
FORECAST_URLS = [
    "https://cveforecast.org/data.json",
    "https://raw.githubusercontent.com/RogoLabs/CVEForecast/main/web/data.json",
]
# Production EPSS daily scores, mirrored by Empirical Security. This path always
# serves the current production model: as of 2026-06-15 that is the V5 generation
# (model v2026.06.15), which superseded V4 (v2025.03.14) and the retired V5-beta
# feed. The captured model_version in each file records exactly which model ran.
# Files are date-stamped; "current" = the most recent date that exists (the feed
# lags a day or two), so fetch_epss walks back from today until one downloads.
EPSS_URL = (
    "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/"
    "{year}/epss_scores-{date}.csv.gz"
)
# MITRE CWE-1000 Research view: every weakness chains up to one of 10 Pillars.
CWE_VIEW_URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"


def _parse_epss_gz(content):
    """Parse a gzipped EPSS CSV (with leading # comment lines) into a DataFrame.

    Returns (df[cve_id, epss, percentile], score_date, model_version).
    """
    with gzip.open(io.BytesIO(content), "rt") as f:
        raw = f.read()
    # The first commented line carries metadata, e.g.
    #   #model_version:v2025.03.14,score_date:2025-04-01T00:00:00+0000
    score_date = model_version = None
    if raw.startswith("#"):
        header = raw.split("\n", 1)[0].lstrip("#")
        for part in header.split(","):
            k, _, v = part.partition(":")
            if k.strip() == "score_date":
                score_date = v.strip()
            elif k.strip() == "model_version":
                model_version = v.strip()
    while raw.startswith("#"):
        raw = raw[raw.index("\n") + 1:]
    df = pd.read_csv(io.StringIO(raw))
    df.columns = [c.strip() for c in df.columns]
    df = df.rename(columns={"cve": "cve_id"})  # match NVD/CVEList join key
    df["epss"] = pd.to_numeric(df["epss"], errors="coerce")
    df["percentile"] = pd.to_numeric(df["percentile"], errors="coerce")
    return df[["cve_id", "epss", "percentile"]], score_date, model_version


def fetch_epss(days_back=10):
    """Fetch the most recent production EPSS scores into processed/epss.parquet.

    The production feed currently serves the V5 model; the exact model is recorded
    in the model_version column so charts can label it precisely.
    """
    OUTPUT_DIR.mkdir(exist_ok=True)
    today = datetime.datetime.now(datetime.timezone.utc).date()
    for delta in range(days_back + 1):
        day = today - datetime.timedelta(days=delta)
        url = EPSS_URL.format(year=day.year, date=day.isoformat())
        try:
            print(f"  EPSS: trying {day.isoformat()} ...")
            resp = requests.get(url, timeout=120)
            if resp.status_code == 404:
                continue
            resp.raise_for_status()
            df, score_date, model_version = _parse_epss_gz(resp.content)
            df["score_date"] = score_date or day.isoformat()
            df["model_version"] = model_version
            df.to_parquet(OUTPUT_DIR / "epss.parquet", index=False)
            print(
                f"[EPSS] wrote processed/epss.parquet "
                f"({len(df):,} CVEs, score_date {df['score_date'].iloc[0]}, "
                f"{model_version or 'unknown model'})"
            )
            return
        except Exception as e:  # noqa: BLE001 - try the previous day
            print(f"    {day.isoformat()} failed: {e}")
    print("[EPSS] no scores found in the lookback window; leaving existing file")


def fetch_cwe_pillars():
    """Map every CWE to its top-level MITRE Pillar (CWE-1000 Research view)."""
    try:
        print("  CWE: fetching MITRE CWE-1000 hierarchy ...")
        content = requests.get(CWE_VIEW_URL, timeout=60).content
    except Exception as e:  # noqa: BLE001
        print(f"[CWE] fetch failed ({e}); leaving existing cwe_pillars.json")
        return
    zf = zipfile.ZipFile(io.BytesIO(content))
    rows = list(csv.DictReader(io.StringIO(zf.read(zf.namelist()[0]).decode("utf-8", "replace"))))
    abstraction, cname, parents = {}, {}, {}
    for r in rows:
        cid = "CWE-" + r["CWE-ID"]
        abstraction[cid] = r.get("Weakness Abstraction", "")
        cname[cid] = r.get("Name", "")
        parents[cid] = ["CWE-" + m.group(1) for m in re.finditer(
            r"NATURE:ChildOf:CWE ID:(\d+):VIEW ID:1000", r.get("Related Weaknesses", "") or "")]
    pillars = {c for c, a in abstraction.items() if a == "Pillar"}

    def to_pillar(cid, seen=None):
        seen = seen or set()
        if cid in pillars:
            return cid
        if cid in seen or cid not in parents:
            return None
        seen.add(cid)
        for p in parents[cid]:
            r = to_pillar(p, seen)
            if r:
                return r
        return None

    mapping = {c: to_pillar(c) for c in parents if to_pillar(c)}
    OUTPUT_DIR.mkdir(exist_ok=True)
    (OUTPUT_DIR / "cwe_pillars.json").write_text(json.dumps({
        "_source": "MITRE CWE-1000 Research Concepts view (cwe.mitre.org)",
        "pillars": {p: cname[p] for p in sorted(pillars)},
        "cwe_to_pillar": mapping,
    }, indent=1))
    print(f"[CWE] wrote processed/cwe_pillars.json ({len(mapping)} CWEs -> {len(pillars)} pillars)")


def fetch_feeds():
    OUTPUT_DIR.mkdir(exist_ok=True)
    kev = _fetch_json(KEV_URLS)
    if kev is not None:
        with open(OUTPUT_DIR / "kev_catalog.json", "w") as f:
            json.dump(kev, f)
        n = len(kev.get("vulnerabilities", []))
        print(f"[KEV] wrote processed/kev_catalog.json ({n:,} entries)")
    else:
        print("[KEV] fetch failed; leaving any existing kev_catalog.json in place")

    forecast = _fetch_json(FORECAST_URLS)
    if forecast is not None:
        with open(OUTPUT_DIR / "forecast.json", "w") as f:
            json.dump(forecast, f)
        print("[Forecast] wrote processed/forecast.json")
    else:
        print("[Forecast] fetch failed; leaving any existing forecast.json in place")

    fetch_euvd_exploited()
    fetch_epss()
    fetch_cwe_pillars()


def fetch_euvd_exploited():
    """ENISA EUVD exploited list -> processed/euvd_kev.json (slim rows).

    Keeps only the fields the charts use; the CVE id lives in the ``aliases``
    blob alongside GHSA ids. Leaves any existing file in place on failure or a
    short read, so a flaky page never truncates the list.
    """
    items, page, total = [], 0, None
    try:
        while True:
            r = requests.get(EUVD_EXPLOITED_URL.format(page=page),
                             headers={"User-Agent": "CVEGraphs"}, timeout=60)
            r.raise_for_status()
            d = r.json()
            total = d.get("total", 0)
            batch = d.get("items", [])
            items += batch
            if not batch or len(items) >= total:
                break
            page += 1
            time.sleep(0.3)
    except Exception as e:
        print(f"[EUVD] fetch failed ({e}); leaving any existing euvd_kev.json in place")
        return
    if total is None or len(items) < total:
        print(f"[EUVD] short read ({len(items)} of {total}); leaving existing file")
        return
    keep = ("id", "aliases", "datePublished", "exploitedSince", "assigner", "baseScore")
    slim = [{k: i.get(k) for k in keep} for i in items]
    (OUTPUT_DIR / "euvd_kev.json").write_text(json.dumps(slim))
    print(f"[EUVD] wrote processed/euvd_kev.json ({len(slim):,} exploited entries)")

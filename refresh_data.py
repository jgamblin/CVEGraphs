#!/usr/bin/env python3
"""
Self-contained weekly data refresh for CVEGraphs.

Builds this repo's OWN copy of the processed data from upstream feeds, so the
repo is rebuildable anywhere without depending on a sibling checkout:

    NVD JSON            https://nvd.handsonhacking.org/nvd.json      -> processed/nvd_cves.parquet
    CVE List V5 (git)   github.com/CVEProject/cvelistV5              -> processed/cvelist_v5.parquet
    CISA KEV catalog    cisa.gov feed                                -> processed/kev_catalog.json
    CVEForecast feed    cveforecast.org/data.json                    -> processed/forecast.json
    EPSS scores (V5)    empiricalsec/epss_scores (daily, production)  -> processed/epss.parquet

Raw downloads land in ./data (gitignored, ~large). Processed parquet lands in
./processed (gitignored; this repo keeps it locally per project decision).

Usage:
    python refresh_data.py                # full refresh (download + process + feeds)
    python refresh_data.py --process-only # reprocess existing ./data, skip downloads
    python refresh_data.py --feeds-only   # only KEV + forecast (fast)
    python refresh_data.py --force        # force NVD re-download

Parsing logic mirrors H12026CVEBlog steps 01/02 so the parquet schema is
byte-for-byte compatible with data.py / charts/.
"""

import argparse
import concurrent.futures
import csv
import datetime
import gzip
import io
import json
import re
import shutil
import subprocess
import tarfile
import time
import warnings
import zipfile
from email.utils import parsedate_to_datetime
from pathlib import Path

import pandas as pd
import requests

try:
    from tqdm import tqdm
except ImportError:  # tqdm is optional; degrade to a no-op iterator
    def tqdm(it=None, **kwargs):
        return it if it is not None else iter(())

warnings.filterwarnings("ignore")

HERE = Path(__file__).resolve().parent
DATA_DIR = HERE / "data"
OUTPUT_DIR = HERE / "processed"

NVD_URL = "https://nvd.handsonhacking.org/nvd.json"
CVELIST_REPO = "https://github.com/CVEProject/cvelistV5.git"
# Tarball fallback: a single streamed HTTP download (like NVD), far more reliable
# than git's smart protocol for this very large repo, which frequently resets
# mid-pack ("RPC failed ... Connection reset by peer").
CVELIST_TARBALL = "https://codeload.github.com/CVEProject/cvelistV5/tar.gz/refs/heads/main"
KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json",
]
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


# =============================================================================
# DOWNLOAD
# =============================================================================
def download_nvd(force=False):
    """Download the NVD JSON (~1.7GB) atomically, with retry and freshness check."""
    DATA_DIR.mkdir(exist_ok=True)
    out = DATA_DIR / "nvd.json"

    need = force or not out.exists()
    if out.exists() and not force:
        try:
            head = requests.head(NVD_URL, timeout=10)
            head.raise_for_status()
            lm = head.headers.get("Last-Modified")
            if lm:
                remote = parsedate_to_datetime(lm)
                local = datetime.datetime.fromtimestamp(
                    out.stat().st_mtime, tz=datetime.timezone.utc
                )
                if remote > local:
                    print(f"  NVD: remote is newer ({lm})")
                    need = True
                else:
                    print("  NVD: local copy is up to date")
            remote_size = int(head.headers.get("content-length", 0))
            if remote_size and abs(remote_size - out.stat().st_size) > 1024 * 1024:
                need = True
        except requests.RequestException as e:
            print(f"  NVD: could not check for updates ({e}); using existing file")
            return out

    if not need:
        return out

    print(f"  NVD: downloading {NVD_URL} (large, please wait) ...")
    tmp = out.with_name("nvd.json.part")
    last_err = None
    for attempt in range(1, 4):
        try:
            resp = requests.get(NVD_URL, stream=True, timeout=(30, 300))
            resp.raise_for_status()
            total = int(resp.headers.get("content-length", 0))
            with open(tmp, "wb") as f, tqdm(
                total=total, unit="iB", unit_scale=True, unit_divisor=1024
            ) as pbar:
                for chunk in resp.iter_content(chunk_size=8192):
                    pbar.update(f.write(chunk))
            got = tmp.stat().st_size
            if total and got < total:
                raise IOError(f"incomplete download: {got:,}/{total:,} bytes")
            tmp.replace(out)
            print(f"  NVD: saved {out} ({out.stat().st_size / 1e9:.2f} GB)")
            return out
        except Exception as e:  # noqa: BLE001 - report, back off, retry
            last_err = e
            print(f"  NVD: attempt {attempt}/3 failed: {e}")
            if attempt < 3:
                time.sleep(5 * attempt)
    tmp.unlink(missing_ok=True)
    raise RuntimeError(f"NVD download failed after 3 attempts: {last_err}")


def _git_clone_cvelist(out, attempts=3):
    """Shallow git clone with retries + a larger HTTP buffer. Returns success."""
    for attempt in range(1, attempts + 1):
        if out.exists():
            shutil.rmtree(out, ignore_errors=True)  # git won't clone into a stale dir
        try:
            print(f"  CVEList V5: git clone attempt {attempt}/{attempts} ...")
            subprocess.run(
                ["git", "-c", "http.postBuffer=524288000",
                 "clone", "--depth", "1", CVELIST_REPO, str(out)],
                check=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"    git clone failed: {e}")
            if attempt < attempts:
                time.sleep(5 * attempt)
    return False


def _download_cvelist_tarball(out):
    """Fallback: stream the GitHub tarball and extract it into ``out``."""
    tmp = DATA_DIR / "cvelistV5.tar.gz"
    last_err = None
    for attempt in range(1, 4):
        try:
            print(f"  CVEList V5: tarball download attempt {attempt}/3 ...")
            with requests.get(CVELIST_TARBALL, stream=True, timeout=(30, 600)) as r:
                r.raise_for_status()
                with open(tmp, "wb") as f, tqdm(
                    unit="iB", unit_scale=True, unit_divisor=1024
                ) as pbar:
                    for chunk in r.iter_content(chunk_size=1 << 20):
                        pbar.update(f.write(chunk))
            break
        except Exception as e:  # noqa: BLE001 - report, back off, retry
            last_err = e
            print(f"    tarball attempt {attempt}/3 failed: {e}")
            tmp.unlink(missing_ok=True)
            if attempt < 3:
                time.sleep(5 * attempt)
    else:
        raise RuntimeError(f"CVEList tarball download failed after 3 attempts: {last_err}")

    if out.exists():
        shutil.rmtree(out, ignore_errors=True)
    print("  CVEList V5: extracting tarball ...")
    with tarfile.open(tmp, "r:gz") as tf:
        tf.extractall(DATA_DIR, filter="data")  # extracts to cvelistV5-main/
    tmp.unlink(missing_ok=True)
    extracted = DATA_DIR / "cvelistV5-main"
    if extracted.exists():
        extracted.rename(out)


def clone_or_update_cvelist():
    """Get the CVE List V5 tree into ./data, resiliently.

    Existing git clone -> fast-forward. Otherwise git clone with retries, and if
    that keeps failing (the repo is large and the transfer often resets), fall
    back to a streamed tarball download.
    """
    DATA_DIR.mkdir(exist_ok=True)
    out = DATA_DIR / "cvelistV5"
    if (out / ".git").exists():
        print("  CVEList V5: updating existing clone ...")
        try:
            subprocess.run(["git", "-C", str(out), "fetch", "--unshallow"], check=False)
            subprocess.run(["git", "-C", str(out), "pull", "--ff-only"], check=True)
            return out
        except subprocess.CalledProcessError as e:
            print(f"    update failed ({e}); refetching fresh")

    if _git_clone_cvelist(out):
        return out
    print("  CVEList V5: git clone exhausted retries; using tarball fallback")
    _download_cvelist_tarball(out)
    return out


# =============================================================================
# PARSE NVD  (schema must match H12026CVEBlog/02_process_data.py exactly)
# =============================================================================
def _parse_nvd(items):
    records, skipped = [], 0
    for item in tqdm(items, desc="  NVD parse"):
        try:
            if "cve" not in item:
                continue
            cve_data = item["cve"]

            if "id" in cve_data:  # NVD API 2.0
                cve_id = cve_data["id"]
                published = cve_data.get("published", "")
                modified = cve_data.get("lastModified", "")
                descriptions = cve_data.get("descriptions", [])
                description = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"), ""
                )
                metrics = cve_data.get("metrics", {})
                cvss_v3 = cvss_v2 = cvss_v4 = severity = None
                if metrics.get("cvssMetricV40"):
                    d = metrics["cvssMetricV40"][0].get("cvssData", {})
                    cvss_v4, severity = d.get("baseScore"), d.get("baseSeverity")
                if metrics.get("cvssMetricV31"):
                    d = metrics["cvssMetricV31"][0].get("cvssData", {})
                    cvss_v3 = d.get("baseScore")
                    severity = severity or d.get("baseSeverity")
                if metrics.get("cvssMetricV30") and cvss_v3 is None:
                    d = metrics["cvssMetricV30"][0].get("cvssData", {})
                    cvss_v3 = d.get("baseScore")
                    severity = severity or d.get("baseSeverity")
                if metrics.get("cvssMetricV2"):
                    m = metrics["cvssMetricV2"][0]
                    cvss_v2 = m.get("cvssData", {}).get("baseScore")
                    severity = severity or m.get("baseSeverity")
                cwes = [
                    desc["value"]
                    for w in cve_data.get("weaknesses", [])
                    for desc in w.get("description", [])
                    if desc.get("value", "").startswith("CWE-")
                ]
                cwe = cwes[0] if cwes else None
                cpes = [
                    cm.get("criteria", "")
                    for cfg in cve_data.get("configurations", [])
                    for node in cfg.get("nodes", [])
                    for cm in node.get("cpeMatch", [])
                ]
                ref_count = len(cve_data.get("references", []))
                vuln_status = cve_data.get("vulnStatus", "")
            else:  # old NVD format
                cve_id = cve_data.get("CVE_data_meta", {}).get("ID", "")
                published = item.get("publishedDate", "")
                modified = item.get("lastModifiedDate", "")
                desc_data = cve_data.get("description", {}).get("description_data", [])
                description = next(
                    (d["value"] for d in desc_data if d.get("lang") == "en"), ""
                )
                impact = item.get("impact", {})
                cvss_v3 = impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore")
                cvss_v2 = impact.get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore")
                cvss_v4 = None
                severity = impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity")
                severity = severity or impact.get("baseMetricV2", {}).get("severity")
                cwes = [
                    desc["value"]
                    for pt in cve_data.get("problemtype", {}).get("problemtype_data", [])
                    for desc in pt.get("description", [])
                    if desc.get("value", "").startswith("CWE-")
                ]
                cwe = cwes[0] if cwes else None
                cpes = [
                    cm.get("cpe23Uri", "")
                    for node in item.get("configurations", {}).get("nodes", [])
                    for cm in node.get("cpe_match", [])
                ]
                ref_count = len(cve_data.get("references", {}).get("reference_data", []))
                vuln_status = ""

            try:
                pub_date = pd.to_datetime(published, utc=True)
            except Exception:
                pub_date = None
            try:
                mod_date = pd.to_datetime(modified, utc=True)
            except Exception:
                mod_date = None
            try:
                cve_year = int(cve_id.split("-")[1])
            except Exception:
                cve_year = None
            year = pub_date.year if pub_date is not None else cve_year

            is_rejected = bool(vuln_status) and vuln_status.upper() in ("REJECTED", "REJECT")
            if not is_rejected and description:
                dl = description.lower()
                is_rejected = (
                    "** reject **" in dl
                    or "** disputed **" in dl
                    or "this cve id has been rejected" in dl
                )

            vendor = product = None
            for cpe in cpes:
                if cpe:
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3] if parts[3] != "*" else None
                        product = parts[4] if parts[4] != "*" else None
                        if vendor and product:
                            break

            records.append({
                "cve_id": cve_id,
                "year": year,
                "cve_year": cve_year,
                "published": pub_date,
                "modified": mod_date,
                "description": description[:500] if description else "",
                "cvss_v2": cvss_v2,
                "cvss_v3": cvss_v3,
                "cvss_v4": cvss_v4,
                "severity": severity,
                "cwe": cwe,
                "cpe_count": len(cpes),
                "has_cpe": len(cpes) > 0,
                "vendor": vendor,
                "product": product,
                "ref_count": ref_count,
                "vuln_status": vuln_status,
                "is_rejected": is_rejected,
            })
        except Exception:
            skipped += 1
            continue

    df = pd.DataFrame(records)
    if skipped:
        print(f"  NVD: skipped {skipped:,} unparseable entries")
    return df


def process_nvd():
    print("[NVD] loading JSON (1GB+, this takes a minute) ...")
    with open(DATA_DIR / "nvd.json") as f:
        data = json.load(f)
    items = data if isinstance(data, list) else data.get(
        "CVE_Items", data.get("vulnerabilities", [])
    )
    print(f"[NVD] parsing {len(items):,} entries ...")
    df = _parse_nvd(items)
    OUTPUT_DIR.mkdir(exist_ok=True)
    df.to_parquet(OUTPUT_DIR / "nvd_cves.parquet", index=False)
    print(f"[NVD] wrote processed/nvd_cves.parquet ({len(df):,} rows)")
    return df


# =============================================================================
# PARSE CVE LIST V5  (module-level for ProcessPoolExecutor / macOS spawn)
# =============================================================================
def _process_cve_file(cve_file):
    try:
        with open(cve_file) as f:
            data = json.load(f)
        meta = data.get("cveMetadata", {})
        cve_id = meta.get("cveId", cve_file.stem)
        state = meta.get("state", "")
        date_reserved = meta.get("dateReserved", "")
        date_published = meta.get("datePublished", "")
        cna = data.get("containers", {}).get("cna", {})

        vendors, products = [], []
        for aff in cna.get("affected", []):
            if aff.get("vendor"):
                vendors.append(aff["vendor"])
            if aff.get("product"):
                products.append(aff["product"])

        cwes = [
            desc["cweId"]
            for pt in cna.get("problemTypes", [])
            for desc in pt.get("descriptions", [])
            if desc.get("cweId")
        ]

        cvss_v3 = cvss_v4 = severity = None
        for m in cna.get("metrics", []):
            if "cvssV4_0" in m:
                cvss_v4 = m["cvssV4_0"].get("baseScore")
                severity = m["cvssV4_0"].get("baseSeverity")
            if "cvssV3_1" in m:
                cvss_v3 = m["cvssV3_1"].get("baseScore")
                severity = severity or m["cvssV3_1"].get("baseSeverity")
            if "cvssV3_0" in m and cvss_v3 is None:
                cvss_v3 = m["cvssV3_0"].get("baseScore")
                severity = severity or m["cvssV3_0"].get("baseSeverity")

        descriptions = cna.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"), ""
        )
        try:
            cve_year = int(cve_id.split("-")[1])
        except Exception:
            cve_year = None
        try:
            pub_date = pd.to_datetime(date_published, utc=True) if date_published else None
        except Exception:
            pub_date = None
        try:
            reserved_date = pd.to_datetime(date_reserved, utc=True) if date_reserved else None
        except Exception:
            reserved_date = None
        year = pub_date.year if pub_date is not None else cve_year

        return {
            "cve_id": cve_id,
            "year": year,
            "cve_year": cve_year,
            "state": state,
            "date_reserved": reserved_date,
            "date_published": pub_date,
            "assigner_org_id": meta.get("assignerOrgId", ""),
            "assigner_short_name": meta.get("assignerShortName", ""),
            "vendor": vendors[0] if vendors else None,
            "product": products[0] if products else None,
            "vendor_count": len(set(vendors)),
            "product_count": len(set(products)),
            "cwe": cwes[0] if cwes else None,
            "cwe_count": len(cwes),
            "cvss_v3": cvss_v3,
            "cvss_v4": cvss_v4,
            "severity": severity,
            "description": description[:500] if description else "",
            "ref_count": len(cna.get("references", [])),
            "is_rejected": state == "REJECTED",
            "is_published": state == "PUBLISHED",
        }
    except Exception:
        return None


def process_cvelist():
    root = DATA_DIR / "cvelistV5" / "cves"
    if not root.exists():
        root = DATA_DIR / "cvelistV5"
    print(f"[CVEList] scanning {root} ...")
    files = list(root.rglob("CVE-*.json"))
    print(f"[CVEList] parsing {len(files):,} files in parallel ...")
    with concurrent.futures.ProcessPoolExecutor() as ex:
        results = list(tqdm(
            ex.map(_process_cve_file, files, chunksize=1000),
            total=len(files), desc="  CVEList parse",
        ))
    records = [r for r in results if r is not None]
    failed = len(results) - len(records)
    if failed:
        print(f"  CVEList: {failed:,} files failed to parse")
    df = pd.DataFrame(records)
    OUTPUT_DIR.mkdir(exist_ok=True)
    df.to_parquet(OUTPUT_DIR / "cvelist_v5.parquet", index=False)
    print(f"[CVEList] wrote processed/cvelist_v5.parquet ({len(df):,} rows)")

    # CNA leaderboard input (used by future cna chart).
    cna = (
        df.groupby("assigner_short_name")
        .agg(total_cves=("cve_id", "count"),
             published=("is_published", "sum"),
             rejected=("is_rejected", "sum"))
        .sort_values("total_cves", ascending=False)
    )
    cna.to_csv(OUTPUT_DIR / "cna_stats.csv")
    return df


# =============================================================================
# SMALL FEEDS
# =============================================================================
def _fetch_json(urls, retries=3):
    for url in urls:
        for attempt in range(1, retries + 1):
            try:
                print(f"  fetching {url} (attempt {attempt}/{retries}) ...")
                r = requests.get(url, timeout=30)
                r.raise_for_status()
                return r.json()
            except Exception as e:  # noqa: BLE001
                print(f"    could not fetch {url}: {e}")
                if attempt < retries:
                    time.sleep(3 * attempt)
    return None


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

    fetch_epss()
    fetch_cwe_pillars()


# =============================================================================
# CLI
# =============================================================================
def main():
    ap = argparse.ArgumentParser(description="Rebuild CVEGraphs data from upstream feeds")
    ap.add_argument("--process-only", action="store_true",
                    help="reprocess existing ./data, skip downloads")
    ap.add_argument("--feeds-only", action="store_true",
                    help="only fetch KEV + forecast feeds")
    ap.add_argument("--force", action="store_true", help="force NVD re-download")
    args = ap.parse_args()

    print("=" * 60)
    print("CVEGraphs data refresh")
    print("=" * 60)

    if args.feeds_only:
        fetch_feeds()
        return

    if not args.process_only:
        print("\n[1/3] Downloading sources ...")
        download_nvd(force=args.force)
        clone_or_update_cvelist()

    print("\n[2/3] Processing to parquet ...")
    process_nvd()
    process_cvelist()

    print("\n[3/3] Fetching feeds ...")
    fetch_feeds()

    print("\nDone. Data is in ./processed. Render with: python make.py all")


if __name__ == "__main__":
    main()

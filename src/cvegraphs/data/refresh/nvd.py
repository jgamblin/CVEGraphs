"""NVD: download the full JSON mirror and parse it to processed/nvd_cves.parquet.

The parquet schema mirrors H12026CVEBlog/02_process_data.py so charts written
against either repo read the same columns.
"""

import datetime
import json
import time
from email.utils import parsedate_to_datetime

import pandas as pd
import requests

from cvegraphs.data.refresh.common import DATA_DIR, OUTPUT_DIR, tqdm

NVD_URL = "https://nvd.handsonhacking.org/nvd.json"


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


def reconcile_nvd_v4(nvd_df, cvelist_df):
    """Override NVD's cvss_v4 with the CNA's authoritative CVE List v4.

    The NVD JSON mirror carries stale/lower CVSS v4 base scores for many CVEs (it
    lags the CNA's own vector), which made v4 read ~0.6 points lower than it truly
    is and produced a spurious "v4 scores lower than v3" trend. The CVE List V5 CNA
    container is authoritative for the CNA's own v4, so we prefer it by cve_id and
    fall back to the NVD value only where CVE List has none. NVD's v3 matches the
    CNA and is left untouched.
    """
    auth_v4 = cvelist_df.dropna(subset=["cvss_v4"]).drop_duplicates(
        "cve_id").set_index("cve_id")["cvss_v4"]
    mapped = nvd_df["cve_id"].map(auth_v4)
    changed = int((mapped.notna() & (mapped != nvd_df["cvss_v4"])).sum())
    nvd_df = nvd_df.copy()
    nvd_df["cvss_v4"] = mapped.where(mapped.notna(), nvd_df["cvss_v4"])
    nvd_df.to_parquet(OUTPUT_DIR / "nvd_cves.parquet", index=False)
    print(f"[NVD] reconciled cvss_v4 from CVE List (authoritative): "
          f"{changed:,} scores corrected -> processed/nvd_cves.parquet")
    return nvd_df


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

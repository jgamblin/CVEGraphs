"""CVE List V5: clone (or tarball-download) cvelistV5 and parse it to processed/cvelist_v5.parquet."""

import concurrent.futures
import json
import re
import shutil
import subprocess
import tarfile
import time

import pandas as pd
import requests

from cvegraphs.data.refresh.common import DATA_DIR, OUTPUT_DIR, tqdm

# Matches a CWE id embedded in a problemTypes description, e.g.
# "CWE-79 Cross-Site Scripting (XSS)". Used when a CNA omits the `cweId` key.
CWE_IN_TEXT = re.compile(r"\bCWE-\d+", re.IGNORECASE)
CVELIST_REPO = "https://github.com/CVEProject/cvelistV5.git"
# Tarball fallback: a single streamed HTTP download (like NVD), far more reliable
# than git's smart protocol for this very large repo, which frequently resets
# mid-pack ("RPC failed ... Connection reset by peer").
CVELIST_TARBALL = "https://codeload.github.com/CVEProject/cvelistV5/tar.gz/refs/heads/main"


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
        print("  CVEList V5: updating existing clone (shallow) ...")
        try:
            # Shallow fetch of just the latest commit + hard reset. Never
            # --unshallow: that re-downloads the repo's entire history (huge and
            # slow) on every refresh.
            subprocess.run(["git", "-C", str(out), "fetch", "--depth", "1", "origin", "main"],
                           check=True)
            subprocess.run(["git", "-C", str(out), "reset", "--hard", "FETCH_HEAD"], check=True)
            return out
        except subprocess.CalledProcessError as e:
            print(f"    update failed ({e}); refetching fresh")

    if _git_clone_cvelist(out):
        return out
    print("  CVEList V5: git clone exhausted retries; using tarball fallback")
    _download_cvelist_tarball(out)
    return out


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

        # A CNA can declare a weakness class two ways: the optional `cweId` key, or a
        # bare "CWE-79 Cross-Site Scripting (XSS)" string in `description` (usually
        # with type "CWE"). Reading only `cweId` scored WPScan at 0% CWE coverage on
        # all 697 of its 2026 CVEs when the real figure is 100%, and did the same to
        # CERT/CC and Samsung Mobile. Accept either form; a literal CWE-<n> in the
        # description is a positive assertion, so it counts regardless of `type`.
        cwes = []
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_id = desc.get("cweId")
                if cwe_id:
                    cwes.append(cwe_id)
                    continue
                m = CWE_IN_TEXT.search(desc.get("description") or "")
                if m:
                    cwes.append(m.group(0).upper())

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

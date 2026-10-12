#!/usr/bin/env python3
"""
Precompute same-CVE CVSS v3 score pairs from the raw NVD mirror.

For every CVE PUBLISHED in the latest year, collect up to three v3.x base
scores per record, keyed by who authored them:

  * the OWNING CNA's own score (metric ``source`` == the record's
    ``sourceIdentifier``), and
  * a second opinion from the two U.S. government enrichment programs:
    NVD (``nvd@nist.gov``) and the CISA ADP / Vulnrichment
    (``134c704f-9b21-4f2e-91b3-4a467353bcc0``).

Other ADPs that re-score (e.g. Red Hat's SADP) are deliberately excluded so
the pair semantics stay one thing: "the CNA that owns the record" vs "the
government's second opinion". Cohort is publication year, not CVE-ID year,
matching the rest of the repo.

Streams data/nvd.json (1.7 GB) with a chunked regex scan rather than
json.load; the fields needed are flat and uniquely named inside each record.

Writes processed/score_pairs.parquet: cve_id, published, cna_source,
cna_name (assigner_short_name joined from the CVE List parquet), cna_score,
cna_vector, nvd_score, nvd_vector, adp_score, adp_vector. Rows are kept only
when the CNA score AND at least one second opinion exist.
"""

import re
from pathlib import Path

import pandas as pd

HERE = Path(__file__).resolve().parent
NVD_JSON = HERE / "data" / "nvd.json"
CVELIST = HERE / "processed" / "cvelist_v5.parquet"
OUT = HERE / "processed" / "score_pairs.parquet"

NVD_SRC = "nvd@nist.gov"
CISA_ADP_SRC = "134c704f-9b21-4f2e-91b3-4a467353bcc0"

RECORD_MARK = b'{"cve":{"id":"CVE-'
PAT_SOURCE_ID = re.compile(rb'"sourceIdentifier":"([^"]+)"')
PAT_PUBLISHED = re.compile(rb'"published":"(\d{4})-')
# One v3.x metric entry: source, then cvssData with version/vector/baseScore.
PAT_METRIC = re.compile(
    rb'"source":"([^"]+)","type":"(?:Primary|Secondary)","cvssData":'
    rb'\{"version":"3\.[01]","vectorString":"(CVSS:3\.[01]/[^"]+)",'
    rb'"baseScore":([\d.]+)'
)


def _latest_year(cl):
    """Most recent publication year with real volume (ignores stray future dates)."""
    yr = pd.to_datetime(cl["date_published"], utc=True, errors="coerce").dt.year
    counts = yr[cl["is_rejected"] != True].value_counts()
    return int(counts[counts >= 1000].index.max())


def _pairs_from_record(rec, year_bytes):
    """Return a row tuple for one raw record slice, or None."""
    mp = PAT_PUBLISHED.search(rec)
    if not mp or mp.group(1) != year_bytes:
        return None
    ms = PAT_SOURCE_ID.search(rec)
    if not ms:
        return None
    owner = ms.group(1).decode()

    cna = nvd = adp = None  # (score, vector), first metric per source wins
    for src, vec, score in PAT_METRIC.findall(rec):
        src = src.decode()
        entry = (float(score), vec.decode())
        if src == owner and cna is None:
            cna = entry
        elif src == NVD_SRC and nvd is None:
            nvd = entry
        elif src == CISA_ADP_SRC and adp is None:
            adp = entry
    if cna is None or (nvd is None and adp is None):
        return None

    cve_id = "CVE-" + rec[: rec.index(b'"')].decode()
    return (
        cve_id, owner, cna[0], cna[1],
        nvd[0] if nvd else None, nvd[1] if nvd else None,
        adp[0] if adp else None, adp[1] if adp else None,
    )


def main():
    cl = pd.read_parquet(
        CVELIST, columns=["cve_id", "date_published", "is_rejected",
                          "assigner_short_name"]
    )
    year = _latest_year(cl)
    year_bytes = str(year).encode()
    print(f"  score_pairs: scanning {NVD_JSON.name} for CVEs published in {year}")

    rows = []
    buf = b""
    with open(NVD_JSON, "rb") as f:
        while True:
            chunk = f.read(16 * 1024 * 1024)
            if not chunk:
                break
            buf += chunk
            parts = buf.split(RECORD_MARK)
            buf = RECORD_MARK + parts[-1]
            for rec in parts[1:-1]:
                row = _pairs_from_record(rec, year_bytes)
                if row:
                    rows.append(row)
    # The final buffered record has no trailing marker; process it too.
    if buf.startswith(RECORD_MARK):
        row = _pairs_from_record(buf[len(RECORD_MARK):], year_bytes)
        if row:
            rows.append(row)

    df = pd.DataFrame(rows, columns=[
        "cve_id", "cna_source", "cna_score", "cna_vector",
        "nvd_score", "nvd_vector", "adp_score", "adp_vector",
    ]).drop_duplicates("cve_id")
    df["year"] = year
    names = cl[["cve_id", "assigner_short_name"]].rename(
        columns={"assigner_short_name": "cna_name"})
    df = df.merge(names, on="cve_id", how="left")

    OUT.parent.mkdir(exist_ok=True)
    df.to_parquet(OUT, index=False)
    second = df["nvd_score"].fillna(df["adp_score"])
    band = lambda s: pd.cut(s, [0, 3.95, 6.95, 8.95, 10.0],
                            labels=["Low", "Medium", "High", "Critical"])
    flips = (band(df["cna_score"]).astype(str) != band(second).astype(str)).mean()
    print(f"wrote {OUT} ({len(df):,} pairs for {year}): "
          f"exact agreement {(df['cna_score'] == second).mean():.1%}, "
          f"band differs {flips:.1%}")


if __name__ == "__main__":
    main()

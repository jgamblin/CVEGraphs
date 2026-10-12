#!/usr/bin/env python3
"""
CVE tornado: a 3D spiral of CVEs published per day, one turn per calendar year.

Angle is day of year (Jan at 12 o'clock), height is time, radius is the smoothed
daily publication rate. As the yearly rate climbs the coil widens, so the whole
thing reads as a funnel/tornado growing out of the 2000s.

The page (tools/cvenado/template.html, three.js) is Ben Edwards' template from
github.com/empiricalsec/cvenado, restyled to the CVE Insights look (white ground,
navy ramp, Host Grotesk headline, eyebrow and stamp from style_social.py). The
data is CVE List V5 (published, non-rejected, by date_published) instead of the
CVE.org metadata parquet his build pulls from S3.

    python tools/cvenado/build.py            # writes graphs/cvenado.html

Open the file in a browser; three.js loads from jsdelivr, so it needs a network
connection. Press Play (or Space) for the growth animation.
"""

import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from data import load_cvelist  # noqa: E402
from rolling_config import data_asof, today_utc  # noqa: E402

HERE = Path(__file__).resolve().parent
OUT = ROOT / "graphs" / "cvenado.html"
START = pd.Timestamp("2000-01-01", tz="UTC")


def daily_counts():
    """One count per UTC day, 2000-01-01 through the last full day in the snapshot, zeros included."""
    df = load_cvelist()
    if "is_published" in df.columns:
        df = df[df["is_published"]]
    asof = data_asof(df)
    end = asof - pd.Timedelta(days=1)  # the newest day is still filling in
    dates = pd.to_datetime(df["date_published"], utc=True, errors="coerce").dropna().dt.floor("D")
    per_day = dates.value_counts()
    days = pd.date_range(START, end, freq="D", tz="UTC")
    counts = per_day.reindex(days, fill_value=0).astype(int)
    newest = pd.to_datetime(df["date_published"], utc=True, errors="coerce").max()
    return counts, newest


def main():
    counts, newest = daily_counts()
    snap = f"{newest:%Y-%m-%d %H:%M} UTC"
    page = (HERE / "template.html").read_text()
    page = (page.replace("__COUNTS__", ",".join(map(str, counts.tolist())))
                .replace("__SNAPSHOT__", snap)
                .replace("__STAMP__", today_utc().strftime("%b %d, %Y")))
    OUT.write_text(page)
    print(f"wrote {OUT.relative_to(ROOT)}: {len(counts):,} days, "
          f"{counts.index[0]:%Y-%m-%d} to {counts.index[-1]:%Y-%m-%d}, {int(counts.sum()):,} CVEs")


if __name__ == "__main__":
    main()

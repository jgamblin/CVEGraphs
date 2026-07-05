#!/usr/bin/env python3
"""
Rolling reporting-window configuration for CVEGraphs.

Unlike the H12026CVEBlog pipeline, which fixed a Jan 1 - Jun 30 window, the
social engine is *evergreen*: every chart is measured "as of today" so numbers
never go stale. Year-over-year comparisons use the SAME elapsed window (Jan 1
through today's month/day) in every prior year, so a partial current year is
never measured against a full one.

Everything routes through the helpers here so the window is defined in one place.
"""

import datetime as _dt

import pandas as pd

# First year of the CVE program; historical charts start here.
HIST_MIN_YEAR = 1999

# @-handle and site stamped onto every chart.
HANDLE = "@jgamblin"
SITE = "rogolabs.net"


def today_utc():
    """Current UTC date as a tz-aware midnight Timestamp."""
    now = _dt.datetime.now(_dt.timezone.utc)
    return pd.Timestamp(now.year, now.month, now.day, tz="UTC")


def current_year(asof=None):
    return (asof or today_utc()).year


def _date_column(df):
    """Name of the publish-date column present on ``df`` (or None)."""
    for col in ("published", "date_published"):
        if col in df.columns:
            return col
    return None


def data_asof(df):
    """Latest publish date actually present in ``df`` (the true 'as of' date).

    Data feeds lag, so the newest CVE in the snapshot is usually a day or two
    behind the wall clock. Charts anchor to this so the elapsed-window math
    matches the data we actually have, not the calendar.
    """
    col = _date_column(df)
    if col is None:
        return today_utc()
    dates = pd.to_datetime(df[col], utc=True, errors="coerce").dropna()
    if not len(dates):
        return today_utc()
    d = dates.max()
    return pd.Timestamp(d.year, d.month, d.day, tz="UTC")


def ytd_mask(df, year, asof):
    """Mask for Jan 1 of ``year`` through the same month/day as ``asof``.

    The heart of the rolling comparison: every year is measured over the
    identical number of elapsed days, so bars are apples-to-apples even while
    the current year is still in progress.
    """
    col = _date_column(df)
    if col is None:
        raise KeyError("DataFrame has no publish-date column")
    start = pd.Timestamp(f"{year}-01-01", tz="UTC")
    # End at the midnight AFTER the as-of day so the day itself is included.
    # Feb 29 as-of collapses to Mar 1 in non-leap years, which is correct.
    try:
        anchor = pd.Timestamp(f"{year}-{asof.month:02d}-{asof.day:02d}", tz="UTC")
    except ValueError:
        anchor = pd.Timestamp(f"{year}-02-28", tz="UTC")
    end = anchor + pd.Timedelta(days=1)
    dates = pd.to_datetime(df[col], utc=True, errors="coerce")
    return (dates >= start) & (dates < end)


def recent_mask(df, days, asof):
    """Mask for the trailing ``days`` window ending on ``asof`` (inclusive)."""
    col = _date_column(df)
    if col is None:
        raise KeyError("DataFrame has no publish-date column")
    end = asof + pd.Timedelta(days=1)
    start = end - pd.Timedelta(days=days)
    dates = pd.to_datetime(df[col], utc=True, errors="coerce")
    return (dates >= start) & (dates < end)


def elapsed_days(year, asof):
    """Number of days elapsed from Jan 1 of ``year`` through ``asof``."""
    start = pd.Timestamp(f"{year}-01-01", tz="UTC")
    try:
        anchor = pd.Timestamp(f"{year}-{asof.month:02d}-{asof.day:02d}", tz="UTC")
    except ValueError:
        anchor = pd.Timestamp(f"{year}-02-28", tz="UTC")
    return (anchor - start).days + 1

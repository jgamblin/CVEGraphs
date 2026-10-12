"""The rolling window: every year measured over the same elapsed days."""

import pandas as pd
import pytest

from cvegraphs import rolling


def _frame(dates):
    return pd.DataFrame({"published": pd.to_datetime(dates, utc=True)})


def test_post_date_override(monkeypatch):
    monkeypatch.setenv("CVEGRAPHS_POST_DATE", "2026-10-11")
    assert rolling.today_utc() == pd.Timestamp("2026-10-11", tz="UTC")


def test_data_asof_is_newest_publish_day_not_wall_clock():
    df = _frame(["2026-10-01T10:00", "2026-10-09T23:59"])
    assert rolling.data_asof(df) == pd.Timestamp("2026-10-09", tz="UTC")


def test_ytd_mask_uses_same_month_day_every_year():
    asof = pd.Timestamp("2026-10-09", tz="UTC")
    df = _frame(["2025-01-01T00:00", "2025-10-09T23:59", "2025-10-10T00:00", "2024-12-31T23:59"])
    assert rolling.ytd_mask(df, 2025, asof).tolist() == [True, True, False, False]


def test_leap_day_asof_collapses_to_feb_28():
    asof = pd.Timestamp("2028-02-29", tz="UTC")
    df = _frame(["2027-02-28T12:00", "2027-03-01T00:00"])
    assert rolling.ytd_mask(df, 2027, asof).tolist() == [True, False]
    assert rolling.elapsed_days(2027, asof) == 59


@pytest.mark.parametrize("asof,days", [("2026-01-01", 1), ("2026-12-31", 365), ("2028-12-31", 366)])
def test_elapsed_days(asof, days):
    assert rolling.elapsed_days(int(asof[:4]), pd.Timestamp(asof, tz="UTC")) == days


def test_recent_mask_is_inclusive_of_asof():
    asof = pd.Timestamp("2026-10-09", tz="UTC")
    df = _frame(["2026-10-02T23:59", "2026-10-03T00:00", "2026-10-09T23:59"])
    assert rolling.recent_mask(df, 7, asof).tolist() == [False, True, True]

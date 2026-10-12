"""Shared fixtures. Tests marked ``snapshot`` need the local processed/ data and
are skipped when it is absent (CI never has the 7 GB snapshot)."""

import os

import pytest

os.environ.setdefault("MPLBACKEND", "Agg")

from cvegraphs import paths  # noqa: E402

HAVE_SNAPSHOT = (paths.PROCESSED / "nvd_cves.parquet").exists()


def pytest_collection_modifyitems(config, items):
    if HAVE_SNAPSHOT:
        return
    skip = pytest.mark.skip(reason="no processed/ snapshot (run `cvegraphs refresh`)")
    for item in items:
        if "snapshot" in item.keywords:
            item.add_marker(skip)

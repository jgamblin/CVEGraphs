"""
Derived datasets built from the raw clones after the main parquet refresh.

Each module here exposes ``main()`` and writes one or more files into
``processed/``. They run as part of ``cvegraphs refresh`` in the order below,
or one at a time with ``cvegraphs precompute <name>``.

The list is explicit, not discovered, because order matters:

* ``after="parse"`` steps scan ``data/cvelistV5`` or ``data/nvd.json`` and only
  need the download + parse stage.
* ``after="feeds"`` steps need ``processed/kev_catalog.json`` from the feed
  fetch. The three EPSS steps share ``processed/epss_history_cache/`` and run in
  this order so each only downloads the snapshots the previous one did not.
"""

import importlib

# (module, run after, chart(s) that read it)
STEPS = [
    ("product_id", "parse", "product_id"),
    ("credits", "parse", "credit_rise"),
    ("cisco_rollup", "parse", "cisco_rollup"),
    ("score_pairs", "parse", "score_disagreement"),
    ("cwe787", "parse", "cwe787_alone"),
    ("patch_tag", "parse", "patch_tag"),
    ("epss_report_card", "feeds", "epss_report_card, epss_gain"),
    ("epss_early_warning", "feeds", "epss_early_warning*"),
    ("epss_kev_window", "feeds", "epss_kev_window*"),
    ("detection_rules", "feeds", "detection_coverage, detection_breadth"),
    ("ghsa_reviewed", "feeds", "ghsa_output"),
]

NAMES = [name for name, _, _ in STEPS]


def run(name):
    """Run one step. Returns True on success; a failure leaves the old output in place."""
    charts = next(c for n, _, c in STEPS if n == name)
    print(f"  Building {name} (for {charts}) ...")
    try:
        importlib.import_module(f"cvegraphs.precompute.{name}").main()
        return True
    except Exception as e:  # one broken source must not sink the whole refresh
        print(f"  [{name}] precompute failed: {e}; leaving existing output")
        return False


def run_stage(after):
    """Run every step that belongs after the given refresh stage; return names that failed."""
    return [name for name, stage, _ in STEPS if stage == after and not run(name)]

"""Short-lived CVEs: a one-page HTML report on CVEs that patch cycles close fast."""

from cvegraphs.papers.short_lived_cves.build_paper import render

DESCRIPTION = "HTML paper: short-lived CVEs, Windows/Chrome update defaults, and a lookalike backtest"

__all__ = ["DESCRIPTION", "render"]

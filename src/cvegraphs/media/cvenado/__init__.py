"""CVE tornado: CVEs per day as a three.js spiral (Ben Edwards' cvenado, restyled)."""

from cvegraphs.media.cvenado.build import render

DESCRIPTION = "3D spiral web page: CVEs published per day since 2000, one turn per year (record.py makes the MP4/GIF)"

__all__ = ["DESCRIPTION", "render"]

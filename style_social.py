#!/usr/bin/env python3
"""
Social-media chart styling for CVEGraphs.

A fork of H12026CVEBlog/style_config.py retuned for the feed rather than the
blog: square/portrait/wide canvases, big mobile-legible type, the takeaway as
the headline, and a handle + affiliation + date stamp on every image.

Design language: an editorial system aligned with Empirical Security's look
(Host Grotesk headlines, Roboto body, Roboto Mono for IDs and stamps, near-black
ink on white, a hairline grid, flat bars, generous whitespace) but on a distinct
deep-navy accent rather than Empirical's green, so the feed reads as its own
brand while sharing the house typographic language.
"""

import re
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib import font_manager as fm

from rolling_config import HANDLE, SITE, today_utc

# -----------------------------------------------------------------------------
# Fonts — bundled in the repo so rendering is self-contained. Registered with
# matplotlib's font manager at import; if a file is missing we fall back to the
# generic family names and matplotlib picks the nearest installed face.
# -----------------------------------------------------------------------------
FONT_DIR = Path(__file__).resolve().parent / "fonts"
HEAD_FONT = "Host Grotesk"  # headlines (single Light weight — editorial, thin)
BODY_FONT = "Roboto"        # subtitles, axis labels, body copy
MONO_FONT = "Roboto Mono"   # CVE ids, PURLs, the date stamp


def _register_fonts():
    for fn in ("HostGrotesk.ttf", "Roboto-Regular.ttf", "Roboto-Bold.ttf",
               "RobotoMono.ttf"):
        p = FONT_DIR / fn
        if p.exists():
            try:
                fm.fontManager.addfont(str(p))
            except Exception:
                pass


_register_fonts()

# -----------------------------------------------------------------------------
# Output aspect ratios (pixels). One render per ratio -> a full posting set.
# -----------------------------------------------------------------------------
RATIOS = {
    "square": (1080, 1080),    # LinkedIn / X / Mastodon / Bluesky / IG feed
    "portrait": (1080, 1350),  # Instagram + LinkedIn portrait (4:5)
    "wide": (1600, 900),       # X / Twitter landscape (16:9)
}
DEFAULT_RATIOS = ("square", "portrait", "wide")

SAVE_DPI = 150  # figsize is derived as pixels / SAVE_DPI

# -----------------------------------------------------------------------------
# Palette — a deep-navy accent ramp on Empirical's neutral ink/line/soft tokens.
# Distinct from Empirical's green so the feed keeps its own identity.
# -----------------------------------------------------------------------------
COLORS = {
    "primary":   "#1f3a5f",  # deep navy — primary accent, strongest emphasis
    "accent":    "#5a7a9c",  # mid navy — secondary emphasis
    "neutral":   "#8da0b5",  # muted navy-grey
    "light":     "#afc0d4",  # pale navy tint — non-highlighted fills
    "secondary": "#525559",  # muted ink — subtitles, footnotes, stamp
    "text":      "#181818",  # near-black ink — headlines, labels
    "grid":      "#dfe2e5",  # hairline grid / axis line
    "soft":      "#f6f7f9",  # near-white panel
    "alert":     "#dc2626",  # alert red — highlight / current year
}

# The uppercase eyebrow that sits above the headline.
EYEBROW = "CVE Insights"

SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH": "#ea580c",
    "MEDIUM": "#f59e0b",
    "LOW": "#64748b",
    "NONE": "#cbd5e1",
}


def figsize_for(ratio):
    """(width, height) in inches for a named ratio at SAVE_DPI."""
    w, h = RATIOS[ratio]
    return (w / SAVE_DPI, h / SAVE_DPI)


def apply_style():
    """Apply the social style globally. Body text is Roboto; headlines opt into
    Host Grotesk via ``draw_header`` / the ``HEAD_FONT`` family."""
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": [BODY_FONT, "Arial", "Helvetica", "DejaVu Sans",
                            "sans-serif"],
        "font.size": 15,
        "axes.titlesize": 24,
        "axes.titleweight": "bold",
        "axes.titlepad": 14,
        "axes.labelsize": 15,
        "axes.labelweight": "bold",
        "axes.labelpad": 8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.edgecolor": COLORS["grid"],
        "axes.linewidth": 1.0,
        "axes.facecolor": "white",
        "figure.facecolor": "white",
        "savefig.facecolor": "white",
        "text.color": COLORS["text"],
        "axes.labelcolor": COLORS["text"],
        "axes.grid": True,
        "axes.grid.axis": "y",
        "grid.color": COLORS["grid"],
        "grid.linewidth": 0.6,
        "grid.alpha": 0.8,
        "xtick.labelsize": 13,
        "ytick.labelsize": 13,
        "xtick.color": COLORS["text"],
        "ytick.color": COLORS["text"],
        "figure.dpi": 100,
        "savefig.dpi": SAVE_DPI,
        # Not 'tight': we want exact figure dimensions so aspect ratios are
        # honored and the reserved header/footer margins survive.
        "savefig.bbox": None,
    })


# Standard header geometry per ratio: (title_y, title_size). The eyebrow sits a
# little above the title; the subtitle a little below. Tuned so the block clears
# the plot area given each chart's own subplots_adjust(top=...).
_HEADER = {
    "wide":     {"eyebrow_y": 0.945, "title_y": 0.905, "sub_y": 0.830, "t1": 26},
    "square":   {"eyebrow_y": 0.955, "title_y": 0.915, "sub_y": 0.853, "t1": 22},
    "portrait": {"eyebrow_y": 0.960, "title_y": 0.925, "sub_y": 0.872, "t1": 22},
}


def draw_header(fig, title, subtitle, ratio="wide", eyebrow=EYEBROW,
                x=0.05, eyebrow_suffix=None, title_size=None):
    """Draw the house header: an uppercase mono eyebrow + a short accent rule,
    the Host Grotesk headline, then the Roboto subtitle. Charts reserve room for
    it with ``fig.subplots_adjust(top=...)`` (roughly 0.80-0.86). Pass
    ``title_size`` to override the default headline size for a long title."""
    g = _HEADER[ratio]
    label = eyebrow if not eyebrow_suffix else f"{eyebrow}  ·  {eyebrow_suffix}"
    fig.text(x, g["eyebrow_y"], label.upper(), fontfamily=MONO_FONT,
             fontsize=10.5, fontweight="bold", color=COLORS["primary"],
             ha="left", va="center")
    # short accent rule under the eyebrow
    fig.add_artist(plt.Line2D([x, x + 0.075], [g["eyebrow_y"] - 0.028] * 2,
                              color=COLORS["primary"], lw=2.4,
                              transform=fig.transFigure))
    fig.text(x, g["title_y"], title, fontfamily=HEAD_FONT,
             fontsize=title_size or g["t1"],
             color=COLORS["text"], ha="left", va="top")
    fig.text(x, g["sub_y"], subtitle, fontfamily=BODY_FONT, fontsize=11,
             fontweight="bold", color=COLORS["secondary"], ha="left", va="top")


def _format_thousands(x, pos):
    if x >= 1000:
        v = x / 1000
        return f"{v:.0f}K" if abs(v - round(v)) < 1e-9 else f"{v:.1f}K"
    return f"{int(x)}"


def thousands_formatter():
    return ticker.FuncFormatter(_format_thousands)


def stamp_and_save(fig, filepath, asof_str=None):
    """Stamp handle / site / affiliation / POST date and write the file, close.

    House rule: the stamp is always the day the chart is rendered (posted), never
    the data-source date, so a chart never looks staler or fresher than the day it
    goes out. Data provenance belongs in the footnote / Source line. The date in the
    output filename is rewritten to match. ``asof_str`` is ignored (kept for
    backward compatibility with callers that still pass a date).
    """
    today = today_utc()
    stamp = today.strftime("%b %d, %Y")
    # Keep the saved filename's date in sync with the stamp.
    p = Path(filepath)
    p = p.with_name(re.sub(r"\d{4}-\d{2}-\d{2}(?=\.[^.]+$)", today.strftime("%Y-%m-%d"), p.name))
    filepath = p

    fig.text(
        0.99, 0.012, f"{HANDLE}  ·  {SITE}  ·  {stamp}",
        transform=fig.transFigure,
        fontfamily=MONO_FONT, fontsize=8.5, color=COLORS["secondary"],
        alpha=0.85, ha="right", va="bottom",
    )
    # Exact dimensions (no 'tight' crop) so the aspect ratio is honored and the
    # reserved header/footer margins survive.
    fig.savefig(filepath, dpi=SAVE_DPI, bbox_inches=None,
                facecolor="white", edgecolor="none")
    plt.close(fig)
    return filepath  # the actual (post-dated) path, so callers report the real file


apply_style()

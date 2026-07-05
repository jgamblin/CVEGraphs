#!/usr/bin/env python3
"""
Social-media chart styling for CVEGraphs.

A fork of H12026CVEBlog/style_config.py retuned for the feed rather than the
blog: square/portrait/wide canvases, big mobile-legible type, the takeaway as
the headline, and a handle + date + site stamp on every image.

Design language is kept identical to the blog (deep navy, alert red) so the two
bodies of work read as one brand.
"""

import matplotlib.pyplot as plt
import matplotlib.ticker as ticker

from rolling_config import HANDLE, SITE

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
# Palette — identical to the blog for brand continuity.
# -----------------------------------------------------------------------------
COLORS = {
    "primary": "#1e3a5f",    # deep navy
    "secondary": "#64748b",  # slate
    "accent": "#3d6a99",     # medium blue
    "alert": "#dc2626",      # alert red (current year / highlight)
    "neutral": "#94a3b8",
    "light": "#cbd5e1",
    "text": "#1e293b",
    "grid": "#e2e8f0",
}

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
    """Apply the social style globally. Fonts are sized up for mobile feeds."""
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.sans-serif": ["Arial", "Helvetica", "DejaVu Sans", "sans-serif"],
        "font.size": 15,
        "axes.titlesize": 24,
        "axes.titleweight": "bold",
        "axes.titlepad": 14,
        "axes.labelsize": 15,
        "axes.labelweight": "bold",
        "axes.labelpad": 8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.edgecolor": COLORS["secondary"],
        "axes.linewidth": 1.0,
        "axes.facecolor": "white",
        "figure.facecolor": "white",
        "savefig.facecolor": "white",
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


def _format_thousands(x, pos):
    if x >= 1000:
        v = x / 1000
        return f"{v:.0f}K" if abs(v - round(v)) < 1e-9 else f"{v:.1f}K"
    return f"{int(x)}"


def thousands_formatter():
    return ticker.FuncFormatter(_format_thousands)


def stamp_and_save(fig, filepath, asof_str):
    """Stamp handle / site / as-of date and write the file, then close."""
    fig.text(
        0.99, 0.01, f"{HANDLE}  ·  {SITE}  ·  {asof_str}",
        transform=fig.transFigure,
        fontsize=12, color=COLORS["secondary"],
        alpha=0.75, ha="right", va="bottom",
        fontweight="bold", fontstyle="italic",
    )
    # Exact dimensions (no 'tight' crop) so the aspect ratio is honored and the
    # reserved header/footer margins survive.
    fig.savefig(filepath, dpi=SAVE_DPI, bbox_inches=None,
                facecolor="white", edgecolor="none")
    plt.close(fig)


apply_style()

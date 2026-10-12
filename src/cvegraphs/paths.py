"""
Every filesystem location CVEGraphs reads or writes, defined once.

Inputs live at the repo root (``data/`` raw clones, ``processed/`` parquet).
Everything the project produces lands under ``content/``:

    content/drafts/<chart>/   renders + post.md for anything not yet posted
    content/posts/<date>-<chart>/   frozen once it goes out
    content/insights/         the mined insight brief
    content/planning/         BACKLOG, CALENDAR, INSIGHTS

The repo root defaults to the checkout this package was installed from
(``pip install -e .``); set ``CVEGRAPHS_ROOT`` to point somewhere else.
"""

import contextlib
import contextvars
import os
from pathlib import Path

ROOT = Path(os.environ.get("CVEGRAPHS_ROOT") or Path(__file__).resolve().parents[2])

DATA = ROOT / "data"
PROCESSED = ROOT / "processed"
LOGS = ROOT / "logs"

CONTENT = ROOT / "content"
DRAFTS = CONTENT / "drafts"
POSTS = CONTENT / "posts"
INSIGHTS = CONTENT / "insights"
PLANNING = CONTENT / "planning"

PACKAGE = Path(__file__).resolve().parent
FONTS = PACKAGE / "fonts"

# The directory the chart currently being rendered writes into. The registry
# sets it per chart (content/drafts/<chart>/); outside a render it falls back to
# content/drafts/_adhoc/ so a direct `module.render()` call never litters the root.
_output_dir = contextvars.ContextVar("cvegraphs_output_dir", default=DRAFTS / "_adhoc")


def output_dir():
    """Directory the current render writes into (created on demand)."""
    d = _output_dir.get()
    d.mkdir(parents=True, exist_ok=True)
    return d


@contextlib.contextmanager
def render_target(name, root=None):
    """Send every file written inside the block to ``<root>/<name>/``.

    ``root`` defaults to content/drafts. Tests pass a scratch directory so a
    check render can never overwrite a real draft.
    """
    token = _output_dir.set(Path(root or DRAFTS) / name)
    try:
        yield output_dir()
    finally:
        _output_dir.reset(token)


class _Output:
    """Path-like stand-in for "the current render's output directory".

    Charts build filenames as ``OUTPUT / f"pace_{ratio}_{date}.png"``. The
    directory is looked up at that moment, not at import time, so one module can
    be rendered into whichever draft folder the caller chose.
    """

    def __truediv__(self, name):
        return output_dir() / name

    def __fspath__(self):
        return os.fspath(output_dir())

    def __repr__(self):
        return f"<render output: {_output_dir.get()}>"


OUTPUT = _Output()

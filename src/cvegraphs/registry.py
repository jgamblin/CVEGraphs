"""
Everything ``cvegraphs render`` can produce, discovered rather than listed.

A renderable is any module that defines ``DESCRIPTION`` (one line, shown by
``cvegraphs list``) and ``render(nvd=None)`` returning the paths it wrote:

    cvegraphs/charts/<name>.py          one module per chart
    cvegraphs/media/<name>/__init__.py  non-chart media (the CVE tornado)
    cvegraphs/papers/<name>/__init__.py long-form HTML reports

Drop a new file in one of those places and it is registered; there is no list
to keep in sync. The name is the module (or subpackage) name, and it is also the
draft folder the output lands in: content/drafts/<name>/.
"""

import importlib
import pkgutil
import re
from pathlib import Path

from cvegraphs import paths

# (package, whether each renderable is a subpackage rather than a module)
SOURCES = [
    ("cvegraphs.charts", False),
    ("cvegraphs.media", True),
    ("cvegraphs.papers", True),
]


def _discover():
    found = {}
    for pkg_name, want_pkg in SOURCES:
        pkg = importlib.import_module(pkg_name)
        for info in pkgutil.iter_modules(pkg.__path__):
            if info.ispkg != want_pkg or info.name.startswith("_"):
                continue
            mod = importlib.import_module(f"{pkg_name}.{info.name}")
            if hasattr(mod, "DESCRIPTION") and callable(getattr(mod, "render", None)):
                if info.name in found:
                    raise RuntimeError(f"duplicate renderable name: {info.name}")
                found[info.name] = mod
    return dict(sorted(found.items()))


_CACHE = None


def all_renderables():
    """name -> module, alphabetical."""
    global _CACHE
    if _CACHE is None:
        _CACHE = _discover()
    return _CACHE


_DATED = re.compile(r"^(?P<stem>.+)_(?P<date>\d{4}-\d{2}-\d{2})(?P<ext>\.\w+)$")


def _set_aside_superseded(folder, written):
    """Move older-dated renders of the files just written into folder/superseded/.

    ``pace_wide_2026-10-11.png`` supersedes ``pace_wide_2026-10-04.png``. Nothing is
    deleted; the draft folder just keeps showing only the current render.
    """
    for new in written:
        m = _DATED.match(new.name)
        if not m:
            continue
        for old in folder.glob(f"{m['stem']}_*{m['ext']}"):
            o = _DATED.match(old.name)
            if old != new and o and o["stem"] == m["stem"] and o["date"] < m["date"]:
                (folder / "superseded").mkdir(exist_ok=True)
                old.rename(folder / "superseded" / old.name)


def render(name, nvd=None, root=None):
    """Render one item into ``<root or content/drafts>/<name>/``; return written paths."""
    mod = all_renderables()[name]
    with paths.render_target(name, root=root) as folder:
        written = [Path(p) for p in mod.render(nvd=nvd)]
    _set_aside_superseded(folder, written)
    return written

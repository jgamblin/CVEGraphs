#!/usr/bin/env python3
"""
Golden-render check for the repo reorg.

Renders everything in the registry independently (one failure does not stop
the rest), with the post date pinned, into a scratch directory, then compares
output hashes (PNG and HTML) against the baseline in logs/golden/. Run it after
any refactor: a behavior-preserving change reproduces the baseline byte for byte.

    python tests/golden_render.py            # render + compare
    python tests/golden_render.py --update   # render + overwrite the baseline

The baseline only holds for the processed/ snapshot it was taken on, so this
refuses to compare if the processed/*.parquet fingerprint has changed. After a
`cvegraphs refresh`, re-baseline before refactoring, not after.
"""

import hashlib
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "logs" / "golden"
POST_DATE = "2026-10-11"


def _sha(path):
    return hashlib.sha1(path.read_bytes()).hexdigest()


def _fingerprint(path):
    """Hash what a viewer sees. PNGs are hashed by decoded pixels, not file bytes:
    two zlib builds (system matplotlib vs a pip wheel) encode identical pixels
    into different files."""
    if path.suffix != ".png":
        return _sha(path)
    from PIL import Image

    with Image.open(path) as im:
        h = hashlib.sha1(f"{im.mode}{im.size}".encode())
        h.update(im.tobytes())
        return h.hexdigest()


def _processed_fingerprint():
    return {p.name: _sha(p) for p in sorted((ROOT / "processed").glob("*.parquet"))}


def _render_all(out_dir):
    os.environ["CVEGRAPHS_POST_DATE"] = POST_DATE
    os.environ.setdefault("MPLBACKEND", "Agg")
    from cvegraphs import registry
    from cvegraphs.data import load_nvd

    nvd = load_nvd()
    result = {}
    for name in registry.all_renderables():
        try:
            # Each item renders into <scratch>/<name>/, never into content/drafts.
            paths = [Path(p) for p in registry.render(name, nvd=nvd, root=out_dir)]
            result[name] = {"ok": True, "paths": sorted(p.name for p in paths)}
        except Exception as e:
            result[name] = {"ok": False, "error": f"{type(e).__name__}: {str(e).splitlines()[0]}"}
    return result


def main(argv):
    update = "--update" in argv
    fp = _processed_fingerprint()
    fp_file = GOLDEN / "processed.json"
    if not update and fp_file.exists() and json.loads(fp_file.read_text()) != fp:
        print("processed/ changed since the baseline was taken; comparison is meaningless.")
        return 2

    out = Path(tempfile.mkdtemp(prefix="cvegraphs-golden-"))
    charts = _render_all(out)
    hashes = {p.name: _fingerprint(p) for p in sorted(out.rglob("*")) if p.suffix in (".png", ".html")}
    failed = {k: v["error"] for k, v in charts.items() if not v["ok"]}
    print(f"{len(charts)} items, {len(charts) - len(failed)} rendered, {len(hashes)} files")
    for k, v in failed.items():
        print(f"  FAIL {k}: {v}")

    if update:
        GOLDEN.mkdir(parents=True, exist_ok=True)
        fp_file.write_text(json.dumps(fp, indent=1))
        (GOLDEN / "png.json").write_text(json.dumps(hashes, indent=1))
        (GOLDEN / "charts.json").write_text(json.dumps(charts, indent=1))
        shutil.rmtree(GOLDEN / "png", ignore_errors=True)
        shutil.copytree(out, GOLDEN / "png")  # per-item folders, for eyeballing a diff
        print(f"baseline written to {GOLDEN}")
        return 0

    base = json.loads((GOLDEN / "png.json").read_text())
    base_charts = json.loads((GOLDEN / "charts.json").read_text())
    problems = []
    for name in sorted(set(base) | set(hashes)):
        if name not in hashes:
            problems.append(f"  missing  {name}")
        elif name not in base:
            problems.append(f"  new      {name}")
        elif base[name] != hashes[name]:
            problems.append(f"  CHANGED  {name}")
    for name in sorted(set(base_charts) ^ set(charts)):
        problems.append(f"  registry {name} {'removed' if name in base_charts else 'added'}")
    if problems:
        print(f"{len(problems)} difference(s) vs baseline (renders kept in {out}):")
        print("\n".join(problems))
        return 1
    shutil.rmtree(out)
    print("MATCH: every output identical to baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

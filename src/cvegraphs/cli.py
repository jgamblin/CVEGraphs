#!/usr/bin/env python3
"""
CVEGraphs command line.

    cvegraphs list                     # everything that can be rendered
    cvegraphs render pace              # one chart, every aspect ratio -> content/drafts/pace/
    cvegraphs render pace kev          # several
    cvegraphs render all               # the whole shelf (keeps going past failures)
    cvegraphs publish kev_weekend      # drafts/kev_weekend -> posts/<today>-kev_weekend, frozen
    cvegraphs refresh [--feeds-only]   # rebuild processed/ from upstream feeds
    cvegraphs precompute [name ...]    # rerun derived datasets (all if none named)
    cvegraphs insights [--top 15]      # mine the ranked insight brief

``cvegraphs pace`` (no verb) still renders, for muscle memory from make.py.
Set CVEGRAPHS_POST_DATE=YYYY-MM-DD to stamp a chart with the day you will post it.
"""

import argparse
import datetime as dt
import shutil
import subprocess
import sys

from cvegraphs import paths, registry


def _warn_if_stale(nvd, max_age=2):
    """Charts stamp today's date, so guard against a fresh stamp on stale data."""
    from cvegraphs.rolling import data_asof, today_utc

    age = (today_utc() - data_asof(nvd)).days
    if age > max_age:
        bar = "!" * 70
        print(f"\n{bar}")
        print(f"  WARNING: data is {age} days old (latest CVE {data_asof(nvd).date()}).")
        print("  Charts stamp TODAY's date, so this puts a fresh stamp on stale data.")
        print("  Run  cvegraphs refresh  before rendering to post.")
        print(f"{bar}\n")


def cmd_list(_args):
    items = registry.all_renderables()
    width = max(map(len, items))
    for name, mod in items.items():
        print(f"  {name:{width}s}  {mod.DESCRIPTION}")
    return 0


def cmd_render(args):
    items = registry.all_renderables()
    names = list(items) if args.names == ["all"] else args.names
    unknown = [n for n in names if n not in items]
    if unknown:
        print(f"Unknown: {', '.join(unknown)}. Run `cvegraphs list` to see what exists.")
        return 1

    from cvegraphs.data import load_nvd

    # Load once and share across every chart in this run.
    try:
        nvd = load_nvd()
    except FileNotFoundError as e:
        print(e)
        return 1
    _warn_if_stale(nvd)

    failed = {}
    for name in names:
        print(f"Rendering {name} ...")
        try:
            for path in registry.render(name, nvd=nvd):
                print(f"  wrote {path}")
        except Exception as e:  # one broken chart must not stop the shelf
            failed[name] = f"{type(e).__name__}: {str(e).splitlines()[0] if str(e) else ''}"
            print(f"  FAILED {failed[name]}")
    if failed:
        print(f"\n{len(failed)} of {len(names)} failed:")
        for name, err in failed.items():
            print(f"  {name}: {err}")
        return 1
    return 0


def _git_commit():
    try:
        sha = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=paths.ROOT,
                             capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--", "src"], cwd=paths.ROOT,
                               capture_output=True, text=True).stdout.strip()
        return f"{sha}-dirty" if dirty else sha
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def cmd_publish(args):
    from cvegraphs.rolling import data_asof, today_utc

    src = paths.DRAFTS / args.name
    if not src.is_dir():
        print(f"No draft at {src}. Render it first: cvegraphs render {args.name}")
        return 1
    posted = args.date or today_utc().strftime("%Y-%m-%d")
    dt.date.fromisoformat(posted)  # validate
    dest = paths.POSTS / f"{posted}-{args.name}"
    if dest.exists():
        print(f"{dest} already exists; pass --date or remove it first.")
        return 1

    from cvegraphs.data import load_cvelist

    asof = data_asof(load_cvelist()).strftime("%Y-%m-%d")
    front = "\n".join([
        "---",
        f"chart: {args.name}",
        f"posted: {posted}",
        f"data_as_of: {asof}",
        f"commit: {_git_commit()}",
        f"platforms: {args.platforms}",
        f"link: {args.link or ''}",
        "---",
        "",
    ])
    post = src / "post.md"
    body = post.read_text() if post.exists() else f"# {args.name}\n\n(post text not saved)\n"
    if body.startswith("---\n"):
        print(f"{post} already has front matter; leaving it as-is.")
    else:
        post.write_text(front + body)

    paths.POSTS.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), dest)
    print(f"Published {args.name} -> {dest.relative_to(paths.ROOT)}")
    print("Log it in content/planning/CALENDAR.md once it is live.")
    return 0


def cmd_refresh(args):
    from cvegraphs.data.refresh import main

    return main(args.rest)


def cmd_precompute(args):
    from cvegraphs import precompute

    names = args.names or precompute.NAMES
    unknown = [n for n in names if n not in precompute.NAMES]
    if unknown:
        print(f"Unknown: {', '.join(unknown)}. Steps: {', '.join(precompute.NAMES)}")
        return 1
    failed = [n for n in names if not precompute.run(n)]
    return 1 if failed else 0


def cmd_insights(args):
    from cvegraphs.insights import main

    return main(args.rest) or 0


def build_parser():
    ap = argparse.ArgumentParser(prog="cvegraphs", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list renderable charts and media").set_defaults(func=cmd_list)

    p = sub.add_parser("render", help="render charts into content/drafts/<name>/")
    p.add_argument("names", nargs="+", metavar="name", help="chart name(s), or 'all'")
    p.set_defaults(func=cmd_render)

    p = sub.add_parser("publish", help="freeze a draft into content/posts/<date>-<name>/")
    p.add_argument("name")
    p.add_argument("--date", help="posting date YYYY-MM-DD (default: today / CVEGRAPHS_POST_DATE)")
    p.add_argument("--platforms", default="LI", help="where it went, e.g. 'LI, X' (default LI)")
    p.add_argument("--link", help="URL of the live post")
    p.set_defaults(func=cmd_publish)

    for name, func, help_ in [
        ("refresh", cmd_refresh, "rebuild processed/ from upstream feeds (flags pass through)"),
        ("insights", cmd_insights, "mine the ranked insight brief (flags pass through)"),
    ]:
        p = sub.add_parser(name, help=help_, add_help=False)
        p.add_argument("rest", nargs=argparse.REMAINDER)
        p.set_defaults(func=func)

    p = sub.add_parser("precompute", help="rerun derived datasets in processed/")
    p.add_argument("names", nargs="*", metavar="name")
    p.set_defaults(func=cmd_precompute)
    return ap


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    # `cvegraphs pace` / `cvegraphs all`: the old make.py form.
    if argv and argv[0] not in {"list", "render", "publish", "refresh", "precompute",
                                "insights", "-h", "--help"}:
        argv = ["render", *argv]
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
Detection Breadth — how many CVE IDs each open ruleset actually names.

The companion to ``detection_coverage``. That chart asks how much of KEV the
open defensive rulesets name; this one asks how much of the CVE corpus they
name at all, and puts the answer next to the offense-side equivalent.

Nuclei is an exploitation/scanning template library, not a detection ruleset.
That is the point: it answers "do we care about CVE-X" from the attacker's
side, it is indexed by CVE ID by design, and it names roughly twice as many
CVE IDs as Emerging Threats Open, SigmaHQ and Elastic combined. The asymmetry
is about INDEXING, not about who is better at their job, and the chart label
plus footnote say so.

Sigma's number is the one that needs care: 3,797 active rules naming 180 CVE
IDs is not a coverage failure, it is SigmaHQ's stated design (behavior over
signature). Cite it as evidence that host detection is not CVE-indexed, never
as evidence that Sigma is thin.

Data: processed/detection_rules.parquet + _meta.json from
scripts_precompute_detection_rules.py.

Renders one PNG per aspect ratio into ``graphs/``.
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

from style_social import (
    COLORS,
    DEFAULT_RATIOS,
    draw_header,
    figsize_for,
    stamp_and_save,
    thousands_formatter,
)

ROOT = Path(__file__).resolve().parent.parent
PROCESSED = ROOT / "processed"
GRAPHS = ROOT / "graphs"


def _load():
    df = pd.read_parquet(PROCESSED / "detection_rules.parquet")
    meta = json.loads((PROCESSED / "detection_rules_meta.json").read_text())
    return df, meta


def _rows(df, meta):
    """Bottom-to-top for a barh axis: components, union, then the offense bar."""
    return [
        # (label, distinct CVE ids, rule/template count, color, is_offense)
        ("Elastic Detection Rules", int(df["elastic"].sum()),
         meta["elastic_rules"], COLORS["light"], False),
        ("SigmaHQ", int(df["sigma"].sum()),
         meta["sigma_rules_active"], COLORS["light"], False),
        ("Emerging Threats Open", int(df["et_open"].sum()),
         meta["et_rules_parsed"] - meta["et_rules_disabled"], COLORS["accent"], False),
        ("All Three, De-Duplicated", int(df["defensive"].sum()), None,
         COLORS["primary"], False),
        ("Nuclei (Offense-Side)", int(df["nuclei"].sum()),
         meta["nuclei_templates"], COLORS["alert"], True),
    ]


def render(nvd=None, ratios=DEFAULT_RATIOS):
    """Render the breadth comparison. Returns list of output paths.

    ``nvd`` is accepted for the shared make.py dispatch signature and ignored.
    """
    df, meta = _load()
    rows = _rows(df, meta)
    labels = [r[0] for r in rows]
    vals = [r[1] for r in rows]
    counts = [r[2] for r in rows]
    colors = [r[3] for r in rows]

    defensive = int(df["defensive"].sum())
    offense = int(df["nuclei"].sum())
    ratio_x = offense / defensive
    # The union bar is SMALLER than the three component bars added up, because
    # rulesets overlap. Unexplained, a numerate reader concludes the chart is
    # broken, which taints the comparison the image exists to make.
    overlap = int((df[["et_open", "sigma", "elastic"]].sum(axis=1) >= 2).sum())
    parts_sum = int(df[["et_open", "sigma", "elastic"]].sum().sum())

    title = "Distinct CVE IDs Named by Each Open Ruleset"

    out = []
    for r in ratios:
        fig, ax = plt.subplots(figsize=figsize_for(r))
        y = range(len(rows))
        # A gap under the top bar separates the offense-side foil from the
        # defensive stack, so the two groups do not read as one ranking.
        ypos = [0, 1, 2, 3, 4.55]
        ax.barh(ypos, vals, color=colors, height=0.68, zorder=3)
        ax.set_axisbelow(True)

        lab = {"wide": 13, "square": 11, "portrait": 11.5}[r]
        for yy, v, c in zip(ypos, vals, counts):
            txt = f"{v:,}" + (f"   from {c:,} rules" if c else "")
            ax.text(v + max(vals) * 0.015, yy, txt, va="center", ha="left",
                    fontsize=lab, fontweight="bold", color=COLORS["text"],
                    zorder=4)

        ax.set_yticks(ypos)
        ax.set_yticklabels(labels, fontsize=lab)
        for tick, (_, _, _, col, is_off) in zip(ax.get_yticklabels(), rows):
            if is_off:
                tick.set_color(COLORS["alert"])
                tick.set_fontweight("bold")
        # Headroom for the "N   from M rules" label, which is widest on the
        # top bar; the narrow ratios have far less axes width to spend.
        ax.set_xlim(0, max(vals) * {"wide": 1.38, "square": 1.62, "portrait": 1.58}[r])
        ax.xaxis.set_major_formatter(thousands_formatter())
        ax.tick_params(axis="x", labelsize=11)
        ax.grid(axis="x", zorder=0)
        ax.grid(axis="y", visible=False)
        ax.spines["left"].set_visible(False)
        ax.tick_params(axis="y", length=0)

        sub = (f"Emerging Threats Open, SigmaHQ and Elastic together name "
               f"{defensive:,} CVE IDs\n"
               f"Nuclei's exploitation templates name {offense:,}, "
               f"{ratio_x:.1f}x as many")

        top = {"wide": 0.74, "square": 0.77, "portrait": 0.79}[r]
        bottom = {"wide": 0.30, "square": 0.26, "portrait": 0.22}[r]
        left = {"wide": 0.26, "square": 0.28, "portrait": 0.26}[r]
        fig.subplots_adjust(top=top, bottom=bottom, left=left, right=0.97)
        t1 = {"wide": 25, "square": 19, "portrait": 19}[r]
        draw_header(fig, title, sub, r, eyebrow_suffix="Exploitation",
                    title_size=t1)

        foot_size = {"wide": 9, "square": 8, "portrait": 8}[r]
        fig.text(
            0.05, 0.035,
            "Counts distinct CVE IDs cited by a rule file, across all years, not "
            "coverage or quality. SigmaHQ targets\nattacker behavior rather than "
            "specific CVEs by design, so its total is a fact about how host detection "
            "is indexed.\n"
            f"The combined bar counts distinct IDs: {overlap:,} are named by more "
            f"than one ruleset, so it is smaller than the {parts_sum:,}\nthe three "
            f"bars add up to.\n"
            f"Source: rulesets retrieved {meta['fetched']}; Emerging Threats Open "
            f"excludes the {meta['et_rules_disabled']:,} rules it ships disabled.",
            fontsize=foot_size, color=COLORS["secondary"], ha="left", va="bottom",
            linespacing=1.5,
        )

        path = GRAPHS / f"detection_breadth_{r}_2026-01-01.png"
        out.append(stamp_and_save(fig, path))
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

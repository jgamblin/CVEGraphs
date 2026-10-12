#!/usr/bin/env python3
"""
The EU KEV entries that differ from CISA KEV, and the public evidence behind each.

Companion to `eu_kev_overlay`. ENISA's EUVD exploited list holds every CISA KEV CVE,
so what is left to judge is small: CVEs only the EU lists, and CVEs the EU listed
before CISA did. EUVD records carry no source or evidence field for
``exploitedSince``, so each EU-only entry was graded by hand (2026-09-23) against its
EUVD references and linked advisories, its CVE record, and the pages those cite:

    Supported     a named vendor or researcher reports exploitation or live implant use
    Partial       exploitation reported for a chain, this CVE not named as part of it
    None found    nothing in the record or its references claims exploitation
    Contradicted  the evidence that exists says not exploited, or the date is impossible

The EU-first group is computed live: for each, the CVE record's CISA-ADP SSVC
``Exploitation`` value is read from cvelistV5. Full audit notes:
content/captions/eu_kev_overlay.md.

GRADES is hand research. ``render()`` refuses to draw if the live EU-only set no
longer matches it, so a refresh that adds or clears an entry cannot ship stale grades.
"""

import json

import matplotlib.pyplot as plt

from cvegraphs.charts.eu_kev_overlay import _load
from cvegraphs.paths import DATA, OUTPUT
from cvegraphs.style import COLORS, DEFAULT_RATIOS, MONO_FONT, draw_header, figsize_for, stamp_and_save

DESCRIPTION = "Table: EU KEV entries that differ from CISA KEV, graded by evidence"

GRAPHS = OUTPUT
CVELIST = DATA / "cvelistV5" / "cves"

GRADE_ORDER = ["Supported", "Partial", "None found", "Contradicted"]
GRADE_COLORS = {
    "Supported": COLORS["primary"],
    "Partial": COLORS["accent"],
    "None found": COLORS["light"],
    "Contradicted": COLORS["alert"],
}

# (cve, product, grade, evidence). Checked 2026-09-23; see module docstring.
GRADES = [
    ("CVE-2025-59719", "Fortinet FortiWeb", "Supported",
     "Fortinet advisory: \"Known Exploited: Yes\", shared with KEV's CVE-2025-59718"),
    ("CVE-2026-74232", "Zbtlink routers", "Supported",
     "VulnCheck: 392 devices beaconing to the backdoor's C2; no attacks documented"),
    ("CVE-2026-74233", "Zbtlink routers", "Supported",
     "Same VulnCheck research as CVE-2026-74232"),
    ("CVE-2026-67276", "MikroTik RouterOS", "Partial",
     "CERT-PL: a two-CVE chain is exploited; CISA added the other two"),
    ("CVE-2011-4085", "Red Hat JBoss", "None found",
     "References are 2011 to 2012 Red Hat errata; added in a Jul 14 2025 batch"),
    ("CVE-2015-7501", "Red Hat JBoss", "None found",
     "References are 2015 to 2020 errata and Oracle patch notes; same batch"),
    ("CVE-2025-25231", "Omnissa Workspace ONE", "None found",
     "Vendor PDF unreachable; German and Dutch CERT advisories make no claim"),
    ("CVE-2026-41679", "Paperclip", "None found",
     "GitHub advisory: researcher proof of concept only; CISA-ADP rates it \"poc\""),
    ("CVE-2026-49049", "JoomShaper Helix3", "None found",
     "Only reference is the vendor's homepage"),
    ("CVE-2026-58400", "GeoNetwork", "Contradicted",
     "EU date is a day before the CVE was published; press says no exploitation"),
    ("CVE-2026-63219", "GeoNetwork", "Contradicted",
     "Same as CVE-2026-58400"),
    ("CVE-2026-69836", "Microsoft Entra", "Contradicted",
     "Microsoft advisory: \"Exploited: No\"; CISA-ADP rates it \"none\""),
]


def _ssvc_exploitation(cve):
    """CISA-ADP SSVC Exploitation value from the local CVE record, or None."""
    _, year, num = cve.split("-")
    p = CVELIST / year / f"{num[:-3]}xxx" / f"{cve}.json"
    if not p.exists():
        return None
    rec = json.load(open(p))
    for adp in rec["containers"].get("adp", []):
        for m in adp.get("metrics", []):
            o = m.get("other", {})
            if o.get("type") == "ssvc":
                for opt in o["content"].get("options", []):
                    if "Exploitation" in opt:
                        return opt["Exploitation"]
    return None


def evidence():
    """EU-only rows (graded) + the EU-first set with its CISA-ADP SSVC values."""
    eu, cisa = _load()
    eu_only = set(eu["cve_id"]) - set(cisa["cve_id"])
    graded = {g[0] for g in GRADES}
    if eu_only != graded:
        raise RuntimeError(
            "EU-only set changed since GRADES was researched; re-grade before rendering.\n"
            f"  new: {sorted(eu_only - graded)}\n  gone: {sorted(graded - eu_only)}")

    m = eu.merge(cisa, on="cve_id", suffixes=("_eu", "_cisa"))
    first = m[m["date_eu"] < m["date_cisa"]].copy()
    first["ssvc"] = first["cve_id"].map(_ssvc_exploitation)
    first["lead"] = (first["date_cisa"] - first["date_eu"]).dt.days
    rows = sorted(GRADES, key=lambda g: (GRADE_ORDER.index(g[2]), g[0]))
    return rows, first, len(set(eu["cve_id"])), len(set(cisa["cve_id"]))


def render(nvd=None, ratios=DEFAULT_RATIOS):
    rows, first, n_eu, n_cisa = evidence()
    n_active = int((first["ssvc"] == "active").sum())
    stamp_date = max(_load()[0]["date"].max(), _load()[1]["date"].max())

    title = "EU KEV Entries That Differ From CISA KEV"
    subtitle = (f"The {len(rows) + len(first)} CVEs on ENISA's EUVD exploited list that "
                f"CISA KEV lacks or added later.")

    out = []
    for ratio in ratios:
        fig = plt.figure(figsize=figsize_for(ratio))
        g = {
            #          top    bottom  x_cve  x_prod x_ev   id  prod  ev   head  wrap
            "wide":     (0.765, 0.115, 0.075, 0.215, 0.375, 10.5, 10.5, 10,  11.5, None),
            "square":   (0.800, 0.105, 0.080, 0.300, None,  10,   10,   9,   11,   0.300),
            "portrait": (0.830, 0.100, 0.080, 0.300, None,  10.5, 10.5, 9.5, 11.5, 0.300),
        }[ratio]
        top, bottom, x_cve, x_prod, x_ev, fs_id, fs_prod, fs_ev, fs_head, x_ev2 = g
        two_line = x_ev is None  # narrow ratios put the evidence under the product

        # Row plan: a header per group, then its rows. Units: header=1.25, row=1 (or
        # 1.6 when the evidence wraps under the product).
        row_u = 1.6 if two_line else 1.0
        plan = [("head", f"Listed by the EU first  ·  {len(first)}", COLORS["neutral"]),
                ("note", first, None)]
        for grade in GRADE_ORDER:
            grp = [r for r in rows if r[2] == grade]
            if grp:
                plan.append(("head", f"On the EU list only: {grade}  ·  {len(grp)}",
                             GRADE_COLORS[grade]))
                plan += [("row", r, GRADE_COLORS[grade]) for r in grp]
        note_u = 2.1 if two_line else 1.0  # two text lines when narrow, one when wide
        units = sum(1.25 if k == "head" else (note_u if k == "note" else row_u)
                    for k, *_ in plan)
        step = (top - bottom) / units

        y = top
        for kind, payload, color in plan:
            if kind == "head":
                y -= step * 0.55
                fig.add_artist(plt.Rectangle((0.05, y - 0.009), 0.012, 0.018,
                                             transform=fig.transFigure, color=color,
                                             lw=0))
                fig.text(x_cve, y, payload, fontsize=fs_head, fontweight="bold",
                         color=COLORS["text"], ha="left", va="center")
                y -= step * 0.70
            elif kind == "note":
                h = step * note_u
                lead = payload["lead"]
                who = (f"All {n_active}" if n_active == len(payload)
                       else f"{n_active} of {len(payload)}")
                txt = (f"{who} already carried CISA-ADP's \"Exploitation: active\" "
                       f"rating in the CVE record."
                       + ("\n" if two_line else " ")
                       + f"CISA added them to KEV {lead.min()} to {lead.max()} days "
                       f"after the EU listed them.")
                fig.text(x_cve, y - h * 0.5, txt, fontsize=fs_ev + 0.5,
                         color=COLORS["secondary"], ha="left", va="center",
                         linespacing=1.35)
                y -= h
            else:
                cve, prod, _, ev = payload
                h = step * row_u
                yc = y - h * (0.32 if two_line else 0.5)
                fig.text(x_cve, yc, cve, fontfamily=MONO_FONT, fontsize=fs_id,
                         color=COLORS["text"], ha="left", va="center")
                fig.text(x_prod, yc, prod, fontsize=fs_prod, fontweight="bold",
                         color=COLORS["text"], ha="left", va="center")
                if two_line:
                    fig.text(x_ev2, y - h * 0.72, ev, fontsize=fs_ev,
                             color=COLORS["secondary"], ha="left", va="center")
                else:
                    fig.text(x_ev, yc, ev, fontsize=fs_ev,
                             color=COLORS["secondary"], ha="left", va="center")
                fig.add_artist(plt.Line2D([x_cve, 0.95], [y - h] * 2, lw=0.6,
                                          color=COLORS["grid"],
                                          transform=fig.transFigure))
                y -= h

        foot = {"wide": 9, "square": 8, "portrait": 8}[ratio]
        fig.text(0.05, 0.05,
                 f"EUVD {n_eu:,} CVEs, CISA KEV {n_cisa:,}. Evidence checked Sep 23 2026. "
                 f"Source: ENISA EUVD, CISA KEV, CVE List V5.",
                 fontsize=foot, color=COLORS["secondary"], ha="left", va="bottom")
        draw_header(fig, title, subtitle, ratio=ratio, eyebrow_suffix="EXPLOITATION",
                    title_size={"wide": 26, "square": 22, "portrait": 22}[ratio])

        path = GRAPHS / f"eu_kev_evidence_{ratio}_{stamp_date.strftime('%Y-%m-%d')}.png"
        out.append(stamp_and_save(fig, path))
    return out


if __name__ == "__main__":
    for p in render():
        print(p)

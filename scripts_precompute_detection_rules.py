#!/usr/bin/env python3
"""
Precompute the CVE -> open-source detection-rule map.

Answers one narrow, checkable question per CVE: does at least one PUBLIC rule
in a widely used open ruleset explicitly NAME this CVE ID? That is a naming /
indexing measure, not a detection-efficacy measure. See the "What this is not"
note below, and repeat it in any post copy.

Sources (all fetched fresh; the fetch is the only network step):

  Emerging Threats Open   network IDS/IPS   ``reference:cve,YYYY-NNNN`` and the
                                            ``metadata: ... cve YYYY_NNNN`` form
  SigmaHQ                 host / log        ``tags: cve.YYYY-NNNN`` + references
  Elastic detection-rules EDR               CVE ids in rule ``references``
  Nuclei templates        OFFENSE-side      ``http/cves/YYYY/CVE-...yaml`` +
                                            ``cve-id:`` classification

Nuclei is deliberately included as a foil: it is an exploitation/scanning
template library, not a detection ruleset, and it exists to answer the same
"do we care about CVE-X" question from the attacker's side. Charts must label
it as such.

What this is NOT: evidence that a CVE is undetectable. Most endpoint detection
is behavioral and never names a CVE (SigmaHQ says so explicitly in its own
docs), so a KEV entry with zero named rules may be very well covered by generic
rules. The honest reading is "no public ruleset lets you answer the question by
CVE ID".

Writes:
  processed/detection_rules.parquet     one row per CVE named by any ruleset
  processed/detection_rules_meta.json   rule counts, fetch date, source URLs

Raw downloads land in data/rules (gitignored, ~120 MB). A failed fetch falls
back to whatever is already cached there, so a network blip cannot silently
shrink the coverage numbers.
"""

import io
import json
import re
import tarfile
from pathlib import Path

import pandas as pd
import requests

HERE = Path(__file__).resolve().parent
RULES_DIR = HERE / "data" / "rules"
OUT = HERE / "processed" / "detection_rules.parquet"
OUT_META = HERE / "processed" / "detection_rules_meta.json"

# ET Open is published per Suricata version. Bump this when the ruleset drops a
# version; the URL 404s rather than silently serving an old set.
ET_URL = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules"
TARBALLS = {
    "sigma": "https://codeload.github.com/SigmaHQ/sigma/tar.gz/refs/heads/master",
    "elastic": "https://codeload.github.com/elastic/detection-rules/tar.gz/refs/heads/main",
    "nuclei": "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/heads/main",
}

CVE_RE = re.compile(r"CVE-(\d{4})-(\d{4,7})", re.IGNORECASE)
ET_REF = re.compile(r"reference:\s*cve,\s*(\d{4})-(\d{4,7})", re.IGNORECASE)
ET_META = re.compile(r"\bcve[ _](\d{4})[-_](\d{4,7})", re.IGNORECASE)
SIGMA_TAG = re.compile(r"cve\.(\d{4})[.-](\d{4,7})", re.IGNORECASE)
NUCLEI_ID = re.compile(r"cve-id:\s*\|?\s*\n?\s*CVE-(\d{4})-(\d{4,7})", re.IGNORECASE)

# Sigma directories that hold documentation/tests rather than shipped rules.
SIGMA_SKIP = {"tests", "documentation", "images", "regression_data", "other"}
SIGMA_RETIRED = {"deprecated", "unsupported"}


def _cve(y, n):
    return f"CVE-{y}-{n}"


def _download(url, dest, timeout=600):
    """Fetch ``url`` to ``dest``. On failure keep any cached copy."""
    try:
        r = requests.get(url, timeout=timeout, stream=True)
        r.raise_for_status()
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(dest.suffix + ".part")
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(1 << 20):
                f.write(chunk)
        tmp.replace(dest)
        print(f"  [fetch] {dest.name} ({dest.stat().st_size / 1e6:.1f} MB)")
        return True
    except Exception as e:
        if dest.exists():
            print(f"  [fetch] {dest.name} FAILED ({e}); using cached copy")
            return True
        print(f"  [fetch] {dest.name} FAILED ({e}); no cached copy")
        return False


def _fetch_all():
    ok = {"et_open": _download(ET_URL, RULES_DIR / "et_open.rules")}
    for name, url in TARBALLS.items():
        ok[name] = _download(url, RULES_DIR / f"{name}.tar.gz")
    return ok


def _members(name):
    """Yield (relative_path, text) for every file in a cached tarball."""
    path = RULES_DIR / f"{name}.tar.gz"
    if not path.exists():
        return
    with tarfile.open(path, "r:gz") as tf:
        for m in tf:
            if not m.isfile():
                continue
            # strip the GitHub "<repo>-<ref>/" prefix
            rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
            f = tf.extractfile(m)
            if f is None:
                continue
            try:
                yield rel, io.TextIOWrapper(f, encoding="utf-8", errors="replace").read()
            except Exception:
                continue


def _scan_et():
    """ET Open: CVEs named by enabled rules, and by commented-out rules only.

    ET Open ships a large block of rules disabled by default (leading ``#``).
    Counting those as coverage would overstate what an out-of-the-box deploy
    actually alerts on, so they are tracked separately.
    """
    path = RULES_DIR / "et_open.rules"
    if not path.exists():
        return {}, {}, 0, 0
    enabled, disabled = {}, {}
    n_rules = n_off = 0
    for line in path.read_text(errors="replace").splitlines():
        s = line.strip()
        if not s:
            continue
        off = s.startswith("#")
        body = s.lstrip("# \t")
        if not re.match(r"^(alert|drop|pass|reject)\s", body):
            continue
        n_rules += 1
        n_off += off
        ids = ({_cve(y, n) for y, n in ET_REF.findall(body)} |
               {_cve(y, n) for y, n in ET_META.findall(body)})
        tgt = disabled if off else enabled
        for c in ids:
            tgt[c] = tgt.get(c, 0) + 1
    return enabled, disabled, n_rules, n_off


def _scan_sigma():
    """SigmaHQ active rules. Returns (tagged, mentioned, n_active, n_retired)."""
    tagged, mentioned = set(), set()
    n_active = n_retired = 0
    for rel, txt in _members("sigma"):
        if not rel.endswith(".yml"):
            continue
        top = rel.split("/")[0]
        if top in SIGMA_SKIP:
            continue
        if top in SIGMA_RETIRED:
            n_retired += 1
            continue
        n_active += 1
        tags = {_cve(y, n) for y, n in SIGMA_TAG.findall(txt)}
        tagged |= tags
        mentioned |= tags | {_cve(y, n) for y, n in CVE_RE.findall(txt)}
    return tagged, mentioned, n_active, n_retired


def _scan_elastic():
    """Elastic detection-rules (shipped rules + building blocks; hunting queries
    are excluded, they are not alerting rules)."""
    found = set()
    n_files = 0
    for rel, txt in _members("elastic"):
        top = rel.split("/")[0]
        if top not in {"rules", "rules_building_block"}:
            continue
        if not rel.endswith((".toml", ".yml", ".yaml")):
            continue
        n_files += 1
        found |= {_cve(y, n) for y, n in CVE_RE.findall(txt)}
    return found, n_files


def _scan_nuclei():
    """Nuclei templates, keyed off the CVE-named filename then the cve-id field."""
    found = set()
    n_files = 0
    for rel, txt in _members("nuclei"):
        if not rel.endswith(".yaml"):
            continue
        if rel.split("/")[0] in {"profiles", "workflows", "helpers"}:
            continue
        n_files += 1
        m = CVE_RE.search(Path(rel).name)
        if m:
            found.add(_cve(m.group(1), m.group(2)))
            continue
        found |= {_cve(y, n) for y, n in NUCLEI_ID.findall(txt[:4000])}
    return found, n_files


def main():
    print("  Fetching open rulesets ...")
    _fetch_all()

    et_on, et_off, et_rules, et_disabled = _scan_et()
    sig_tag, sig_any, sig_active, sig_retired = _scan_sigma()
    ela, ela_files = _scan_elastic()
    nuc, nuc_files = _scan_nuclei()

    if not (et_on or sig_any or ela or nuc):
        raise RuntimeError("no rules parsed from any source; refusing to write")

    ids = sorted(set(et_on) | set(et_off) | sig_any | ela | nuc)
    df = pd.DataFrame({"cve_id": ids})
    df["et_open"] = df["cve_id"].isin(et_on)
    # named ONLY by rules ET ships commented out
    df["et_disabled_only"] = df["cve_id"].isin(et_off) & ~df["et_open"]
    df["et_rule_count"] = df["cve_id"].map(et_on).fillna(0).astype(int)
    df["sigma"] = df["cve_id"].isin(sig_any)
    df["sigma_tagged"] = df["cve_id"].isin(sig_tag)
    df["elastic"] = df["cve_id"].isin(ela)
    df["nuclei"] = df["cve_id"].isin(nuc)
    df["defensive"] = df["et_open"] | df["sigma"] | df["elastic"]
    df["host_defensive"] = df["sigma"] | df["elastic"]

    meta = {
        "fetched": pd.Timestamp.now("UTC").strftime("%Y-%m-%d"),
        "sources": {"et_open": ET_URL, **TARBALLS},
        "et_rules_parsed": et_rules,
        "et_rules_disabled": et_disabled,
        "et_cves_enabled": int(df["et_open"].sum()),
        "et_cves_disabled_only": int(df["et_disabled_only"].sum()),
        "sigma_rules_active": sig_active,
        "sigma_rules_retired": sig_retired,
        "sigma_cves_tagged": len(sig_tag),
        "sigma_cves_mentioned": len(sig_any),
        "elastic_rules": ela_files,
        "elastic_cves": len(ela),
        "nuclei_templates": nuc_files,
        "nuclei_cves": len(nuc),
        "defensive_union_cves": int(df["defensive"].sum()),
    }

    OUT.parent.mkdir(exist_ok=True)
    df.to_parquet(OUT, index=False)
    OUT_META.write_text(json.dumps(meta, indent=2))
    print(f"  wrote {OUT} ({len(df):,} CVEs named by at least one ruleset)")
    print(f"    ET Open  {meta['et_cves_enabled']:>5} CVEs from {et_rules:,} rules "
          f"({et_disabled:,} shipped disabled)")
    print(f"    Sigma    {meta['sigma_cves_mentioned']:>5} CVEs from {sig_active:,} active rules")
    print(f"    Elastic  {meta['elastic_cves']:>5} CVEs from {ela_files:,} rules")
    print(f"    Nuclei   {meta['nuclei_cves']:>5} CVEs from {nuc_files:,} templates")
    print(f"    Defensive union: {meta['defensive_union_cves']:,} CVEs")


if __name__ == "__main__":
    main()

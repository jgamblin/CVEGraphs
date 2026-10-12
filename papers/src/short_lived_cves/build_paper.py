#!/usr/bin/env python3
"""Assemble the short-lived CVE one-pager.

Facts live in dicts at the top. The timeline SVG is computed from the lane data so
every bar position traces to a stated day number, not to a hand-placed pixel.
Run: python3 build_paper.py > /path/to/out.html
"""
import html
import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else None

# ---------------------------------------------------------------- repo numbers
# From processed/cvelist_v5.parquet and processed/kev_catalog.json, as of 2026-09-28.
N = dict(
    asof="October 2, 2026",
    ms_2026=2962, ms_pt_sep=965, ms_pt_jul=570, ms_pt_aug=402, ms_pt_all=2669,
    ms_kev=26, ms_kev_day0=16, ms_kev_7d=18, ms_kev_late=8, ms_pt_kev=21,
    ch_2026=2935, ch_days=50, ch_top=427, ch_top_date="June 4", ch_sep9=230,
    ch_kev=7, ch_kev_day0=2, ch_kev_max_lag=4,
    all_2026=73483,
    ms_pt_hour=2639, ms_days=66,
    # from papers/src/short_lived_cves/backtest_lookalike.py, run 2026-10-02
    ms_2426=5301, base_rate="1.7%", ef_n=64, ef_kev=52, ef_rate="81%", ep_rate="4.1%", eu_n=5121, eu_rate="0.6%",
    day0_ef=9, cvss_ge9_kev="19%", cvss_ge9_all="7%", sept_ge78=489, sept_ge9=43,
    sp_n=64, sp_kev=8, sp_rate="12.5%", afd_n=56, afd_kev=4,
    pt_kev=21, hard_n=11, hard_day0=5, epss_scored=7, epss_top="0.197", epss_median="0.005",
    bt_eflag10="11.7", bt_combo10="12.0", rand_expect="1.7",
    backtest=[   # means over 200 random tie-break seeds
        ("Random order", (1.8, 4.3, 1.1, 2.5)),
        ("CVSS base score", (5.4, 10.1, 3.7, 6.4)),
        ("Microsoft's exploit flag", (11.7, 13.1, 1.7, 3.1)),
        ("Lookup by component and impact", (3.5, 8.2, 2.0, 4.0)),
        ("Flag, then lookup", (12.0, 14.0, 2.0, 4.0)),
    ],
    hard_rows=[
        dict(cve="CVE-2026-20805", what="Desktop Window Manager, information disclosure", cvss=5.5, flag="Unproven", lag=0),
        dict(cve="CVE-2026-20963", what="SharePoint, remote code execution", cvss=9.8, flag="Unproven", lag=64),
        dict(cve="CVE-2026-21519", what="Desktop Window Manager, elevation of privilege", cvss=7.8, flag="Unproven", lag=0),
        dict(cve="CVE-2026-21513", what="MSHTML Framework, security feature bypass", cvss=8.8, flag="Unproven", lag=0),
        dict(cve="CVE-2026-21525", what="Remote Access Connection Manager, denial of service", cvss=6.2, flag="Unproven", lag=0),
        dict(cve="CVE-2026-33825", what="Microsoft Defender, elevation of privilege", cvss=7.8, flag="Proof of concept", lag=8),
        dict(cve="CVE-2026-33824", what="IKE Service Extensions, remote code execution", cvss=9.8, flag="Unproven", lag=126),
        dict(cve="CVE-2026-50522", what="SharePoint, remote code execution", cvss=9.8, flag="Unproven", lag=8),
        dict(cve="CVE-2026-55040", what="SharePoint Server, security feature bypass", cvss=9.1, flag="Unproven", lag=35),
        dict(cve="CVE-2026-65660", what="SharePoint Server, remote code execution", cvss=8.8, flag="Unproven", lag=45),
        dict(cve="CVE-2026-68820", what="Ancillary Function Driver for WinSock, elevation of privilege", cvss=7.0, flag="Unproven", lag=0),
    ], ms_kev_late_lags=[8, 8, 14, 35, 40, 45, 64, 126], kev_total=1731,
    sources=[
        ("Microsoft, Understanding Windows monthly updates: Servicing explained (Jul 9, 2026)", "https://techcommunity.microsoft.com/blog/windows-itpro-blog/understanding-windows-monthly-updates-servicing-explained/4532290", "A quarterly baseline (a monthly security update with restart) is required ... the two subsequent monthly security updates are installed without requiring a restart."),
        ("Microsoft Learn, Update release cycle for Windows clients", "https://learn.microsoft.com/en-us/windows/deployment/update/release-cycle", "Second Tuesday of each month, typically published at 10:00 AM Pacific Time"),
        ("Microsoft Learn, Policy CSP: Update (AllowAutoUpdate, DetectionFrequency, ConfigureDeadline*)", "https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-update", "If automatic maintenance is unable to install updates for two days, Windows Update will install updates right away."),
        ("Microsoft Learn, Manage device restarts after updates", "https://learn.microsoft.com/en-us/windows/deployment/update/waas-restart", "By default, active hours are from 8 AM to 5 PM on PCs."),
        ("Microsoft Learn, Enforce compliance deadlines with policies (Jun 30, 2026)", "https://learn.microsoft.com/en-us/windows/deployment/update/wufb-compliancedeadlines", "When the update is released on Patch Tuesday, the effective deadline expires on Friday."),
        ("Microsoft Learn, How Windows Update works", "https://learn.microsoft.com/en-us/windows/deployment/update/how-windows-update-works", "checks the Microsoft Update server or your WSUS endpoint for new updates at random intervals"),
        ("Microsoft Learn, WSUS: Configure Group Policy settings for Automatic Updates", "https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/4-configure-group-policy-settings-for-automatic-updates", "If no schedule is specified, the default schedule for all installations is every day at 3:00 AM."),
        ("Microsoft Learn, Manage additional Windows Update settings", "https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings", "the Automatic Updates client connects directly to the Windows Update site on the Internet"),
        ("Microsoft Learn, Configure WSUS", "https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus", "By default, your client computers receive updates from Windows Update."),
        ("Microsoft Learn, WSUS: Updates operations", "https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/manage/updates-operations", "you must approve the updates before they're deployed to the computers on your network"),
        ("Microsoft, Windows Server Update Services (WSUS) deprecation (Sep 20, 2024)", "https://techcommunity.microsoft.com/blog/windows-itpro-blog/windows-server-update-services-wsus-deprecation/4250436", ""),
        ("Microsoft Learn, Manage Windows quality updates in Intune", "https://learn.microsoft.com/en-us/intune/device-updates/windows/manage-quality-updates", "Devices without a quality update policy continue to receive quality updates through standard Windows Update behavior"),
        ("Microsoft Learn, Update rings for Windows 10 and later settings reference", "https://learn.microsoft.com/en-us/intune/device-updates/windows/ref-update-ring-settings", ""),
        ("Microsoft Learn, Manage Windows Autopatch groups", "https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/manage/windows-autopatch-manage-autopatch-groups", "deferral and deadline periods ranging from one to 20 days"),
        ("Microsoft Learn, Expedite policies for Windows quality updates (Mar 31, 2026)", "https://learn.microsoft.com/en-us/intune/device-updates/windows/configure-expedite-policy", "Expedited updates install as soon as possible, bypassing deferral settings"),
        ("Microsoft Learn, Hotpatch updates in Intune", "https://learn.microsoft.com/en-us/intune/device-updates/windows/configure-hotpatch", "Hotpatch security updates are enabled by default for all eligible devices in Microsoft Intune."),
        ("Microsoft Learn, Windows Autopatch: Hotpatch updates (prerequisites)", "https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/manage/windows-autopatch-hotpatch-updates", "VBS must be turned on for a device to be offered hotpatch updates."),
        ("Microsoft, Securing devices faster with hotpatch updates on by default (Mar 9, 2026)", "https://techcommunity.microsoft.com/blog/windows-itpro-blog/securing-devices-faster-with-hotpatch-updates-on-by-default/4500066", "Typically, you'd allow 3-5 days after installing those fixes before forcing a restart to apply them."),
        ("Microsoft, Achieving world-class Windows monthly patching efficiency (Jul 21, 2021)", "https://techcommunity.microsoft.com/blog/windows-itpro-blog/achieving-world-class-windows-monthly-patching-efficiency/2572945", "the many tens-of-millions of devices that are sending telemetry"),
        ("Microsoft Support, January 13, 2026 security update (KB5074109)", "https://support.microsoft.com/en-us/topic/january-13-2026-kb5074109-os-builds-26200-7623-and-26100-7623-3ec427dd-6fc4-4c32-a471-83504dd081cb", "This update downloads and installs automatically from Windows Update and Microsoft Update."),
        ("Microsoft Support, Windows Update: FAQ", "https://support.microsoft.com/en-us/windows/windows-update-faq-8a903416-6f45-0718-f5c7-375e92dddeb2", "You can pause updates for up to 5 weeks"),
        ("Microsoft Learn, Add a Windows line-of-business app to Intune", "https://learn.microsoft.com/en-us/intune/app-management/deployment/add-lob-windows", "Windows apps with self-updating installers (such as Google Chrome)"),
        ("Chromium, Chrome Release Cycle", "https://chromium.googlesource.com/chromium/src/+/main/docs/process/release_cycle.md", "The new release generally reaches all users within one to two weeks unless major issues arise."),
        ("Google, Manage Chrome updates (Windows)", "https://support.google.com/chrome/a/answer/6350036", "Google Update checks for the latest update approximately every 5 hours."),
        ("Chromium, Updater functional specification", "https://chromium.googlesource.com/chromium/src/+/main/docs/updater/functional_spec.md", "The updater has a base update check period of 4.5 hours"),
        ("Chromium policy definitions, RelaunchNotification and RelaunchNotificationPeriod", "https://chromium.googlesource.com/chromium/src/+/main/components/policy/resources/templates/policy_definitions/Relaunch/RelaunchNotificationPeriod.yaml", "If not set, the default period of 604800000 milliseconds (one week) is used."),
        ("Google, Notify users to restart to apply pending updates", "https://support.google.com/chrome/a/answer/7679871", ""),
        ("Google Chrome Releases, Stable Channel Update for Desktop (Chrome 153, Sep 8, 2026)", "https://chromereleases.googleblog.com/2026/09/stable-channel-update-for-desktop_0808145027.html", ""),
        ("Google, Deploy and test Chrome browser (MSI behavior)", "https://support.google.com/chrome/a/answer/7650247", "Installing Chrome browser from an MSI overrides any version of Chrome browser installed by a user."),
        ("Google Chrome Releases, the seven Stable posts behind the KEV-listed Chrome CVEs (Feb 13, Mar 12, Mar 13, Mar 31, Jun 8, Sep 3 and Sep 8, 2026); linked from each CVE record", "https://chromereleases.googleblog.com/2026/02/stable-channel-update-for-desktop_13.html", "Google is aware that an exploit for CVE-2026-2441 exists in the wild."),
        ("Google, Stronger with every update (Jul 30, 2026)", "https://blog.google/security/chrome-stronger-with-every-update/", "the time spent waiting for the user to restart Chrome can be a significant contributor to N-day exploitation risk"),
        ("Google, Manage Chrome browser with Intune Settings Catalog (Windows)", "https://support.google.com/chrome/a/answer/12129062", ""),
        ("Tenable, Microsoft's September 2026 Patch Tuesday addresses 964 CVEs", "https://www.tenable.com/blog/microsofts-september-2026-patch-tuesday-addresses-964-cves-cve-2026-81963-cve-2026-85880", ""),
        ("CISA, Known Exploited Vulnerabilities catalog (JSON)", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", ""),
        ("CVE Program, cvelistV5", "https://github.com/CVEProject/cvelistV5", ""),
    ],
)

# ---------------------------------------------------------------- lanes
# Filled in after the primary-source research lands. Each lane: label, vendor,
# and a list of phases (start_day, end_day, step, text). Days are from the moment
# the vendor publishes the fix (and the CVE): Patch Tuesday 10:00 PT for
# Microsoft, the Stable channel post for Chrome.
LANES = []

PAGE_TITLE = "Short-Lived CVEs"


def esc(s):
    return html.escape(s, quote=True)


def head_css():
    return """
:root {
  --ink: #181818; --ink-2: #525559; --ink-3: #6f7378;
  --line: #dfe2e5; --soft: #f6f7f9; --surface: #ffffff;
  --navy-1: #1f3a5f; --navy-2: #5a7a9c; --navy-3: #8da0b5; --navy-4: #afc0d4;
  --alert: #dc2626;
  --head: "Host Grotesk", "Helvetica Neue", Arial, sans-serif;
  --body: Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono: "Roboto Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ink: #f2f2f2; --ink-2: #c3c6ca; --ink-3: #9a9fa5;
    --line: #2e3237; --soft: #1b1e22; --surface: #121417;
    --navy-1: #4d6b8c; --navy-2: #7f98b4; --navy-3: #afc0d4; --navy-4: #2a3a4d;
    --alert: #f87171;
  }
}
:root[data-theme="dark"] {
  --ink: #f2f2f2; --ink-2: #c3c6ca; --ink-3: #9a9fa5;
  --line: #2e3237; --soft: #1b1e22; --surface: #121417;
  --navy-1: #4d6b8c; --navy-2: #7f98b4; --navy-3: #afc0d4; --navy-4: #2a3a4d;
  --alert: #f87171;
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--surface); color: var(--ink); font-family: var(--body);
  font-size: 17px; line-height: 1.6; }
.wrap { max-width: 760px; margin: 0 auto; padding: 40px 16px 72px; }
.eyebrow { font-family: var(--mono); font-size: 12px; letter-spacing: .12em; text-transform: uppercase;
  color: var(--ink-2); margin: 0 0 14px; }
h1 { font-family: var(--head); font-weight: 300; font-size: clamp(34px, 6vw, 52px); line-height: 1.08;
  letter-spacing: -.01em; margin: 0 0 14px; }
.deck { font-size: 20px; line-height: 1.45; color: var(--ink-2); margin: 0 0 18px; }
.byline { font-family: var(--mono); font-size: 13px; color: var(--ink-3); margin: 0 0 36px;
  padding-bottom: 20px; border-bottom: 1px solid var(--line); }
h2 { font-family: var(--head); font-weight: 300; font-size: 29px; line-height: 1.2; margin: 48px 0 12px;
  letter-spacing: -.005em; }
h3 { font-family: var(--body); font-weight: 700; font-size: 17px; margin: 26px 0 6px; }
p { margin: 0 0 16px; }
a { color: inherit; text-decoration-color: var(--navy-3); text-underline-offset: 3px; }
a:hover { text-decoration-color: var(--navy-1); }
strong { font-weight: 700; }
.tldr { background: var(--soft); border-left: 3px solid var(--navy-1); padding: 16px 20px; margin: 0 0 8px;
  border-radius: 0 6px 6px 0; }
.tldr p:last-child { margin-bottom: 0; }
.caveats { border: 1px solid var(--line); border-radius: 8px; padding: 16px 20px; margin: 20px 0 8px; }
.caveats ol { margin: 6px 0 0; padding-left: 20px; }
.caveats li { margin-bottom: 8px; }
table { width: 100%; border-collapse: collapse; margin: 14px 0 22px; font-size: 15.5px; }
th, td { text-align: left; padding: 9px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { font-weight: 700; font-size: 13px; letter-spacing: .04em; text-transform: uppercase; color: var(--ink-2); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; white-space: nowrap; }
td.mono { font-family: var(--mono); font-size: 14px; }
.table-scroll { overflow-x: auto; margin: 0 -16px; padding: 0 16px; }
.kicker { color: var(--ink-2); }
figure { margin: 28px 0 32px; }
figure .fig-title { font-family: var(--body); font-weight: 700; font-size: 16px; margin: 0 0 2px; }
figure .fig-sub { font-size: 14px; color: var(--ink-2); margin: 0 0 12px; }
figcaption { font-size: 14px; color: var(--ink-2); line-height: 1.5; margin-top: 10px; }
.legend { display: flex; flex-wrap: wrap; gap: 6px 18px; font-size: 13.5px; color: var(--ink-2); margin: 8px 0 0; }
.legend span { display: inline-flex; align-items: center; gap: 7px; }
.legend i { display: inline-block; width: 14px; height: 10px; border-radius: 2px; }
.legend i.hatch { background: repeating-linear-gradient(135deg, var(--navy-3) 0 2px, transparent 2px 5px); }
.legend i.dot { width: 10px; height: 10px; border-radius: 50%; background: var(--alert); }
svg text { font-family: var(--body); }
svg .lane-label { font-size: 13px; fill: var(--ink); }
svg .lane-sub { font-size: 11.5px; fill: var(--ink-3); }
svg .tick { font-size: 11.5px; fill: var(--ink-3); }
svg .grid { stroke: var(--line); stroke-width: 1; }
svg .group { font-size: 12px; fill: var(--ink-2); letter-spacing: .08em; text-transform: uppercase; font-weight: 700; }
svg .bar:hover, svg .bar:focus { filter: brightness(1.12); outline: none; }
svg .note { font-size: 11.5px; fill: var(--ink-2); }
.tip { position: fixed; pointer-events: none; background: var(--ink); color: var(--surface); font-size: 13px;
  line-height: 1.4; padding: 8px 10px; border-radius: 6px; max-width: 260px; opacity: 0; transition: opacity .12s;
  z-index: 10; }
.tip b { display: block; font-size: 14px; }
.sources ol { padding-left: 20px; }
.sources li { margin-bottom: 8px; font-size: 15px; word-break: break-word; }
.sources .q { color: var(--ink-2); font-style: italic; }
.foot { margin-top: 48px; padding-top: 18px; border-top: 1px solid var(--line); font-family: var(--mono);
  font-size: 13px; color: var(--ink-3); }
.cols { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin: 14px 0 20px; }
.col { background: var(--soft); border-radius: 8px; padding: 14px 16px; font-size: 15px; line-height: 1.5; }
.col h4 { margin: 0 0 6px; font-size: 13px; letter-spacing: .06em; text-transform: uppercase; color: var(--ink-2); }
.col .big { font-family: var(--head); font-weight: 300; font-size: 30px; line-height: 1.1; margin: 2px 0 6px; }
.col .big small { font-family: var(--body); font-size: 13px; color: var(--ink-2); margin-left: 4px; }
@media (max-width: 640px) { .cols { grid-template-columns: 1fr; } body { font-size: 16px; } }
"""


def build():
    import sections
    css = head_css()
    body = sections.body()
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(PAGE_TITLE)}</title>
<meta name="description" content="What Windows and Chrome auto-update defaults imply for CVEs whose patch cycle outruns the scoring ecosystem.">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Host+Grotesk:wght@300&family=Roboto:wght@400;700&family=Roboto+Mono&display=swap" rel="stylesheet">
<style>{css}</style>
</head>
<body>
<div class="wrap">
{body}
</div>
<div class="tip" id="tip" role="tooltip"></div>
<script>
(function(){{
  var tip=document.getElementById('tip');
  function show(e,el){{
    tip.textContent='';
    var b=document.createElement('b'); b.textContent=el.getAttribute('data-h')||'';
    tip.appendChild(b); tip.appendChild(document.createTextNode(el.getAttribute('data-t')||''));
    tip.style.opacity=1; move(e);
  }}
  function move(e){{
    var x=(e.clientX||0)+14, y=(e.clientY||0)+14;
    if(x+270>window.innerWidth) x=(e.clientX||0)-270;
    tip.style.left=x+'px'; tip.style.top=y+'px';
  }}
  function hide(){{ tip.style.opacity=0; }}
  document.querySelectorAll('.bar').forEach(function(el){{
    el.addEventListener('pointerenter',function(e){{show(e,el);}});
    el.addEventListener('pointermove',move);
    el.addEventListener('pointerleave',hide);
    el.addEventListener('focus',function(e){{var r=el.getBoundingClientRect();show({{clientX:r.left+r.width/2,clientY:r.top}},el);}});
    el.addEventListener('blur',hide);
  }});
}})();
</script>
</body>
</html>
"""



if __name__ == "__main__":
    out = build()
    if OUT:
        OUT.write_text(out)
        print(f"wrote {OUT} ({len(out):,} bytes)")
    else:
        sys.stdout.write(out)

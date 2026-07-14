export const meta = {
  name: 'post-review',
  description: 'World-class pre-publish review of a CVEGraphs post: verify the data, pressure-test the copy, and critique the rendered graph, then synthesize a go/no-go verdict',
  whenToUse: 'Before publishing any chart post. Pass the chart name as args, e.g. args: "product_id".',
  phases: [
    { title: 'Prep', detail: 'read caption + module, find the PNG, extract claims and copy' },
    { title: 'Review', detail: 'copy + data + visual-design personas in parallel' },
    { title: 'Synthesize', detail: 'editor-in-chief verdict and prioritized fixes' },
  ],
}

// ---- input ---------------------------------------------------------------
const name = (typeof args === 'string' && args.trim())
  ? args.trim()
  : (args && args.name) ? args.name : null
if (!name) throw new Error('post-review needs a chart name, e.g. args: "product_id"')

const capPath = `content/captions/${name}.md`
const modPath = `charts/${name}.py`

// Reusable finding shape so every persona reports the same way.
const FINDINGS_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['findings', 'keep'],
  properties: {
    findings: {
      type: 'array',
      items: {
        type: 'object', additionalProperties: false,
        required: ['severity', 'element', 'problem', 'fix'],
        properties: {
          severity: { type: 'string', enum: ['blocker', 'should-fix', 'nice-to-have'] },
          element: { type: 'string', description: 'exact phrase, number, or visual element at fault' },
          problem: { type: 'string' },
          fix: { type: 'string', description: 'concrete replacement wording or design change' },
        },
      },
    },
    keep: { type: 'string', description: 'one honest thing that already works and should not change' },
  },
}

// ---- Phase 1: prep -------------------------------------------------------
phase('Prep')
const prep = await agent(
  `You are prepping a review packet for the CVEGraphs post "${name}".\n` +
  `1. Read the caption file ${capPath} and the chart module ${modPath}.\n` +
  `2. Find the newest rendered wide PNG by running: ls -t graphs/${name}_wide_*.png | head -1\n` +
  `3. Extract, verbatim: the LinkedIn/Mastodon post copy, the X/Bluesky copy, and the on-chart ` +
  `title + subtitle.\n` +
  `4. List every load-bearing factual or numeric claim in the copy and chart (each as one short ` +
  `string a fact-checker could independently recompute, e.g. "64% of 2026 CVEs have no CPE").\n` +
  `Return JSON. If a field is missing, return an empty string / empty list for it.`,
  { phase: 'Prep', label: `prep:${name}`, schema: {
    type: 'object', additionalProperties: false,
    required: ['pngPath', 'linkedin', 'x', 'chartTitle', 'claims'],
    properties: {
      pngPath: { type: 'string' },
      linkedin: { type: 'string' },
      x: { type: 'string' },
      chartTitle: { type: 'string' },
      claims: { type: 'array', items: { type: 'string' } },
    } } }
)

const png = prep.pngPath || `graphs/${name}_wide_*.png`
const packet = JSON.stringify(prep, null, 2)

const HOUSE = `HOUSE STYLE (flag every violation): no em dashes; no "n=" (spell out counts, e.g. ` +
  `"373 CVEs"); posts are compact (~3 short paragraphs), lead with the number, end on a question; ` +
  `palette is blue/grey only, no red/orange EXCEPT a single small deliberate accent marker; KEV ` +
  `charts stamp the KEV catalog release date, volume charts stamp the data-refresh date.`

// ---- Phase 2: review panel ----------------------------------------------
// Copy + data personas read the caption/module; visual personas READ the PNG image.
const COPY = [
  { key: 'factcheck', prompt:
    `You are a hostile DATA FACT-CHECKER. For EACH claim in the packet, independently recompute it ` +
    `from source using Bash + python in this repo (data.py exposes load_nvd()/load_cvelist(); CISA ` +
    `KEV is processed/kev_catalog.json; product-id coverage is processed/product_id_coverage.parquet ` +
    `and per-CVE flags in processed/product_id_cve_flags.parquet; raw records under data/cvelistV5/cves). ` +
    `Report any claim that is wrong, rounded misleadingly, or unsupported, with the value you computed ` +
    `vs the value stated. A confirmed-correct number is NOT a finding. Exclude rejected CVEs unless the ` +
    `claim says otherwise.\n` +
    `SUM/RECONCILE CHECK (treat a failure as a BLOCKER): if the chart shows numbers a reader will ` +
    `naturally add up — a partition, "parts of a whole", stacked segments, or before/after states that ` +
    `should each total 100% — verify the DISPLAYED numbers actually sum/reconcile as shown (mind ` +
    `rounding). If 64+26+2.6 style overlap makes them not sum, or a "sums to 100%" claim is false, that ` +
    `is a blocker, not a nitpick.` },
  { key: 'domain-skeptic', prompt:
    `You are a hostile DOMAIN SKEPTIC (senior vuln-management / detection engineer). Attack the ` +
    `technical framing and any overclaim: causation dressed as correlation, "most/every/always" that ` +
    `the data does not support, survivorship bias (e.g. conditioning on KEV), or a takeaway that ` +
    `contradicts how practitioners actually triage. Be specific about which sentence overreaches.` },
  { key: 'brand-editor', prompt:
    `You are a ruthless COPY EDITOR and brand-risk reviewer for a security audience. Enforce house ` +
    `style and voice. Hunt: em dashes, "n=", bloat beyond ~3 tight paragraphs, hype, hedging, unfair ` +
    `shots at a vendor, a title question the post does not answer, and whether LinkedIn ends on a ` +
    `question. Suggest tighter wording only where it clearly improves the post.\n` +
    `CHART HEADING RULE (blocker): the on-chart title must be FACTUAL and descriptive, stating what ` +
    `the chart shows, never preachy / an argument / a verdict, AND in Title Case (keep acronyms ` +
    `as-is: CVE, CPE, PURL, NVD, CISA). "How 2026 CVEs Identify the Affected Product" is fine; ` +
    `"Enrichment nearly halves the no-ID pile" fails on both counts. Chart LABELS too (axis, ` +
    `category, bucket, legend) must be Title Case; only the subtitle and footnote stay sentence ` +
    `case. The opinion and story live in the post copy. Flag any editorial or non-Title-Case ` +
    `heading or label and give a corrected replacement. The corner date stamp must be the POST ` +
    `date (today), not the data-source date (KEV release, data refresh); flag a data-date stamp.` +
    `\n\n${HOUSE}` },
  { key: 'consistency', prompt:
    `You are the SERIES EDITOR guarding against repetition and cross-post contradiction. Read ` +
    `content/CALENDAR.md (the post-history log). Flag if this post re-runs a chart or reuses a hook ` +
    `too close to a recent one, if it stacks the same thematic lane as the last several posts, or if ` +
    `its claims contradict the nuance of an earlier post. Name the specific prior post you are ` +
    `comparing against.` },
]
const VISUAL = [
  { key: 'dataviz-craft', prompt:
    `You are a hostile DATA-VISUALIZATION critic in the Tufte tradition. OPEN AND LOOK AT the rendered ` +
    `chart image at ${png} (use the Read tool on that path). Judge whether the chart form is the ` +
    `clearest honest encoding of the data: chart-junk, misleading axes or bubble-area scaling, ` +
    `truncated baselines, redundant encodings, poor sorting, or a better chart type. Only raise issues ` +
    `visible in the actual image.` },
  { key: 'legibility-design', prompt:
    `You are a meticulous VISUAL DESIGNER judging whether this looks professionally made. OPEN AND LOOK ` +
    `AT the image at ${png} (Read tool). Scrutinize: title/subtitle hierarchy, typography and font ` +
    `sizes, label collisions or truncation, alignment, spacing and margins, legend placement, ` +
    `overlapping elements, and overall polish. ` +
    `ALSO read the TEXT itself as a designer would and flag anything that looks unprofessional on a ` +
    `published chart: inconsistent capitalization, lowercase sentence fragments or orphan sub-labels ` +
    `("free text or a bare package name"), labels that are not parallel in structure or case, awkward ` +
    `truncations, and title/subtitle/axis wording that is not clean. Every visible string should look ` +
    `deliberate. Point to the exact element and say what a designer would change.` },
  { key: 'color-accessibility', prompt:
    `You are an ACCESSIBILITY and color reviewer. OPEN AND LOOK AT the image at ${png} (Read tool). ` +
    `Check: color-blind safety (deuteranopia/protanopia), contrast of text and marks, whether the ` +
    `chart still reads in grayscale, palette consistency (blue/grey house palette), and whether any ` +
    `red/orange is present and justified as a single deliberate accent. Flag legibility risks at ` +
    `social-feed thumbnail size.` },
]

phase('Review')
const reviews = await parallel(
  [...COPY, ...VISUAL].map(p => () =>
    agent(
      `${p.prompt}\n\nREVIEW PACKET for "${name}":\n${packet}\n\n` +
      `Be adversarial but HONEST: report only real issues, no manufactured nitpicks. For each finding ` +
      `give severity, the exact element/phrase/visual at fault, why it is wrong or weak, and a concrete ` +
      `fix. Also give one honest "keep this" note.`,
      { phase: 'Review', label: `review:${p.key}`, schema: FINDINGS_SCHEMA }
    ).then(r => ({ persona: p.key, ...r }))
  )
)

// ---- Phase 3: editor-in-chief synthesis ----------------------------------
phase('Synthesize')
const verdict = await agent(
  `You are the EDITOR-IN-CHIEF making the final call before "${name}" is published to LinkedIn and X ` +
  `by a well-known CVE-data researcher (10k+ followers). Below are the packet and every reviewer's ` +
  `findings, from copy, data, and visual-design personas.\n\n` +
  `PACKET:\n${packet}\n\nREVIEWS:\n${JSON.stringify(reviews.filter(Boolean), null, 2)}\n\n` +
  `Synthesize decisively:\n` +
  `1. Deduplicate overlapping findings. Separate TRUE defects from reviewer overreach and explicitly ` +
  `dismiss the manufactured nitpicks (say which and why).\n` +
  `2. COPY verdict: a prioritized fix list (blocker / should-fix / nice-to-have) with EXACT ` +
  `replacement wording, then one of POST AS-IS / POST WITH FIXES / REWORK.\n` +
  `3. GRAPH verdict: the same, for the visual, then one of SHIP AS-IS / FIX FIRST / REWORK. Only ` +
  `include design changes that genuinely raise the professional quality.\n` +
  `4. Lead with the single biggest risk in one sentence.\n` +
  `Be concrete and ruthless about priority; most posts should need only a few real changes.`,
  { phase: 'Synthesize', label: 'editor-in-chief', effort: 'high' }
)

return verdict

# Caption — Out with Patch Tuesday, in with Chrome Day (`chrome_day`)

Image: `graphs/chrome_day_<ratio>_<date>.png`. House style: no em dashes.
The one non-negotiable: the honest caveat (batching, not "buggier code") protects
credibility. Numbers are from the CNA view (who published the batch).

## LinkedIn / Mastodon
```
Out with Patch Tuesday, in with Chrome Day.

In May and June 2026, Google's Chrome team published more CVEs on its biggest
single day than Microsoft did on Patch Tuesday. June was not close: 427 Chrome
CVEs in one day (June 4, all in Chrome 149.0.7827.53) against Microsoft's 200.

The honest caveats, because they matter: this is about how vendors batch CVE
publication, not who writes buggier code. And raw count is not risk. Most of
those Chrome CVEs auto-update in the browser and few are exploited, while a
typical Patch Tuesday carries the actively-exploited bugs you actually schedule
around. Patch Tuesday is also a fixed date; Chrome Day lands whenever Chrome
ships.

Still, the shape is striking, and two months is not yet a trend. Microsoft's next
Patch Tuesday is July 14. I will be watching to see if Chrome keeps the crown.

Is your triage still built around one Tuesday a month?

#vulnerabilitymanagement #cybersecurity #CVE
```

## X / Bluesky
```
Out with Patch Tuesday, in with Chrome Day.

For the last two months, Chrome's biggest CVE day beat Microsoft's Patch Tuesday.
June wasn't close: 427 vs 200.

Caveat: batching, not buggier code, and most auto-update. But the busiest day on
the CVE calendar has shifted. Trend or blip? Patch Tuesday is July 14.
```

## Alternate framing — "the vulnpocalypse that wasn't" (deeper take)
Use this when you want the smarter, contrarian angle instead of the pure
head-to-head. Data-backed: ~1,600 Chrome CVEs in 2026 are overwhelmingly
memory-safety bugs (use-after-free ~480), high CVSS but near-zero EPSS (1 of
1,604 above 0.1, none on KEV). The AI line is an informed hypothesis, not
provable from the records, so it stays hedged.

```
Everyone keeps waiting for the AI vulnpocalypse. I think it is already here, and
it looks nothing like the movie.

In 2026 Google has published roughly 1,600 Chrome CVEs, including 427 in a single
day. On a raw-count chart that looks alarming. Look closer and it flips:

- They are overwhelmingly low-level memory-safety bugs. Use-after-free alone is
  about 480 of them.
- By CVSS many rate High or Critical. By EPSS they are near zero: out of ~1,600,
  one scores above 0.1 and none are on CISA's KEV list.
- Translation: real bugs, found and fixed internally, that almost none of will
  ever be exploited in the wild. Chrome auto-updates, so the window is tiny.

This is what proactive, at-scale bug hunting looks like, and it is very likely
being accelerated by fuzzing and AI-assisted analysis (Google has been open about
investing there). The paradox: the harder a vendor hunts and fixes its own
low-level bugs, the worse it looks on a CVE-count leaderboard, while actually
getting safer.

The real vulnpocalypse was never a wave of exploited zero-days. It is a wave of
found-and-fixed bugs that makes raw CVE counts almost useless as a risk signal.

Are we measuring security, or just measuring how hard someone is looking?

#vulnerabilitymanagement #cybersecurity #CVE
```

## Have ready in the comments (verified ammo)
- **"Which release?"** June 4 = Chrome 149.0.7827.53 (427 CVEs); June 30 = 150.0.7871.47 (382).
- **"Low severity?"** The June 30 batch was 205 medium / 91 high / 45 critical. Not trivial.
- **"You cherry-picked the biggest day."** Fair, but June monthly TOTALS were also lopsided: Chrome 965 vs Microsoft 219.
- **"Isn't June 30 + July 1 really one drop?"** No. July 1 (52) is a different version (150.0.7871.46), a separate release ~24h later, not a midnight spillover. June 4's 427 is a clean single-day, single-release record.
- **"Chrome auto-updates, so who cares?"** Correct, and that is the point: this is a disclosure-volume story, not a patch-urgency one. Confirmed exploitation (KEV) and EPSS are the risk signals, and by those Chrome's batch is low-risk.
- **Bug-class / quality framing:** of ~1,600 Chrome 2026 CVEs, ~480 are use-after-free and most of the rest are other memory-safety bugs. Mean EPSS 0.003, max 0.22, one above 0.1, none on KEV. High CVSS, near-zero real-world exploitation likelihood.

## Alt text
```
Grouped monthly bar chart, Jun 2025 to Jul 2026, of the biggest single day each
vendor published CVEs. Microsoft (orange) is steady at roughly 60 to 200 every
month. Chrome (navy) is near zero until 2026, then jumps to 151 in May and 427
in June, far above Microsoft. Source: CVE List V5.
```

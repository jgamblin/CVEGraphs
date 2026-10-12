#!/bin/bash
# Weekly CVEGraphs pipeline: refresh data -> mine insights -> render the shelf.
# Runs under launchd (see com.jgamblin.cvegraphs.weekly.plist), which starts with
# a minimal PATH, so everything is called through the repo's own .venv.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
export PATH="/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"   # git for the cvelistV5 clone
CVEGRAPHS="$REPO/.venv/bin/cvegraphs"
if [ ! -x "$CVEGRAPHS" ]; then
  echo "No $CVEGRAPHS. Set up the venv first (see README.md)." >&2
  exit 1
fi

mkdir -p logs
STAMP="$(date +%Y-%m-%d)"
LOG="logs/weekly-${STAMP}.log"
BRIEF="content/insights/insights_brief.md"

{
  echo "=================================================="
  echo "CVEGraphs weekly run — $(date)"
  echo "=================================================="

  echo "[1/3] Refreshing data ..."
  "$CVEGRAPHS" refresh

  echo "[2/3] Mining insights ..."
  "$CVEGRAPHS" insights --top 15

  echo "[3/3] Rendering charts into content/drafts/ ..."
  # A failing chart is reported in the log but does not fail the run.
  "$CVEGRAPHS" render all || echo "(some charts failed to render; see above)"

  echo "Done — $(date)"
} >> "$LOG" 2>&1

# Keep a stable 'latest' copy of the brief for easy reading / piping.
cp -f "$BRIEF" content/insights/insights_latest.md 2>/dev/null || true

# Desktop notification with the top finding (best-effort).
TOP="$(grep -m1 '^## 1\.' "$BRIEF" 2>/dev/null | sed 's/^## 1\. //')"
osascript -e "display notification \"${TOP:-brief ready}\" with title \"CVEGraphs weekly brief ready\"" 2>/dev/null || true

# Optional email: set MAIL_TO in the plist's EnvironmentVariables to enable.
if [ -n "${MAIL_TO:-}" ]; then
  mail -s "CVEGraphs weekly insight brief (${STAMP})" "$MAIL_TO" < "$BRIEF" || true
fi

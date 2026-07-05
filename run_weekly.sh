#!/bin/bash
# Weekly CVEGraphs pipeline: refresh data -> mine insights -> render the shelf.
# Designed to run under launchd (see com.jgamblin.cvegraphs.weekly.plist), which
# starts with a minimal PATH, so we set it explicitly and use absolute-ish tools.
set -euo pipefail

# Homebrew python + system git must both be reachable.
export PATH="/opt/homebrew/bin:/opt/homebrew/opt/python@3.13/libexec/bin:/usr/bin:/bin:/usr/sbin:/sbin"

REPO="/Users/gamblin/Documents/Github/CVEGraphs"
cd "$REPO"

mkdir -p logs
STAMP="$(date +%Y-%m-%d)"
LOG="logs/weekly-${STAMP}.log"

{
  echo "=================================================="
  echo "CVEGraphs weekly run — $(date)"
  echo "=================================================="

  echo "[1/3] Refreshing data ..."
  python3 refresh_data.py

  echo "[2/3] Mining insights ..."
  python3 insights.py --top 15

  echo "[3/3] Rendering charts ..."
  python3 make.py all

  echo "Done — $(date)"
} >> "$LOG" 2>&1

# Keep a stable 'latest' copy of the brief for easy reading / piping.
cp -f content/insights_brief.md "content/insights_latest.md" 2>/dev/null || true

# Desktop notification with the top finding (best-effort).
TOP="$(grep -m1 '^## 1\.' content/insights_brief.md 2>/dev/null | sed 's/^## 1\. //')"
osascript -e "display notification \"${TOP:-brief ready}\" with title \"CVEGraphs weekly brief ready\"" 2>/dev/null || true

# Optional email: set MAIL_TO in the plist's EnvironmentVariables to enable.
if [ -n "${MAIL_TO:-}" ]; then
  mail -s "CVEGraphs weekly insight brief (${STAMP})" "$MAIL_TO" < content/insights_brief.md || true
fi

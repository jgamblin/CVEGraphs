# Weekly automation (launchd)

Runs the full pipeline every week on your Mac: refresh data → mine insights →
render all charts, then leaves a ranked brief at `content/insights_latest.md`
(and a desktop notification with the top finding).

This is a one-time **manual install** — it schedules code to run beyond any
single session, so you install it yourself.

## Install

```bash
# 1. make the runner executable
chmod +x ~/Documents/Github/CVEGraphs/run_weekly.sh

# 2. copy the agent into place
cp ~/Documents/Github/CVEGraphs/deploy/com.jgamblin.cvegraphs.weekly.plist \
   ~/Library/LaunchAgents/

# 3. load it
launchctl load -w ~/Library/LaunchAgents/com.jgamblin.cvegraphs.weekly.plist
```

Runs **Monday 06:00 local**. Edit `StartCalendarInterval` in the plist to change
day/time, then reload (unload + load).

## Verify / operate

```bash
launchctl list | grep cvegraphs          # is it registered?
launchctl start com.jgamblin.cvegraphs.weekly   # run once now (test)
tail -f logs/weekly-*.log                 # watch a run
```

## Email the brief (optional)

Uncomment the `EnvironmentVariables` / `MAIL_TO` block in the plist (requires a
working `mail` setup), or pipe `content/insights_latest.md` to Slack / any
notifier from the end of `run_weekly.sh`.

## Uninstall

```bash
launchctl unload -w ~/Library/LaunchAgents/com.jgamblin.cvegraphs.weekly.plist
rm ~/Library/LaunchAgents/com.jgamblin.cvegraphs.weekly.plist
```

## Note on the schedule

The pipeline downloads/refreshes large data (NVD, CVE List V5) and reads local
files, so it must run on this machine, not a cloud routine. After the first run
the NVD download is skipped when unchanged and the CVE List clone updates
incrementally, so weekly runs are much lighter than the first.

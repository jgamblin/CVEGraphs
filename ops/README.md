# Weekly automation (launchd)

`run_weekly.sh` runs the full pipeline on this Mac: refresh data, mine the
insight brief, and render every chart into `content/drafts/`. It then copies the
brief to `content/insights/insights_latest.md` and shows a desktop notification
with the top finding. It runs through the repo's `.venv`, so set that up first
(see the top-level README).

The pipeline downloads several GB and reads local files, so it has to run here,
not in CI or a cloud routine. Curation and posting stay manual.

## Install (one-time, manual)

```bash
chmod +x ~/Documents/Github/CVEGraphs/ops/run_weekly.sh
cp ~/Documents/Github/CVEGraphs/ops/com.jgamblin.cvegraphs.weekly.plist ~/Library/LaunchAgents/
launchctl load -w ~/Library/LaunchAgents/com.jgamblin.cvegraphs.weekly.plist
```

It runs **Monday at 06:00 local time**. To change that, edit `StartCalendarInterval`
in the plist, then unload and load it again.

## Operate

```bash
launchctl list | grep cvegraphs                  # registered?
launchctl start com.jgamblin.cvegraphs.weekly    # run once now
tail -f logs/weekly-*.log                        # watch a run
```

A chart that fails to render is listed in the log and does not fail the run.

## Email the brief (optional)

Uncomment the `EnvironmentVariables` / `MAIL_TO` block in the plist (requires a
working `mail` setup).

## Uninstall

```bash
launchctl unload -w ~/Library/LaunchAgents/com.jgamblin.cvegraphs.weekly.plist
rm ~/Library/LaunchAgents/com.jgamblin.cvegraphs.weekly.plist
```

After the first run, the NVD download is skipped when nothing has changed and
the CVE List clone updates incrementally, so later weekly runs are much lighter.

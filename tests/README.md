# tests/

```bash
pytest                          # everything; snapshot tests skip without processed/
pytest -m "not snapshot"        # just the fast, data-free tests (what CI runs in effect)
python tests/golden_render.py   # pixel-compare every chart against the local baseline
```

| File | Covers |
|---|---|
| `test_registry.py` | every chart module is registered and follows the render contract |
| `test_paths.py` | render routing to drafts, superseded renders set aside (never deleted) |
| `test_cli.py` | `list`, unknown names, `publish` front matter and no-overwrite |
| `test_rolling.py` | the same-elapsed-window comparison, leap days, as-of date |
| `test_data_rules.py` | data rules that live in testable code (see docs/data-rules.md) |
| `test_smoke_render.py` | `snapshot`: every chart renders against the local data |

## Golden renders

`golden_render.py` renders every chart with the post date pinned, into a scratch
directory, and hashes the decoded pixels (PNG) or bytes (HTML). It compares those
hashes against `logs/golden/`, which is local and gitignored. Use it to show that
a refactor changed nothing visible.

The baseline only holds for the `processed/` snapshot it was taken on, so the
script refuses to compare once that data changes. After a `cvegraphs refresh`, run
`python tests/golden_render.py --update` before refactoring, not after. Version
pins in `requirements.txt` matter here too, because a different matplotlib can
move pixels.

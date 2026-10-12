# content/

Everything this project produces or that gets written for a post. The code
never writes anywhere else.

```
drafts/<chart>/          not posted yet
  post.md                the copy: LinkedIn / X text, alt text, notes
  <chart>_<ratio>_<date>.png   current render (square, portrait, wide)
  superseded/            earlier renders, moved aside by each new render
posts/<date>-<chart>/    went out on <date>; frozen
  post.md                front matter (chart, posted, platforms, data_as_of, commit, link) + the copy
  <media>                exactly what was posted
planning/
  BACKLOG.md             ideas and what to build next
  CALENDAR.md            cadence rules, queue, and the log of what shipped (with numbers)
  INSIGHTS.md            copy and chart rules: hook, house style, discovery pipeline
insights/
  insights_brief.md      ranked candidate findings from `cvegraphs insights`
  insights.json
```

## Lifecycle

1. `cvegraphs render <chart>` writes into `drafts/<chart>/`.
2. Write `post.md` next to the images.
3. Post it, then run `cvegraphs publish <chart> --link <url>`. The folder moves to
   `posts/<date>-<chart>/` and `post.md` gets front matter saying which data and
   which commit produced it.
4. Add a row to the Log in `planning/CALENDAR.md`.

Leave posted folders alone after that: the images must keep matching the numbers
in the copy that went out. To post the same chart again, render a new draft;
that becomes a new post.

## What is tracked

Everything here is committed, images included, so each post folder on GitHub
is the complete record of what went out. The exception is `superseded/` folders,
which are gitignored: they hold renders that a newer render replaced, so commit
a draft's images once you are happy with them. Posts migrated on 2026-10-11 from
the old `graphs/` + `content/captions/` layout have `migrated: 2026-10-11` in
their front matter, and no `data_as_of` or `commit`.

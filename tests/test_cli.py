"""CLI behaviour that does not need the data snapshot."""

import pandas as pd
import pytest

from cvegraphs import cli, paths


def test_list_prints_every_item(capsys):
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "pace" in out and "cvenado" in out


def test_unknown_chart_is_an_error(capsys):
    assert cli.main(["render", "no_such_chart"]) == 1
    assert "Unknown" in capsys.readouterr().out


def test_bare_chart_name_means_render(monkeypatch):
    seen = {}
    monkeypatch.setattr(cli, "cmd_render", lambda a: seen.setdefault("names", a.names) and 0)
    cli.main(["pace"])
    assert seen["names"] == ["pace"]


@pytest.fixture
def content(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "ROOT", tmp_path)
    monkeypatch.setattr(paths, "DRAFTS", tmp_path / "content" / "drafts")
    monkeypatch.setattr(paths, "POSTS", tmp_path / "content" / "posts")
    monkeypatch.setattr(cli, "_git_commit", lambda: "abc1234")
    import cvegraphs.data as data

    monkeypatch.setattr(data, "load_cvelist", lambda: pd.DataFrame(
        {"published": pd.to_datetime(["2026-10-09T08:00"], utc=True)}))
    return tmp_path / "content"


def test_publish_freezes_draft_with_front_matter(content):
    draft = content / "drafts" / "kev_weekend"
    draft.mkdir(parents=True)
    (draft / "post.md").write_text("# copy\n")
    (draft / "kev_weekend_wide_2026-10-11.png").write_bytes(b"png")

    assert cli.main(["publish", "kev_weekend", "--date", "2026-10-11", "--link", "https://x"]) == 0

    post = content / "posts" / "2026-10-11-kev_weekend"
    assert not draft.exists() and (post / "kev_weekend_wide_2026-10-11.png").exists()
    text = (post / "post.md").read_text()
    assert text.startswith("---\nchart: kev_weekend\nposted: 2026-10-11\ndata_as_of: 2026-10-09\n")
    assert "commit: abc1234" in text and "link: https://x" in text and text.endswith("# copy\n")


def test_publish_refuses_to_overwrite(content):
    (content / "drafts" / "pace").mkdir(parents=True)
    (content / "posts" / "2026-10-11-pace").mkdir(parents=True)
    assert cli.main(["publish", "pace", "--date", "2026-10-11"]) == 1
    assert (content / "drafts" / "pace").exists()


def test_publish_without_draft_is_an_error(content):
    assert cli.main(["publish", "pace"]) == 1

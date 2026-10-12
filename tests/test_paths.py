"""Render routing: where a chart's output lands, and superseded-render handling."""

from cvegraphs import paths, registry


def test_output_follows_render_target(tmp_path):
    with paths.render_target("pace", root=tmp_path) as folder:
        assert folder == tmp_path / "pace" and folder.is_dir()
        assert paths.OUTPUT / "x.png" == tmp_path / "pace" / "x.png"


def test_render_target_nests_and_restores(tmp_path):
    with paths.render_target("outer", root=tmp_path):
        with paths.render_target("inner", root=tmp_path):
            assert (paths.OUTPUT / "f").parent.name == "inner"
        assert (paths.OUTPUT / "f").parent.name == "outer"
    assert (paths.OUTPUT / "f").parent == paths.DRAFTS / "_adhoc"


def test_default_target_is_under_drafts():
    assert paths.DRAFTS == paths.CONTENT / "drafts"
    assert paths.POSTS == paths.CONTENT / "posts"


def test_superseded_renders_are_set_aside_not_deleted(tmp_path):
    folder = tmp_path / "pace"
    folder.mkdir()
    old = folder / "pace_wide_2026-10-04.png"
    other = folder / "pace_square_2026-10-04.png"   # different ratio: not superseded
    keep = folder / "post.md"
    new = folder / "pace_wide_2026-10-11.png"
    for f in (old, other, keep, new):
        f.write_text(f.name)

    registry._set_aside_superseded(folder, [new])

    assert not old.exists() and (folder / "superseded" / old.name).exists()
    assert other.exists() and keep.exists() and new.exists()


def test_newer_render_is_never_set_aside(tmp_path):
    folder = tmp_path / "pace"
    folder.mkdir()
    newer = folder / "pace_wide_2026-10-20.png"
    written = folder / "pace_wide_2026-10-11.png"   # e.g. CVEGRAPHS_POST_DATE in the past
    for f in (newer, written):
        f.write_text(f.name)
    registry._set_aside_superseded(folder, [written])
    assert newer.exists()

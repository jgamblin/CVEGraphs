"""Every chart renders against the local snapshot (skipped without one).

This only checks that rendering succeeds and writes images. For "did the
output change", run tests/golden_render.py.
"""

import pytest

from cvegraphs import registry

# Charts that refuse to render on purpose until a human re-checks them.
GUARDED = {
    "eu_kev_evidence": "EU-only KEV set changed since its grades were researched",
}


@pytest.fixture(scope="module")
def nvd():
    from cvegraphs.data import load_nvd

    return load_nvd()


@pytest.mark.snapshot
@pytest.mark.parametrize("name", sorted(registry.all_renderables()))
def test_renders(name, nvd, tmp_path, monkeypatch):
    monkeypatch.setenv("CVEGRAPHS_POST_DATE", "2026-10-11")
    if name in GUARDED:
        pytest.xfail(GUARDED[name])
    written = registry.render(name, nvd=nvd, root=tmp_path)
    assert written, f"{name} wrote nothing"
    for p in written:
        assert p.exists() and p.stat().st_size > 0 and p.parent == tmp_path / name

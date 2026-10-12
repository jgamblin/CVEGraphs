"""The registry finds every chart, and every chart honors the render contract."""

import inspect

from cvegraphs import paths, registry


def test_every_chart_module_is_registered():
    modules = {p.stem for p in (paths.PACKAGE / "charts").glob("*.py") if not p.stem.startswith("_")}
    items = registry.all_renderables()
    assert modules - set(items) == set(), "chart modules missing DESCRIPTION or render()"
    assert {"cvenado", "short_lived_cves"} <= set(items)


def test_descriptions_are_single_lines():
    for name, mod in registry.all_renderables().items():
        d = mod.DESCRIPTION
        assert isinstance(d, str) and d.strip() and "\n" not in d, name
        assert len(d) <= 140, f"{name}: keep `cvegraphs list` to one line"


def test_render_accepts_nvd_keyword():
    for name, mod in registry.all_renderables().items():
        params = inspect.signature(mod.render).parameters
        assert "nvd" in params, f"{name}.render must accept nvd= (the CLI passes it)"
        assert params["nvd"].default is None, f"{name}.render(nvd=...) must default to None"


def test_names_are_valid_folder_names():
    for name in registry.all_renderables():
        assert name.isidentifier() and name == name.lower(), name

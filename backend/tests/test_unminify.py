from pipeline import unminify
from pipeline.models import JSAsset


def test_beautify_adds_newlines():
    pretty = unminify.beautify("var a=1;var b=2;function f(){return a;}")
    assert pretty.count("\n") >= 2


def test_beautify_empty():
    assert unminify.beautify("") == ""


def test_unbundle_single_module_returns_whole():
    modules = unminify.unbundle("function f(){return 1;}")
    assert modules == ["function f(){return 1;}"]


def test_unbundle_splits_webpack_modules():
    bundle = "{0: function(module, exports){a();}, 1: function(module, exports){b();}}"
    modules = unminify.unbundle(bundle)
    assert len(modules) == 2
    assert "a()" in modules[0]
    assert "b()" in modules[1]


def test_process_expands_bundle_into_assets():
    asset = JSAsset(
        url="http://x/bundle.js",
        content="{0: function(module, exports){a();}, 1: function(module, exports){b();}}",
    )
    out = unminify.process([asset])
    assert len(out) == 2
    assert out[0].url.endswith("::module0")

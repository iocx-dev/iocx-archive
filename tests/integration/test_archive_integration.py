import os
import pytest
from conftest import FakeEngine, FakeCtx, make_zip, make_tar, make_7z

@pytest.mark.integration
def test_zip_end_to_end(plugin, tmp_path):
    """Full pipeline: detect → extract → recurse → analyze."""
    path = tmp_path / "archive.zip"
    make_zip(path, {
        "a.txt": b"hello",
        "b/b.txt": b"world",
    })

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    # Archive detection
    assert any(d.category == "archive" for d in detections)

    # Engine should analyze both extracted files
    analyzed_paths = [p for p, _ in engine.analyzed]
    assert any(p.endswith("a.txt") for p in analyzed_paths)
    assert any(p.endswith("b.txt") for p in analyzed_paths)

@pytest.mark.integration
def test_nested_end_to_end(plugin, tmp_path):
    """Nested archive → inner archive → inner file."""
    inner = tmp_path / "inner.zip"
    make_zip(inner, {"deep.txt": b"ok"})

    outer = tmp_path / "outer.zip"
    make_zip(outer, {"inner.zip": inner.read_bytes()})

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(outer), engine)

    plugin.detect("", ctx)

    analyzed = [p for p, _ in engine.analyzed]

    # Should analyze outer, inner, and deep file
    assert any(p.endswith("inner.zip") for p in analyzed)
    assert any(p.endswith("deep.txt") for p in analyzed)

@pytest.mark.integration
def test_tar_end_to_end(plugin, tmp_path):
    path = tmp_path / "archive.tar"
    make_tar(path, {"x.txt": b"123"})

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    plugin.detect("", ctx)

    assert any(p.endswith("x.txt") for p, _ in engine.analyzed)

@pytest.mark.integration
def test_7z_end_to_end(plugin, tmp_path):
    path = tmp_path / "archive.7z"
    make_7z(path, {"y.txt": b"abc"})

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    plugin.detect("", ctx)

    assert any(p.endswith("y.txt") for p, _ in engine.analyzed)

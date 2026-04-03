import os
import pytest
from conftest import make_7z, FakeEngine, FakeCtx

def test_7z_basic(plugin, tmpfile):
    if not plugin._detect_archive_type:
        pytest.skip("py7zr not installed")

    path = os.path.join(tmpfile, "simple.7z")

    make_7z(path, {"x.txt": b"data"})

    engine = FakeEngine(plugin)
    ctx = FakeCtx(path, engine)

    detections = plugin.detect("", ctx)

    assert any(d.category == "archive" for d in detections)
    assert len(engine.analyzed) >= 1

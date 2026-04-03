import os
import pytest
from iocx.models import Detection
from conftest import make_zip, FakeEngine, FakeCtx

def test_zip_basic(plugin, tmpfile):
    zip_path = os.path.join(tmpfile, "simple.zip")

    # Create a simple ZIP
    make_zip(zip_path, {"hello.txt": b"world"})

    engine = FakeEngine(plugin)
    ctx = FakeCtx(zip_path, engine)

    detections = plugin.detect("", ctx)

    # Should detect archive
    assert any(d.category == "archive" for d in detections)

    # Should analyze extracted file
    assert len(engine.analyzed) == 1
    assert engine.analyzed[0][0].endswith("hello.txt")

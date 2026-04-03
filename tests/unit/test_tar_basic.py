import os
import pytest
from conftest import make_tar, FakeEngine, FakeCtx

def test_tar_basic(plugin, tmpfile):
    tar_path = os.path.join(tmpfile, "simple.tar")

    make_tar(tar_path, {"a.txt": b"123"})

    engine = FakeEngine(plugin)
    ctx = FakeCtx(tar_path, engine)

    detections = plugin.detect("", ctx)

    assert any(d.category == "archive" for d in detections)
    assert len(engine.analyzed) == 1

import os
import pytest
from conftest import make_zip, FakeEngine, FakeCtx

def test_path_traversal_blocked(plugin, tmpfile):
    path = os.path.join(tmpfile, "traversal.zip")

    make_zip(path, {"../evil.txt": b"bad"})

    engine = FakeEngine(plugin)
    ctx = FakeCtx(path, engine)

    detections = plugin.detect("", ctx)

    assert any(d.value == "archive_path_traversal_blocked" for d in detections)
    assert len(engine.analyzed) == 0

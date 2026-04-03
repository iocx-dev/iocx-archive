import os
import pytest
from conftest import make_zip, FakeEngine, FakeCtx

def test_nested_archives(plugin, tmpfile):
    inner = os.path.join(tmpfile, "inner.zip")
    outer = os.path.join(tmpfile, "outer.zip")

    make_zip(inner, {"file.txt": b"ok"})
    make_zip(outer, {"inner.zip": open(inner, "rb").read()})

    engine = FakeEngine(plugin)
    ctx = FakeCtx(outer, engine)

    detections = plugin.detect("", ctx)

    # Should analyze both outer and inner contents
    assert len(engine.analyzed) >= 2

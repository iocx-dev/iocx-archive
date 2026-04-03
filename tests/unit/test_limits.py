import os
import pytest
from conftest import make_zip, FakeEngine, FakeCtx

def test_entry_size_limit(plugin, tmpfile):
    path = os.path.join(tmpfile, "big.zip")

    big_data = b"A" * (plugin.MAX_ENTRY_SIZE + 1)
    make_zip(path, {"big.bin": big_data})

    engine = FakeEngine(plugin)
    ctx = FakeCtx(path, engine)

    detections = plugin.detect("", ctx)

    assert any(d.value == "archive_entry_size_limit_reached" for d in detections)
    assert len(engine.analyzed) == 0

import pytest
import os
import random
from conftest import FakeEngine, FakeCtx
from iocx_archive.plugin import Plugin

plugin = Plugin()


def random_bytes(n=4096):
    return os.urandom(n)


@pytest.mark.fuzz
def test_random_binary_not_archive(tmp_path):
    """Random binary should never crash the plugin."""
    path = tmp_path / "random.bin"
    path.write_bytes(random_bytes(4096))

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    print("[fuzz] random binary processed safely")
    assert detections == []


@pytest.mark.fuzz
def test_random_header_bytes(tmp_path):
    """Random bytes at the start of file should not confuse archive detection."""
    path = tmp_path / "random_header.bin"
    path.write_bytes(random_bytes(128) + b"TRAILINGDATA")

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)
    assert detections == []

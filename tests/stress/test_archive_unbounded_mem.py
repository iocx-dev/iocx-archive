import pytest
import tracemalloc
from conftest import FakeEngine, FakeCtx, make_zip
from iocx_archive.plugin import Plugin

plugin = Plugin()


@pytest.mark.stress
def test_memory_usage_under_load(tmp_path):
    """Ensure memory stays bounded during heavy extraction."""
    path = tmp_path / "mem.zip"
    make_zip(path, {f"f{i}.txt": b"x" * 1024 for i in range(5000)})

    tracemalloc.start()
    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)
    plugin.detect("", ctx)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    print(f"[memory] peak memory: {peak / 1024 / 1024:.2f} MB")

    assert peak < 200 * 1024 * 1024 # <200MB

import pytest
import time
import os
from conftest import FakeEngine, FakeCtx, make_zip, make_tar, make_7z
from iocx_archive.plugin import Plugin

plugin = Plugin()


@pytest.mark.stress
def test_10k_small_files(tmp_path):
    """10,000 tiny files — filesystem pressure + extraction overhead."""
    path = tmp_path / "10k.zip"
    files = {f"f{i}.txt": b"x" for i in range(10_000)}
    make_zip(path, files)

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    start = time.perf_counter()
    plugin.detect("", ctx)
    duration = time.perf_counter() - start

    print(f"[stress] 10k small files: {duration:.4f}s")
    assert duration < 3.0


@pytest.mark.stress
def test_100mb_archive(tmp_path):
    """Ensure plugin handles large archives without memory blowout."""
    path = tmp_path / "100mb.zip"
    big = b"A" * (100 * 1024 * 1024)
    make_zip(path, {"big.bin": big})

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    start = time.perf_counter()
    plugin.detect("", ctx)
    duration = time.perf_counter() - start

    print(f"[stress] 100MB archive: {duration:.4f}s")
    assert duration < 2.0

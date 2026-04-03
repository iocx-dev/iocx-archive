import pytest
import time
import os
import random
import string

from conftest import FakeEngine, FakeCtx, make_zip, make_tar, make_7z
from iocx_archive.plugin import Plugin as ArchivePlugin

# Instantiate plugin once
plugin = ArchivePlugin()


# -----------------------------
# Random archive generators
# -----------------------------

def random_bytes(n=1024):
    return os.urandom(n)


def random_filename():
    chars = string.ascii_letters + string.digits + "._-"
    return "".join(random.choice(chars) for _ in range(12))


def build_many_small_files(count=2000, size=32):
    return {f"{random_filename()}.txt": random_bytes(size) for _ in range(count)}


def build_large_file(size_mb=5):
    return {"large.bin": random_bytes(size_mb * 1024 * 1024)}


def build_nested_archives(tmp_path, depth=5):
    """
    Build nested ZIPs:
        level5.zip -> level4.zip -> ... -> level0.zip
    """
    base = tmp_path / "level0.zip"
    make_zip(base, {"root.txt": b"ok"})

    prev = base
    for i in range(1, depth + 1):
        new = tmp_path / f"level{i}.zip"
        make_zip(new, {f"inner{i-1}.zip": prev.read_bytes()})
        prev = new

    return prev


# -----------------------------
# Performance Tests
# -----------------------------

@pytest.mark.performance
def test_archive_many_small_files_performance(tmp_path):
    """Ensure extraction of many small files stays fast and bounded."""
    path = tmp_path / "many.zip"
    files = build_many_small_files(2000, size=32)
    make_zip(path, files)

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    start = time.perf_counter()
    plugin.detect("", ctx)
    duration = time.perf_counter() - start

    print(f"[perf] archive many-small-files (2000 files): {duration:.4f}s")

    # Should finish quickly on normal hardware
    assert duration < 1.0, f"Archive extraction too slow: {duration:.3f}s"


@pytest.mark.performance
def test_archive_large_file_limit(tmp_path):
    """Ensure large files are blocked quickly without blowing memory."""
    path = tmp_path / "large.zip"
    make_zip(path, build_large_file(size_mb=plugin.MAX_ENTRY_SIZE // (1024 * 1024) + 1))

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    start = time.perf_counter()
    detections = plugin.detect("", ctx)
    duration = time.perf_counter() - start

    print(f"[perf] archive large-file-limit: {duration:.4f}s")

    assert any(d.value == "archive_entry_size_limit_reached" for d in detections)
    assert duration < 0.5, f"Large-file rejection too slow: {duration:.3f}s"


@pytest.mark.performance
def test_archive_nested_depth_limit(tmp_path):
    """Ensure nested archives stop at MAX_DEPTH quickly."""
    path = build_nested_archives(tmp_path, depth=plugin.MAX_DEPTH + 3)

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    start = time.perf_counter()
    detections = plugin.detect("", ctx)
    duration = time.perf_counter() - start

    print(f"[perf] archive nested-depth-limit: {duration:.4f}s")

    assert any(d.value == "archive_max_depth_reached" for d in detections)
    assert duration < 0.7, f"Nested-depth handling too slow: {duration:.3f}s"


@pytest.mark.performance
def test_archive_scaling_behavior(tmp_path):
    """Ensure roughly linear scaling with number of files."""

    # Warm-up run
    warm = tmp_path / "warm.zip"
    make_zip(warm, build_many_small_files(300))
    plugin.detect("", FakeCtx(str(warm), FakeEngine(plugin)))

    sizes = [300, 600, 1200, 2400] # number of files
    timings = []

    for count in sizes:
        path = tmp_path / f"scale-{count}.zip"
        make_zip(path, build_many_small_files(count))

        # median of 3 runs
        runs = []
        for _ in range(3):
            engine = FakeEngine(plugin)
            ctx = FakeCtx(str(path), engine)

            start = time.perf_counter()
            plugin.detect("", ctx)
            runs.append(time.perf_counter() - start)

        duration = sorted(runs)[1]
        timings.append(duration)

        print(f"[perf] archive scaling {count} files: {duration:.4f}s")

    # Ensure no superlinear blow-up (allow 2.5× per doubling)
    for i in range(1, len(timings)):
        assert timings[i] < timings[i-1] * 2.5, "Non-linear scaling detected"

import os
import tempfile
import py7zr
import pytest

from iocx_archive.plugin import Plugin


class FakeEngine:
    def __init__(self, plugin):
        self.plugin = plugin
        self.analyzed = []

    def analyze_file(self, path, depth=0):
        # No recursion in this test
        self.analyzed.append((path, depth))
        return []


class FakeCtx:
    def __init__(self, path, engine, depth=0):
        self.path = path
        self.engine = engine
        self.depth = depth


def make_simple_7z(path):
    """Create a valid 7z archive with one file."""
    with tempfile.TemporaryDirectory() as tmp:
        fpath = os.path.join(tmp, "a.txt")
        with open(fpath, "wb") as f:
            f.write(b"OK")

        with py7zr.SevenZipFile(path, "w") as z:
            z.writeall(tmp, arcname="")


def test_7z_entry_error(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    with tempfile.TemporaryDirectory() as tmp:
        archive_path = os.path.join(tmp, "test.7z")
        make_simple_7z(archive_path)

        # Monkeypatch extract() to raise an exception
        def boom(*args, **kwargs):
            raise Exception("forced failure")

        monkeypatch.setattr(py7zr.SevenZipFile, "extract", boom)

        ctx = FakeCtx(archive_path, engine)
        detections = plugin.detect("", ctx)

        # Assert the specific detection was emitted
        assert any(
            d.value == "archive_7z_entry_error"
            for d in detections
        )


def test_7z_unsupported(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    # Force plugin to think py7zr is unavailable
    monkeypatch.setattr("iocx_archive.plugin.py7zr", None)

    # Force archive type detection to return "7z"
    monkeypatch.setattr(plugin, "_detect_archive_type", lambda path: "7z")

    with tempfile.TemporaryDirectory() as tmp:
        fake_7z = os.path.join(tmp, "fake.7z")
        with open(fake_7z, "wb") as f:
            f.write(b"not a real 7z")

        ctx = FakeCtx(fake_7z, engine)
        detections = plugin.detect("", ctx)

        assert any(
            d.value == "archive_7z_unsupported"
            for d in detections
        )


def test_py7zr_importerror(monkeypatch):
    import sys, importlib, builtins

    # Ensure py7zr is not already imported
    sys.modules.pop("py7zr", None)

    # Patch __import__ so that importing py7zr raises ImportError
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "py7zr":
            raise ImportError("simulated missing py7zr")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)

    # Remove plugin module so it re-executes its import block
    sys.modules.pop("iocx_archive.plugin", None)

    # Now import the plugin fresh
    import iocx_archive.plugin as plugin
    importlib.reload(plugin)

    # Assert the fallback branch executed
    assert plugin.py7zr is None


def test_7z_getinfo_exception(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    # Force archive type detection to return "7z"
    monkeypatch.setattr(plugin, "_detect_archive_type", lambda path: "7z")

    # Monkeypatch getinfo() to raise inside the inner try/except
    def boom(self, name):
        raise Exception("forced getinfo failure")

    monkeypatch.setattr(py7zr.SevenZipFile, "getinfo", boom)

    with tempfile.TemporaryDirectory() as tmp:
        archive_path = os.path.join(tmp, "test.7z")
        make_simple_7z(archive_path)

        ctx = FakeCtx(archive_path, engine)
        detections = plugin.detect("", ctx)

    # No specific detection is emitted for this branch,
    # but the plugin must NOT crash and must continue processing.
    # So we assert that detect() returned normally.
    assert isinstance(detections, list)


def test_7z_stop_branch(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    # Force archive type detection to return "7z"
    monkeypatch.setattr(plugin, "_detect_archive_type", lambda path: "7z")

    # Force enforce_limits() to return "stop"
    monkeypatch.setattr(
        plugin.policy,
        "enforce_limits",
        lambda state, size, det, name: "stop"
    )

    with tempfile.TemporaryDirectory() as tmp:
        archive_path = os.path.join(tmp, "test.7z")
        make_simple_7z(archive_path)

        ctx = FakeCtx(archive_path, engine)
        detections = plugin.detect("", ctx)

    # No detection is emitted for "stop", but the handler must return normally.
    assert isinstance(detections, list)

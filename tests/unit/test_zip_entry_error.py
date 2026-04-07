import os
import zipfile
import tempfile
import pytest

from iocx_archive.plugin import Plugin
from conftest import FakeEngine, FakeCtx


def make_simple_zip(path):
    """Create a valid ZIP with one file."""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a.txt", b"OK")


def test_zip_entry_error(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    with tempfile.TemporaryDirectory() as tmp:
        zip_path = os.path.join(tmp, "test.zip")
        make_simple_zip(zip_path)

        # Monkeypatch ZipFile.open to raise an exception
        def boom(*args, **kwargs):
            raise Exception("forced failure")

        monkeypatch.setattr(zipfile.ZipFile, "open", boom)

        ctx = FakeCtx(zip_path, engine)
        detections = plugin.detect("", ctx)

        # Assert the specific detection was emitted
        assert any(
            d.value == "archive_zip_entry_error"
            for d in detections
        )


def test_zip_outer_exception(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    # Force archive type detection to return "zip"
    monkeypatch.setattr(plugin, "_detect_archive_type", lambda path: "zip")

    # Monkeypatch ZipFile constructor to raise immediately
    def boom(*args, **kwargs):
        raise Exception("forced outer zip failure")

    monkeypatch.setattr(zipfile, "ZipFile", boom)

    with tempfile.NamedTemporaryFile() as tmp:
        ctx = FakeCtx(tmp.name, engine)
        detections = plugin.detect("", ctx)

    assert any(
        d.value == "archive_zip_error"
        for d in detections
    )


def make_zip_with_directory(path):
    """Create a ZIP containing a directory entry."""
    with zipfile.ZipFile(path, "w") as z:
        # Directory entry — MUST end with '/'
        z.writestr("somedir/", b"")
        # Add a normal file too so the handler continues after the directory
        z.writestr("file.txt", b"OK")


def test_zip_directory_entry_continue():
    plugin = Plugin()
    engine = FakeEngine(plugin)

    with tempfile.TemporaryDirectory() as tmp:
        zip_path = os.path.join(tmp, "test.zip")
        make_zip_with_directory(zip_path)

        ctx = FakeCtx(zip_path, engine)
        detections = plugin.detect("", ctx)

    # No detection is emitted for directory entries,
    # so the correct assertion is simply that detect() returns normally.
    assert isinstance(detections, list)

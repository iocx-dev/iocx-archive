import os
import io
import tarfile
import tempfile
import pytest

from iocx_archive.plugin import Plugin


class FakeEngine:
    def __init__(self, plugin):
        self.plugin = plugin
        self.analyzed = []

    def analyze_file(self, path, depth=0):
        # We don't recurse in this test
        self.analyzed.append((path, depth))
        return []


class FakeCtx:
    def __init__(self, path, engine, depth=0):
        self.path = path
        self.engine = engine
        self.depth = depth
        self.metadata = {}


def make_simple_tar(path):
    """Create a valid TAR with one file."""
    with tarfile.open(path, "w") as t:
        info = tarfile.TarInfo("a.txt")
        data = b"OK"
        info.size = len(data)
        t.addfile(info, io.BytesIO(data))


def test_tar_entry_error(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    with tempfile.TemporaryDirectory() as tmp:
        tar_path = os.path.join(tmp, "test.tar")
        make_simple_tar(tar_path)

        # Monkeypatch tarfile.TarFile.extractfile to raise an exception
        def boom(*args, **kwargs):
            raise Exception("forced failure")

        monkeypatch.setattr(tarfile.TarFile, "extractfile", boom)

        ctx = FakeCtx(tar_path, engine)
        detections = plugin.detect("", ctx)

        # Assert the specific detection was emitted
        assert any(
            d.value == "archive_tar_entry_error"
            for d in detections
        )


def test_tar_extractfile_returns_none(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    with tempfile.TemporaryDirectory() as tmp:
        tar_path = os.path.join(tmp, "test.tar")
        make_simple_tar(tar_path)

        # Monkeypatch extractfile() to return None
        def return_none(*args, **kwargs):
            return None

        monkeypatch.setattr(tarfile.TarFile, "extractfile", return_none)

        ctx = FakeCtx(tar_path, engine)
        detections = plugin.detect("", ctx)

        # Assert the specific detection was emitted
        assert any(
            d.value == "archive_tar_entry_error"
            for d in detections
        )


def test_is_tar_safely_exception(monkeypatch):
    plugin = Plugin()

    # Force tarfile.is_tarfile to raise an exception
    def boom(*args, **kwargs):
        raise Exception("forced failure")

    monkeypatch.setattr(tarfile, "is_tarfile", boom)

    with tempfile.NamedTemporaryFile() as tmp:
        result = plugin._is_tar_safely(tmp.name)

    assert result == "error"


def test_tar_error_branch(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    # Force archive type detection to return "tar_error"
    monkeypatch.setattr(plugin, "_detect_archive_type", lambda path: "tar_error")

    with tempfile.NamedTemporaryFile() as tmp:
        ctx = FakeCtx(tmp.name, engine)
        detections = plugin.detect("", ctx)

    assert any(
        d.value == "archive_tar_error"
        for d in detections
    )


def test_tar_outer_exception(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    # Force archive type detection to return "tar"
    monkeypatch.setattr(plugin, "_detect_archive_type", lambda path: "tar")

    # Monkeypatch tarfile.open to raise immediately
    def boom(*args, **kwargs):
        raise Exception("forced outer tar failure")

    monkeypatch.setattr(tarfile, "open", boom)

    with tempfile.NamedTemporaryFile() as tmp:
        ctx = FakeCtx(tmp.name, engine)
        detections = plugin.detect("", ctx)

    assert any(
        d.value == "archive_tar_error"
        for d in detections
    )


def test_detect_archive_type_tar_error(monkeypatch):
    plugin = Plugin()

    # Force _is_tar_safely() to return "error"
    monkeypatch.setattr(plugin, "_is_tar_safely", lambda path: "error")

    # Also force zipfile.is_zipfile to return False so ZIP is skipped
    import zipfile
    monkeypatch.setattr(zipfile, "is_zipfile", lambda path: False)

    with tempfile.NamedTemporaryFile() as tmp:
        result = plugin._detect_archive_type(tmp.name)

    assert result == "tar_error"


def make_tar_with_directory(path):
    """Create a TAR containing a directory entry."""
    with tarfile.open(path, "w") as t:
        # Directory entry
        dir_info = tarfile.TarInfo("somedir/")
        dir_info.type = tarfile.DIRTYPE
        t.addfile(dir_info)

        # Add a normal file too so the handler continues after the directory
        file_info = tarfile.TarInfo("file.txt")
        data = b"OK"
        file_info.size = len(data)
        t.addfile(file_info, io.BytesIO(data))


def test_tar_directory_entry_continue():
    plugin = Plugin()
    engine = FakeEngine(plugin)

    with tempfile.TemporaryDirectory() as tmp:
        tar_path = os.path.join(tmp, "test.tar")
        make_tar_with_directory(tar_path)

        ctx = FakeCtx(tar_path, engine)
        detections = plugin.detect("", ctx)

    # No detection is emitted for directory entries,
    # so the correct assertion is simply that detect() returns normally.
    assert isinstance(detections, list)


def test_tar_stop_branch(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    # Force archive type detection to return "tar"
    monkeypatch.setattr(plugin, "_detect_archive_type", lambda path: "tar")

    # Force enforce_limits() to return "stop"
    monkeypatch.setattr(plugin.policy, "enforce_limits",
                        lambda state, size, det, name: "stop")

    with tempfile.TemporaryDirectory() as tmp:
        tar_path = os.path.join(tmp, "test.tar")
        make_simple_tar(tar_path)

        ctx = FakeCtx(tar_path, engine)
        detections = plugin.detect("", ctx)

    assert isinstance(detections, list)


def test_tar_skip_branch(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    # Force archive type detection to return "tar"
    monkeypatch.setattr(plugin, "_detect_archive_type", lambda path: "tar")

    # Force enforce_limits() to return "skip"
    monkeypatch.setattr(plugin.policy, "enforce_limits",
                        lambda state, size, det, name: "skip")

    with tempfile.TemporaryDirectory() as tmp:
        tar_path = os.path.join(tmp, "test.tar")
        make_simple_tar(tar_path)

        ctx = FakeCtx(tar_path, engine)
        detections = plugin.detect("", ctx)

    assert isinstance(detections, list)

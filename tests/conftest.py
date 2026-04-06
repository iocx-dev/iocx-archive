import io
import os
import zipfile
import tarfile
import py7zr
import tempfile
import pytest

from iocx_archive.plugin import Plugin
from iocx.models import Detection


class FakeEngine:
    def __init__(self, plugin):
        self.plugin = plugin
        self.analyzed = []

    def analyze_file(self, path, depth=0):
        self.analyzed.append((path, depth))
        ctx = FakeCtx(path, self, depth)
        return self.plugin.detect("", ctx)


class FakeCtx:
    """Context object passed to the plugin."""
    def __init__(self, path, engine, depth=0):
        self.path = path
        self.engine = engine
        self.depth = depth
        self.metadata = {}


@pytest.fixture
def plugin():
    return Plugin()


@pytest.fixture
def tmpfile():
    """Creates a temporary file path."""
    with tempfile.TemporaryDirectory() as d:
        yield d


def make_zip(path, files: dict):
    """files = { 'name': b'data', ... }"""
    with zipfile.ZipFile(path, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)


def make_tar(path, files: dict):
    with tarfile.open(path, "w") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))


def make_7z(path, files: dict):
    # Create a temporary directory with the files
    with tempfile.TemporaryDirectory() as tmpdir:
        for name, data in files.items():
            full = os.path.join(tmpdir, name)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "wb") as f:
                f.write(data)

        # Now create the 7z archive from that directory
        with py7zr.SevenZipFile(path, "w") as z:
            z.writeall(tmpdir, arcname="")

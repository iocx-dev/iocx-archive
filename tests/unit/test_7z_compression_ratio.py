import os
import types
import tempfile
from iocx_archive.plugin import Plugin
import iocx_archive.plugin as plugin_module


class FakeEngine:
    def __init__(self, plugin):
        self.plugin = plugin

    def analyze_file(self, path, depth=0):
        return []


class FakeCtx:
    def __init__(self, path, engine, depth=0):
        self.path = path
        self.engine = engine
        self.depth = depth


def test_7z_suspicious_compression_ratio(monkeypatch):
    plugin = Plugin()
    engine = FakeEngine(plugin)

    # Force archive type detection
    monkeypatch.setattr(plugin, "_detect_archive_type", lambda path: "7z")

    # Force enforce_limits() to allow processing
    monkeypatch.setattr(plugin.policy, "enforce_limits",
                        lambda state, size, det, name: "ok")

    # Fake info object with suspicious ratio
    class FakeInfo:
        uncompressed = plugin.policy.MAX_ENTRY_SIZE + 5000
        compressed = 10 # < 1024

    # Fake SevenZipFile instance
    class Fake7zFile:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def getnames(self):
            return ["evil.bin"]

        def getinfo(self, name):
            return FakeInfo()

        def extract(self, *a, **kw):
            pass

    # Inject fake py7zr module into plugin
    fake_py7zr = types.SimpleNamespace(SevenZipFile=Fake7zFile)
    monkeypatch.setattr(plugin_module, "py7zr", fake_py7zr)

    with tempfile.TemporaryDirectory() as tmp:
        fake_path = os.path.join(tmp, "dummy.7z")
        open(fake_path, "wb").close()

        ctx = FakeCtx(fake_path, engine)
        detections = plugin.detect("", ctx)

    assert any(
        d.value == "archive_suspicious_compression_ratio"
        for d in detections
    )

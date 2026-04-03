import pytest
from conftest import FakeEngine, FakeCtx, make_zip
from iocx_archive.plugin import Plugin

plugin = Plugin()


@pytest.mark.attacks
def test_unicode_normalization(tmp_path):
    path = tmp_path / "unicode.zip"

    # U+202E RIGHT-TO-LEFT OVERRIDE
    evil_name = "safe.txt\u202Eexe"

    make_zip(path, {evil_name: b"malicious"})

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    print("[security] unicode path normalization handled")

    assert any("exe" in d.metadata.get("entry_name", "") for d in detections)

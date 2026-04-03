import pytest
import zipfile
from conftest import FakeEngine, FakeCtx
from iocx_archive.plugin import Plugin

plugin = Plugin()


@pytest.mark.attacks
def test_zip_symlink_attack(tmp_path):
    path = tmp_path / "symlink.zip"

    with zipfile.ZipFile(path, "w") as z:
        z.writestr("../../evil.txt", b"owned")

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    print("[security] symlink/path traversal blocked")

    assert any(d.value == "archive_path_traversal_blocked" for d in detections)

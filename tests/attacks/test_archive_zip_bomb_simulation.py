import pytest
import zipfile
from conftest import FakeEngine, FakeCtx
from iocx_archive.plugin import Plugin

plugin = Plugin()


@pytest.mark.attacks
def test_zip_bomb_simulation(tmp_path):
    path = tmp_path / "bomb.zip"

    # Create a real “bomb-like” entry: huge uncompressed, small compressed
    data = b"A" * (plugin.policy.MAX_ENTRY_SIZE * 2)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("bomb.txt", data)

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    print("[bomb] simulated ZIP bomb detected")

    assert any(d.value == "archive_entry_size_limit_reached" for d in detections)

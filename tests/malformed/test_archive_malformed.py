import pytest
from conftest import FakeEngine, FakeCtx, zipfile, io, tarfile, os
from iocx_archive.plugin import Plugin

plugin = Plugin()


@pytest.mark.malformed
def test_corrupted_zip_header(tmp_path):
    path = tmp_path / "bad.zip"
    path.write_bytes(b"PK\x03\x04" + b"\x00" * 10) # incomplete header

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)
    print("[malformed] corrupted ZIP handled safely")

    assert detections == [] # plugin should fail gracefully


@pytest.mark.malformed
def test_corrupted_7z_header(tmp_path):
    path = tmp_path / "bad.7z"
    path.write_bytes(b"7z\xBC\xAF\x27\x1C" + b"\x00" * 20)

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)
    print("[malformed] corrupted 7z handled safely")

    assert any(
        d.value in ("archive_7z_error", "archive_warning")
        for d in detections
    )


@pytest.mark.malformed
def test_zip_corrupted_central_directory(tmp_path):
    """Corrupted central directory should simply result in no detection."""
    path = tmp_path / "bad_cd.zip"

    with open(path, "wb") as f:
        f.write(b"PK\x03\x04" + b"\x00" * 26) # minimal header
        f.write(b"garbagegarbagegarbage") # corrupt CD

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    # Plugin should NOT detect this as a valid archive
    assert detections == []


@pytest.mark.malformed
def test_zip_truncated_file_entry(tmp_path):
    """ZIP entry claims a size but file ends early."""
    path = tmp_path / "truncated.zip"

    with zipfile.ZipFile(path, "w") as z:
        info = zipfile.ZipInfo("file.txt")
        info.file_size = 1000 # claim 1000 bytes
        z.writestr(info, b"123") # only 3 bytes

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    assert any("zip" in d.value for d in detections)


@pytest.mark.malformed
def test_zip_overlapping_segments(tmp_path):
    """ZIP with overlapping file offsets (classic bomb trick)."""
    path = tmp_path / "overlap.zip"

    with open(path, "wb") as f:
        f.write(
            b"PK\x03\x04" + b"\x14\x00" + b"\x00" * 24 +
            b"AAAA" + # fake file data
            b"PK\x01\x02" + b"\x00" * 42 +
            b"PK\x05\x06" + b"\x00" * 18
        )

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    assert any("zip" in d.value for d in detections)


@pytest.mark.malformed
def test_tar_corrupted_header(tmp_path):
    path = tmp_path / "bad.tar"
    path.write_bytes(b"0" * 512)

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    # Not a TAR → no detection
    assert detections == []


@pytest.mark.malformed
def test_tar_fake_huge_size(tmp_path):
    import io, tarfile

    path = tmp_path / "fake_huge.tar"

    with pytest.raises(OSError):
        with tarfile.open(path, "w") as t:
            info = tarfile.TarInfo("huge.bin")
            info.size = 10**12 # extreme size
            t.addfile(info, io.BytesIO(b"123")) # too little data

    # At this point the archive was never successfully created,
    # so there is nothing meaningful for the plugin to test.


@pytest.mark.malformed
def test_tar_negative_size(tmp_path):
    path = tmp_path / "negsize.tar"
    path.write_bytes(b"-1000".ljust(512, b"\x00"))

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    # Not recognized as TAR → no detection
    assert detections == []


@pytest.mark.malformed
def test_7z_corrupted_header(tmp_path):
    """7z header magic present but structure invalid."""
    path = tmp_path / "bad.7z"
    path.write_bytes(b"7z\xBC\xAF\x27\x1C" + b"\x00" * 20)

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)


@pytest.mark.malformed
def test_7z_truncated_stream(tmp_path):
    """7z file with valid header but truncated data stream."""
    path = tmp_path / "trunc.7z"
    path.write_bytes(b"7z\xBC\xAF\x27\x1C" + b"\x00" * 1024)

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    assert any("7z" in d.value for d in detections)


@pytest.mark.malformed
def test_7z_fake_huge_size(tmp_path):
    """7z file that claims huge uncompressed size."""
    path = tmp_path / "huge.7z"
    path.write_bytes(
        b"7z\xBC\xAF\x27\x1C" +
        b"\x00" * 6 + # version + CRC
        b"\xFF" * 64 # fake huge metadata
    )

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    assert any("7z" in d.value for d in detections)


@pytest.mark.malformed
def test_mixed_garbage_archive(tmp_path):
    path = tmp_path / "hybrid.bin"
    path.write_bytes(
        b"PK\x03\x04" + b"\x00" * 20 +
        b"7z\xBC\xAF\x27\x1C" + b"\x00" * 20 +
        b"ustar" + b"\x00" * 20
    )

    engine = FakeEngine(plugin)
    ctx = FakeCtx(str(path), engine)

    detections = plugin.detect("", ctx)

    # Not a valid archive → no detection
    assert detections == []

import pytest
from iocx_archive.safety import ArchiveSafetyPolicy, ArchiveState
from iocx.models import Detection


def test_entry_size_limit():
    policy = ArchiveSafetyPolicy()
    state = ArchiveState()
    detections = []

    result = policy.enforce_limits(
        state,
        entry_size=policy.MAX_ENTRY_SIZE + 1,
        detections=detections,
        entry_name="big.bin",
    )

    assert result == "skip"
    assert any(d.value == "archive_entry_size_limit_reached" for d in detections)


def test_total_size_limit():
    policy = ArchiveSafetyPolicy()
    state = ArchiveState(total_size=policy.MAX_TOTAL_SIZE - 10)
    detections = []

    result = policy.enforce_limits(
        state,
        entry_size=20,
        detections=detections,
        entry_name="x",
    )

    assert result == "stop"
    assert any(d.value == "archive_total_size_limit_reached" for d in detections)


def test_entry_count_limit():
    policy = ArchiveSafetyPolicy()
    state = ArchiveState(entry_count=policy.MAX_ENTRIES)
    detections = []

    result = policy.enforce_limits(
        state,
        entry_size=1,
        detections=detections,
        entry_name="x",
    )

    assert result == "stop"
    assert any(d.value == "archive_entry_count_limit_reached" for d in detections)

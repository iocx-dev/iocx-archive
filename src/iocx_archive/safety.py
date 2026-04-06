from dataclasses import dataclass
from iocx.models import Detection


@dataclass
class ArchiveState:
    entry_count: int = 0
    total_size: int = 0


class ArchiveSafetyPolicy:
    """
    Centralised safety policy for all archive formats.
    ZIP, TAR, and 7z handlers call enforce_limits() to apply
    entry count, total size, and per-entry size rules.
    """

    MAX_ENTRY_SIZE = 50 * 1024 * 1024 # 50 MB
    MAX_TOTAL_SIZE = 200 * 1024 * 1024 # 200 MB
    MAX_ENTRIES = 500
    MAX_DEPTH = 5

    def enforce_limits(self, state: ArchiveState, entry_size: int, detections, entry_name: str):
        """
        Returns:
            "ok" → safe to extract
            "skip" → skip this entry
            "stop" → stop processing archive entirely
        """

        # Entry count limit
        if state.entry_count >= self.MAX_ENTRIES:
            detections.append(
                Detection(
                    category="archive_warning",
                    value="archive_entry_count_limit_reached",
                    metadata={"max_entries": self.MAX_ENTRIES},
                    start=0,
                    end=0,
                )
            )
            return "stop"

        # Update counters
        state.entry_count += 1
        state.total_size += entry_size

        # Total size limit
        if state.total_size > self.MAX_TOTAL_SIZE:
            detections.append(
                Detection(
                    category="archive_warning",
                    value="archive_total_size_limit_reached",
                    metadata={"total_size": state.total_size},
                    start=0,
                    end=0,
                )
            )
            return "stop"

        # Per-entry size limit
        if entry_size > self.MAX_ENTRY_SIZE:
            detections.append(
                Detection(
                    category="archive_warning",
                    value="archive_entry_size_limit_reached",
                    metadata={"entry_name": entry_name, "size": entry_size},
                    start=0,
                    end=0,
                )
            )
            return "skip"

        return "ok"

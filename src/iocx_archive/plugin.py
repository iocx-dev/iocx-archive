import os
import zipfile
import tarfile
import tempfile
from typing import List, Optional

from iocx.plugins.api import IOCXPlugin
from iocx.plugins.metadata import PluginMetadata
from iocx.models import Detection, PluginContext
from .safety import ArchiveSafetyPolicy, ArchiveState

try:
    import py7zr
except ImportError:
    py7zr = None


class Plugin(IOCXPlugin):
    """
    IOCX Archive Plugin
    -------------------
    Safely detects and extracts archives (zip, tar, 7z), then feeds extracted
    files back into the IOCX engine for recursive static analysis.
    """

    # Default safety limits
    MAX_DEPTH = 3
    MAX_ENTRY_SIZE = 50 * 1024 * 1024 # 50 MB
    MAX_TOTAL_SIZE = 500 * 1024 * 1024 # 500 MB
    MAX_ENTRIES = 1000

    metadata = PluginMetadata(
        id="iocx-archive",
        name="Archive Detector",
        version="1.0.0",
        description="Archive detector for IOCX (zip, tar, 7z) with safety limits",
        author="MalX Labs",
        capabilities=["detector"],
        iocx_min_version="0.4.0",
    )

    def __init__(self):
        super().__init__()
        self.policy = ArchiveSafetyPolicy()

    def detect(self, text: str, ctx: PluginContext) -> List[Detection]:
        detections: List[Detection] = []

        path = getattr(ctx, "path", None)
        if not path or not os.path.isfile(path):
            return detections

        archive_type = self._detect_archive_type(path)
        if not archive_type:
            return detections

        detections.append(
            Detection(
                category="archive",
                value=f"{archive_type}_archive",
                metadata={
                    "archive_type": archive_type,
                    "depth": getattr(ctx, "depth", 0),
                },
                start=0,
                end=0,
            )
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            self._extract_and_analyze(
                path=path,
                archive_type=archive_type,
                tmpdir=tmpdir,
                ctx=ctx,
                detections=detections,
                depth=getattr(ctx, "depth", 0),
            )

        return detections

    # ----------------------------------------------------------------------
    # Archive Detection
    # ----------------------------------------------------------------------

    def _is_tar_safely(self, path: str):
        try:
            return tarfile.is_tarfile(path)
        except Exception:
            return "error"

    def _detect_archive_type(self, path: str) -> Optional[str]:
        if zipfile.is_zipfile(path):
            return "zip"

        tar_check = self._is_tar_safely(path)
        if tar_check is True:
            return "tar"
        elif tar_check == "error":
            return "tar_error"

        if py7zr and py7zr.is_7zfile(path):
            return "7z"

        return None

    # ----------------------------------------------------------------------
    # Extraction + Recursion
    # ----------------------------------------------------------------------

    def _extract_and_analyze(self, path, archive_type, tmpdir, ctx, detections, depth):
        if depth >= self.MAX_DEPTH:
            detections.append(
                Detection(
                    category="archive_warning",
                    value="archive_max_depth_reached",
                    metadata={"depth": depth, "max_depth": self.MAX_DEPTH},
                    start=0,
                    end=0,
                )
            )
            return

        if archive_type == "zip":
            self._handle_zip(path, tmpdir, ctx, detections, depth)

        elif archive_type == "tar":
            self._handle_tar(path, tmpdir, ctx, detections, depth)

        elif archive_type == "tar_error":
            detections.append(
                Detection(
                    category="archive_warning",
                    value="archive_tar_error",
                    metadata={"path": path},
                    start=0,
                    end=0,
                )
            )
            return

        elif archive_type == "7z":
            self._handle_7z(path, tmpdir, ctx, detections, depth)

    # ----------------------------------------------------------------------
    # ZIP Handling
    # ----------------------------------------------------------------------

    def _handle_zip(self, path, tmpdir, ctx, detections, depth):
        state = ArchiveState()

        with zipfile.ZipFile(path, "r") as zf:
            for info in zf.infolist():

                if info.is_dir():
                    continue

                # Unified limits
                result = self.policy.enforce_limits(state, info.file_size, detections, info.filename)
                if result == "stop":
                    break
                if result == "skip":
                    continue

                # ZIP bomb heuristic
                uncompressed = info.file_size
                compressed = getattr(info, "compress_size", 0)

                if compressed < 1024 and uncompressed > self.policy.MAX_ENTRY_SIZE:
                    detections.append(
                        Detection(
                            category="archive_warning",
                            value="archive_entry_size_limit_reached",
                            metadata={
                                "entry_name": info.filename,
                                "declared_size": uncompressed,
                                "compressed_size": compressed,
                            },
                            start=0,
                            end=0,
                        )
                    )
                    continue

                # Path safety
                safe_path = self._safe_join(tmpdir, info.filename)
                if not safe_path:
                    detections.append(
                        Detection(
                            category="archive_warning",
                            value="archive_path_traversal_blocked",
                            metadata={"entry_name": info.filename},
                            start=0,
                            end=0,
                        )
                    )
                    continue

                # Extract safely
                zf.extract(info, path=tmpdir)

                # Recurse
                detections.extend(
                    self._analyze_extracted_file(safe_path, ctx, depth + 1)
                )

                detections.append(
                    Detection(
                        category="archive_info",
                        value="archive_entry_extracted",
                        metadata={"entry_name": info.filename},
                        start=0,
                        end=0,
                    )
                )

    # ----------------------------------------------------------------------
    # TAR Handling
    # ----------------------------------------------------------------------

    def _handle_tar(self, path, tmpdir, ctx, detections, depth):
        state = ArchiveState()

        try:
            with tarfile.open(path, "r:*") as tf:
                for member in tf:

                    if not member.isfile():
                        continue

                    # Unified limits
                    result = self.policy.enforce_limits(state, member.size, detections, member.name)
                    if result == "stop":
                        break
                    if result == "skip":
                        continue

                    # Path safety
                    safe_path = self._safe_join(tmpdir, member.name)
                    if not safe_path:
                        detections.append(
                            Detection(
                                category="archive_warning",
                                value="archive_path_traversal_blocked",
                                metadata={"entry_name": member.name},
                                start=0,
                                end=0,
                            )
                        )
                        continue

                    # Extract safely
                    tf.extract(member, path=tmpdir)

                    # Recurse
                    detections.extend(
                        self._analyze_extracted_file(safe_path, ctx, depth + 1)
                    )

                    detections.append(
                        Detection(
                            category="archive_info",
                            value="archive_entry_extracted",
                            metadata={"entry_name": member.name},
                            start=0,
                            end=0,
                        )
                    )

        except Exception:
            detections.append(
                Detection(
                    category="archive_warning",
                    value="archive_tar_error",
                    metadata={"path": path},
                    start=0,
                    end=0,
                )
            )

    # ----------------------------------------------------------------------
    # 7z Handling
    # ----------------------------------------------------------------------

    def _handle_7z(self, path, tmpdir, ctx, detections, depth):
        if not py7zr:
            detections.append(
                Detection(
                    category="archive_warning",
                    value="archive_7z_unsupported",
                    metadata={"path": path},
                    start=0,
                    end=0,
                )
            )
            return

        state = ArchiveState()

        try:
            with py7zr.SevenZipFile(path, mode="r") as z:
                members = z.getnames()

                for name in members:

                    # Try to get metadata
                    try:
                        info = z.getinfo(name)
                        uncompressed = getattr(info, "uncompressed", None)
                        compressed = getattr(info, "compressed", None)
                    except Exception:
                        uncompressed = None
                        compressed = None

                    # Unknown size → treat as unsafe (fail-safe)
                    entry_size = uncompressed if uncompressed is not None else (self.policy.MAX_ENTRY_SIZE + 1)

                    # Unified limits
                    result = self.policy.enforce_limits(state, entry_size, detections, name)
                    if result == "stop":
                        break
                    if result == "skip":
                        continue

                    # Compression ratio heuristic (if metadata available)
                    if compressed is not None and uncompressed is not None:
                        if compressed < 1024 and uncompressed > self.policy.MAX_ENTRY_SIZE:
                            detections.append(
                                Detection(
                                    category="archive_warning",
                                    value="archive_entry_size_limit_reached",
                                    metadata={
                                        "entry_name": name,
                                        "declared_size": uncompressed,
                                        "compressed_size": compressed,
                                    },
                                    start=0,
                                    end=0,
                                )
                            )
                            continue

                    # Path safety
                    safe_path = self._safe_join(tmpdir, name)
                    if not safe_path:
                        detections.append(
                            Detection(
                                category="archive_warning",
                                value="archive_path_traversal_blocked",
                                metadata={"entry_name": name},
                                start=0,
                                end=0,
                            )
                        )
                        continue

                    # Extract only this member
                    z.extract(targets=[name], path=tmpdir)

                    # Recurse
                    detections.extend(
                        self._analyze_extracted_file(safe_path, ctx, depth + 1)
                    )

                    detections.append(
                        Detection(
                            category="archive_info",
                            value="archive_entry_extracted",
                            metadata={"entry_name": name},
                            start=0,
                            end=0,
                        )
                    )

        except Exception:
            detections.append(
                Detection(
                    category="archive_warning",
                    value="archive_7z_error",
                    metadata={"path": path},
                    start=0,
                    end=0,
                )
            )

    # ----------------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------------

    def _safe_join(self, root: str, name: str) -> Optional[str]:
        joined = os.path.normpath(os.path.join(root, name))
        root_abs = os.path.abspath(root)
        if not os.path.abspath(joined).startswith(root_abs):
            return None
        return joined

    def _analyze_extracted_file(self, path: str, ctx, depth: int) -> List[Detection]:
        if not hasattr(ctx, "engine"):
            return []
        return ctx.engine.analyze_file(path, depth=depth)

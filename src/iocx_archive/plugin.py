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

    metadata = PluginMetadata(
        id="iocx-archive",
        name="Archive Detector",
        version="1.0.0",
        description="Archive detector for IOCX (zip, tar, 7z) with safety limits",
        author="MalX Labs",
        capabilities=["detector"],
        iocx_min_version="0.4.0",
    )

    # Recursion depth is a plugin-level concern
    MAX_DEPTH = 3

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

        depth = getattr(ctx, "depth", 0)

        detections.append(
            Detection(
                category="archive",
                value=f"{archive_type}_archive",
                metadata={"archive_type": archive_type, "depth": depth},
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
                depth=depth,
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

    def _extract_and_analyze(
        self, path, archive_type, tmpdir, ctx, detections, depth
    ):
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
        elif archive_type == "7z":
            self._handle_7z(path, tmpdir, ctx, detections, depth)
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

    # ----------------------------------------------------------------------
    # ZIP Handling
    # ----------------------------------------------------------------------

    def _handle_zip(self, path, tmpdir, ctx, detections, depth):
        state = ArchiveState()
        try:
            with zipfile.ZipFile(path, "r") as zf:
                for info in zf.infolist():
                    if info.is_dir():
                        continue

                    entry_size = info.file_size

                    result = self.policy.enforce_limits(
                        state, entry_size, detections, info.filename
                    )
                    if result == "stop":
                        break
                    if result == "skip":
                        continue

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

                    # ensure directories exist
                    os.makedirs(os.path.dirname(safe_path), exist_ok=True)

                    try:
                        with zf.open(info, "r") as src, open(safe_path, "wb") as dst:
                            dst.write(src.read())
                    except Exception:
                        detections.append(
                            Detection(
                                category="archive_warning",
                                value="archive_zip_entry_error",
                                metadata={"entry_name": info.filename},
                                start=0,
                                end=0,
                            )
                        )
                        continue

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
        except Exception:
            detections.append(
                Detection(
                    category="archive_warning",
                    value="archive_zip_error",
                    metadata={"path": path},
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

                    entry_size = member.size

                    result = self.policy.enforce_limits(
                        state, entry_size, detections, member.name
                    )
                    if result == "stop":
                        break
                    if result == "skip":
                        continue

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

                    # ensure directories exist
                    os.makedirs(os.path.dirname(safe_path), exist_ok=True)

                    try:
                        f = tf.extractfile(member)
                        if not f:
                            detections.append(
                                Detection(
                                    category="archive_warning",
                                    value="archive_tar_entry_error",
                                    metadata={"entry_name": member.name},
                                    start=0,
                                    end=0,
                                )
                            )
                            continue
                        with f, open(safe_path, "wb") as out:
                            out.write(f.read())
                    except Exception:
                        detections.append(
                            Detection(
                                category="archive_warning",
                                value="archive_tar_entry_error",
                                metadata={"entry_name": member.name},
                                start=0,
                                end=0,
                            )
                        )
                        continue

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
                    try:
                        info = z.getinfo(name)
                        uncompressed = getattr(info, "uncompressed", None)
                        compressed = getattr(info, "compressed", None)
                    except Exception:
                        uncompressed = None
                        compressed = None

                    # Unknown size → treat as unsafe (fail-safe)
                    entry_size = (
                        uncompressed
                        if uncompressed is not None
                        else (self.policy.MAX_ENTRY_SIZE + 1)
                    )

                    result = self.policy.enforce_limits(
                        state, entry_size, detections, name
                    )
                    if result == "stop":
                        break
                    if result == "skip":
                        continue

                    if (
                        compressed is not None
                        and uncompressed is not None
                        and compressed < 1024
                        and uncompressed > self.policy.MAX_ENTRY_SIZE
                    ):
                        detections.append(
                            Detection(
                                category="archive_warning",
                                value="archive_suspicious_compression_ratio",
                                metadata={
                                    "entry_name": name,
                                    "compressed": compressed,
                                    "uncompressed": uncompressed,
                                    "ratio": float(uncompressed / max(1, compressed)),
                                },
                                start=0,
                                end=0,
                            )
                        )

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

                    # ensure directories exist
                    os.makedirs(os.path.dirname(safe_path), exist_ok=True)

                    try:
                        z.extract(targets=[name], path=tmpdir)
                    except Exception:
                        detections.append(
                            Detection(
                                category="archive_warning",
                                value="archive_7z_entry_error",
                                metadata={"entry_name": name},
                                start=0,
                                end=0,
                            )
                        )
                        continue

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

    def _safe_join(self, base: str, *paths: str) -> Optional[str]:
        candidate = os.path.normpath(os.path.join(base, *paths))
        base_norm = os.path.normpath(base)
        if os.path.commonprefix([candidate, base_norm]) != base_norm:
            return None
        return candidate

    def _analyze_extracted_file(
        self, path: str, ctx: PluginContext, depth: int
    ) -> List[Detection]:
        return ctx.engine.analyze_file(path, depth=depth)

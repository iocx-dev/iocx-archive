import pytest
import concurrent.futures
from conftest import FakeEngine, FakeCtx, make_zip
from iocx_archive.plugin import Plugin

plugin = Plugin()


@pytest.mark.stress
def test_parallel_extraction(tmp_path):
    """Run 20 parallel extractions to ensure no shared-state issues."""
    paths = []
    for i in range(20):
        p = tmp_path / f"c{i}.zip"
        make_zip(p, {f"f{i}.txt": b"x"})
        paths.append(p)

    def run(path):
        engine = FakeEngine(plugin)
        ctx = FakeCtx(str(path), engine)
        plugin.detect("", ctx)
        return True

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(run, paths))

    print("[concurrency] parallel extraction OK")

    assert all(results)

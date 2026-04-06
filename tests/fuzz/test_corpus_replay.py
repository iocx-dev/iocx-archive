import glob, pytest, os
from iocx_archive.plugin import Plugin
from conftest import make_zip, FakeEngine, FakeCtx


@pytest.mark.fuzz
def test_chaos_corpus_does_not_crash():
    plugin = Plugin()
    engine = FakeEngine(plugin)

    for path in glob.glob("chaos_corpus/**/*", recursive=True):
        if not os.path.isfile(path):
            continue
        ctx = FakeCtx(path, engine)
        plugin.detect("", ctx)

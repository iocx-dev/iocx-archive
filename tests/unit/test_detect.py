from iocx_archive.plugin import Plugin


class FakeEngine:
    def __init__(self, plugin):
        self.plugin = plugin

    def analyze_file(self, path, depth=0):
        return []


class FakeCtx:
    # No path attribute at all
    def __init__(self, engine, depth=0):
        self.engine = engine
        self.depth = depth


def test_detect_returns_empty_when_no_path():
    plugin = Plugin()
    engine = FakeEngine(plugin)

    ctx = FakeCtx(engine)

    detections = plugin.detect("", ctx)

    assert detections == []

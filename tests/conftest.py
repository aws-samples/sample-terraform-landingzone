# =============================================================================
# Shared pytest configuration for the test suite
# =============================================================================
#
# Registers the `live` marker and keeps live tests out of every run that does
# not ask for them. Live tests (tests/live/) talk to real AWS accounts and
# require credentials plus a local account allowlist; a full-suite run
# (`pytest tests/`) must behave exactly as it did before they existed, so
# live-marked items are deselected — not skipped — in mixed runs.
#
# Selection rules:
#   * `pytest -m live tests/live/`  → live tests run (strict, fail-closed
#                                     guard in tests/live/conftest.py)
#   * `pytest tests/`               → live tests deselected, all counts of
#                                     the existing suite stay unchanged
#   * a path whose collection is PURELY live-marked (for example
#     `pytest tests/live/test_live_probes.py`, 3 collected / 0 deselected)
#     → items stay selected and skip with a reason when credentials or the
#     allowlist are missing.
#   * `pytest tests/live/` is NOT that case any more and has not been since
#     offline tests live under tests/live/: it collects the offline items and
#     DESELECTS the live-marked ones, because the rule below sees a mixed
#     collection. `pytest tests/live/probes/` likewise. Use `-m live` to run
#     them; the directory is not a pure live run.
#
# The project has no pytest.ini/pyproject.toml (the repository root only
# permits a pinned set of meta-files), so marker registration and default
# deselection both live here.


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "live: test runs against real AWS accounts "
        "(requires local account allowlist and valid credentials)",
    )


def pytest_collection_modifyitems(config, items):
    markexpr = config.getoption("-m", default="") or ""
    if "live" in markexpr:
        # The caller expressed intent about live tests; -m handles selection.
        return
    live_items = [item for item in items if item.get_closest_marker("live")]
    if not live_items or len(live_items) == len(items):
        # No live tests collected, or a pure live run (pytest tests/live/):
        # leave selection alone — the live conftest skips without credentials.
        return
    kept = [item for item in items if item.get_closest_marker("live") is None]
    config.hook.pytest_deselected(items=live_items)
    items[:] = kept

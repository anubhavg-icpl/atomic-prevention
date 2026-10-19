from backend.app.api.routes.sources import _build_test_ids


def test_colliding_truncated_commands_get_distinct_stable_ids():
    prefix = "x" * 220
    tests = [
        {"name": "same", "command": prefix + "one"},
        {"name": "same", "command": prefix + "two"},
    ]
    first = _build_test_ids("fixture", tests)
    second = _build_test_ids("fixture", tests)
    assert first == second
    assert len(set(first)) == 2

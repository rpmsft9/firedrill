import pytest
import yaml

from firedrill.events import make_event
from firedrill.sigma import RuleError, RuleSet, parse_documents


def ruleset(text: str) -> RuleSet:
    return RuleSet(*parse_documents(yaml.safe_load_all(text), "test.yml"))


def event(time: float = 0, **attributes):
    return make_event(time=time, attributes=attributes, span_id=f"s{time}")


def fires(text: str, *events) -> bool:
    return bool(ruleset(text).evaluate(events))


RULE = """
title: t
detection:
  sel:
    {key}: {value}
  condition: sel
"""


@pytest.mark.parametrize(
    "key, value, field, expected",
    [
        ("tool", "shell", "shell", True),
        ("tool", "shell", "SHELL", True),  # case-insensitive by default
        ("tool|cased", "shell", "SHELL", False),
        ("tool", "sh*", "shell", True),
        ("tool", "sh?ll", "shell", True),
        ("tool", "sh", "shell", False),  # exact match is anchored
        ("tool|contains", "hel", "shell", True),
        ("tool|startswith", "she", "shell", True),
        ("tool|startswith", "ell", "shell", False),
        ("tool|endswith", "ell", "shell", True),
        ("tool|endswith", "she", "shell", False),
        ("tool|re", "'^sh.ll$'", "shell", True),
        ("tool|re", "'^SH'", "shell", False),  # regex is case-sensitive
        ("tool|re|i", "'^SH'", "shell", True),
        ("tool|contains", "[a, hel]", "shell", True),  # list is OR
        ("tool|contains|all", "[a, hel]", "shell", False),
        ("tool|contains|all", "[s, hel]", "shell", True),
        ("tool|gte", "5", 5, True),
        ("tool|gt", "5", 5, False),
        ("tool|lt", "5", "not a number", False),
        ("tool|exists", "true", "x", True),
        ("other|exists", "true", "x", False),
        ("other|exists", "false", "x", True),
        ("other", "null", "x", True),  # null matches an absent field
    ],
)
def test_field_matching(key, value, field, expected):
    assert fires(RULE.format(key=key, value=value), event(tool=field)) is expected


def test_wildcards_can_be_escaped():
    text = RULE.format(key="tool", value="'a\\*b'")
    assert fires(text, event(tool="a*b"))
    assert not fires(text, event(tool="axb"))


def test_keyword_list_searches_every_field():
    text = "title: t\ndetection:\n  keywords:\n    - needle\n  condition: keywords\n"
    assert fires(text, event(a="hay", b="a NEEDLE here"))
    assert not fires(text, event(a="hay"))


CONDITION = """
title: t
detection:
  sel_a: {{ a: 1 }}
  sel_b: {{ b: 1 }}
  filter: {{ c: 1 }}
  condition: {condition}
"""


@pytest.mark.parametrize(
    "condition, attributes, expected",
    [
        ("sel_a and sel_b", {"a": 1}, False),
        ("sel_a and sel_b", {"a": 1, "b": 1}, True),
        ("sel_a or sel_b", {"b": 1}, True),
        ("sel_a and not filter", {"a": 1, "c": 1}, False),
        ("sel_a and not filter", {"a": 1}, True),
        ("1 of sel_*", {"b": 1}, True),
        ("all of sel_*", {"b": 1}, False),
        ("all of sel_*", {"a": 1, "b": 1}, True),
        ("1 of them", {"c": 1}, True),
        ("(sel_a or sel_b) and not filter", {"b": 1, "c": 1}, False),
        ("not (sel_a or sel_b)", {"c": 1}, True),
        # `and` binds tighter than `or`
        ("sel_a or sel_b and filter", {"a": 1}, True),
    ],
)
def test_conditions(condition, attributes, expected):
    assert fires(CONDITION.format(condition=condition), event(**attributes)) is expected


@pytest.mark.parametrize(
    "text",
    [
        RULE.format(key="tool|base64", value="x"),  # unsupported modifier
        RULE.format(key="tool|re", value="'('"),  # bad regex
        RULE.format(key="tool|gt", value="abc"),
        CONDITION.format(condition="sel_a and nope"),
        CONDITION.format(condition="sel_a and"),
        CONDITION.format(condition="(sel_a"),
        CONDITION.format(condition="1 of nothing_*"),
        "title: t\ndetection:\n  sel: { a: 1 }\n",  # no condition
        "detection:\n  sel: { a: 1 }\n  condition: sel\n",  # no title
        "title: t\nfoo: bar\n",
    ],
)
def test_unsupported_or_malformed_rules_fail_loudly(text):
    with pytest.raises(RuleError):
        ruleset(text)


BASES = """
title: stage one
name: one
detection: { sel: { step: 1 }, condition: sel }
---
title: stage two
name: two
detection: { sel: { step: 2 }, condition: sel }
---
"""


def correlation(body: str) -> str:
    return BASES + "title: corr\ncorrelation:\n" + body


ORDERED = correlation("  type: temporal_ordered\n  rules: [one, two]\n  group-by: [conv]\n  timespan: 1m\n")


def test_temporal_ordered_needs_order_group_and_window():
    assert fires(ORDERED, event(0, step=1, conv="a"), event(10, step=2, conv="a"))
    assert not fires(ORDERED, event(0, step=2, conv="a"), event(10, step=1, conv="a"))
    assert not fires(ORDERED, event(0, step=1, conv="a"), event(10, step=2, conv="b"))
    assert not fires(ORDERED, event(0, step=1, conv="a"), event(90, step=2, conv="a"))


def test_temporal_ordered_restarts_from_a_later_first_stage():
    # The first stage-one event is too old; the second one is in range.
    events = [event(0, step=1, conv="a"), event(80, step=1, conv="a"), event(100, step=2, conv="a")]
    alerts = ruleset(ORDERED).evaluate(events)
    assert [alert.span_ids for alert in alerts] == [("s80", "s100")]


def test_temporal_ignores_order():
    text = correlation("  type: temporal\n  rules: [one, two]\n  timespan: 1m\n")
    assert fires(text, event(0, step=2), event(10, step=1))
    assert not fires(text, event(0, step=2), event(100, step=1))
    assert not fires(text, event(0, step=1), event(10, step=1))


def test_event_count_uses_a_sliding_window():
    text = correlation("  type: event_count\n  rules: [one]\n  timespan: 10s\n  condition: { gte: 3 }\n")
    assert fires(text, *(event(t, step=1) for t in (0, 4, 8)))
    assert not fires(text, *(event(t, step=1) for t in (0, 8, 16)))
    assert fires(text, *(event(t, step=1) for t in (0, 30, 34, 38)))


def test_value_count_counts_distinct_values():
    text = correlation(
        "  type: value_count\n  rules: [one]\n  timespan: 1m\n  condition: { field: agent, gte: 2 }\n"
    )
    assert fires(text, event(0, step=1, agent="a"), event(1, step=1, agent="b"))
    assert not fires(text, event(0, step=1, agent="a"), event(1, step=1, agent="a"))
    assert not fires(text, event(0, step=1), event(1, step=1, agent="a"))  # absent is not a value


def test_base_rules_are_silent_unless_generate_is_set():
    silent = ruleset(ORDERED)
    assert silent.evaluate([event(0, step=1, conv="a")]) == []
    assert [rule.title for rule in silent.alerting] == ["corr"]
    loud = ruleset(ORDERED + "  generate: true\n")
    assert [alert.title for alert in loud.evaluate([event(0, step=1, conv="a")])] == ["stage one"]


@pytest.mark.parametrize(
    "body",
    [
        "  type: sequence\n  rules: [one]\n  timespan: 1m\n",
        "  type: temporal\n  rules: [missing]\n  timespan: 1m\n",
        "  type: temporal\n  rules: [one]\n",
        "  type: temporal\n  rules: [one]\n  timespan: soon\n",
        "  type: event_count\n  rules: [one]\n  timespan: 1m\n  condition: { lte: 3 }\n",
        "  type: value_count\n  rules: [one]\n  timespan: 1m\n  condition: { gte: 3 }\n",
    ],
)
def test_bad_correlations_fail_loudly(body):
    with pytest.raises(RuleError):
        ruleset(correlation(body))


def test_duplicate_rule_names_are_rejected():
    with pytest.raises(RuleError):
        ruleset(BASES + BASES)

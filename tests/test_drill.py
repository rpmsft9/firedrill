import json
from pathlib import Path

import pytest

from firedrill import report
from firedrill.atomics import AtomicError, load_atomics, parse_atomic
from firedrill.cli import DEFAULT_ATOMICS, DEFAULT_RULES, main
from firedrill.events import load_events, to_otlp
from firedrill.runner import COVERED, MISSED, NOISY, run_drill
from firedrill.sigma import load_rules
from firedrill.taxonomy import MITRE_ATLAS, OWASP_ASI

NAIVE_RULES = Path(__file__).parent.parent / "examples" / "naive-rules"


@pytest.fixture(scope="module")
def atomics():
    return load_atomics(DEFAULT_ATOMICS)


@pytest.fixture(scope="module")
def starter(atomics):
    return run_drill(load_rules([DEFAULT_RULES]), atomics)


def test_library_covers_every_asi_category(atomics):
    assert {atomic.primary_asi for atomic in atomics} == set(OWASP_ASI)


def test_starter_pack_outcome(starter):
    outcomes = {result.atomic.id: result.outcome for result in starter.results}
    assert {id for id, outcome in outcomes.items() if outcome == MISSED} == {"FD-ASI07-001", "FD-ASI09-001"}
    assert NOISY not in outcomes.values()
    assert starter.count(COVERED) == 15
    assert starter.benign_alerting == 0
    assert starter.unexercised == ()


def test_naive_pack_detects_but_cannot_separate_benign(atomics):
    drill = run_drill(load_rules([NAIVE_RULES]), atomics)
    assert drill.count(COVERED) == 0
    assert drill.count(NOISY) == 7
    assert drill.coverage == 0.0
    assert drill.detection_rate == pytest.approx(100 * 7 / 17)


def test_rule_tags_reference_real_framework_ids():
    for rule in load_rules([DEFAULT_RULES]).alerting:
        for tag in rule.tags:
            namespace, _, value = tag.partition(".")
            if namespace == "owasp-asi":
                assert value.upper() in OWASP_ASI, tag
            elif namespace == "atlas":
                assert value.upper() in MITRE_ATLAS, tag
            else:
                pytest.fail(f"unexpected tag namespace: {tag}")


def test_unexercised_rules_are_reported(atomics):
    ruleset = load_rules([DEFAULT_RULES])
    drill = run_drill(ruleset, [a for a in atomics if a.primary_asi != "ASI05"])
    assert set(drill.unexercised) == {
        "Agent piped downloaded or decoded content into an interpreter",
        "Agent opened a reverse shell",
    }


def test_traces_are_deterministic(atomics):
    again = load_atomics(DEFAULT_ATOMICS)
    assert [a.attack for a in atomics] == [a.attack for a in again]


def test_otlp_round_trip_preserves_detections(atomics, tmp_path):
    ruleset = load_rules([DEFAULT_RULES])
    for atomic in atomics:
        path = tmp_path / f"{atomic.id}.json"
        path.write_text(json.dumps(to_otlp(atomic.attack)), encoding="utf-8")
        replayed = ruleset.evaluate(load_events(path))
        direct = ruleset.evaluate(atomic.attack)
        assert [a.title for a in replayed] == [a.title for a in direct], atomic.id


def test_json_lines_trace_is_loaded(tmp_path):
    path = tmp_path / "trace.jsonl"
    spans = [
        {"time": "2026-01-01T00:00:05Z", "span_id": "b", "attributes": {"gen_ai.operation.name": "chat"}},
        {"time": "2026-01-01T00:00:00Z", "span_id": "a",
         "attributes": {"gen_ai.tool.call.arguments": {"path": "x"}}},
    ]
    path.write_text("\n".join(json.dumps(span) for span in spans), encoding="utf-8")
    events = load_events(path)
    assert [event.get("span_id") for event in events] == ["a", "b"]  # sorted by time
    assert events[0].get("gen_ai.tool.call.arguments") == '{"path": "x"}'


@pytest.mark.parametrize(
    "change",
    [
        {"owasp_asi": ["ASI99"]},
        {"atlas": ["AML.T9999"]},
        {"severity": "apocalyptic"},
        {"attack": []},
        {"benign": [{"at": 0}]},
        {"name": ""},
    ],
)
def test_malformed_atomics_are_rejected(change):
    span = {"attrs": {"gen_ai.operation.name": "chat"}}
    doc = {"id": "X-1", "name": "n", "description": "d", "owasp_asi": ["ASI01"],
           "attack": [span], "benign": [span], **change}
    with pytest.raises(AtomicError):
        parse_atomic(doc, "test.yml")


def test_reports_render(starter):
    assert "Coverage 88.2% (15/17 covered)" in report.to_text(starter)
    assert "| ASI07 | Insecure Inter-Agent Communication | 1 | 0 | 0 | 1 |" in report.to_markdown(starter)
    payload = json.loads(report.to_json(starter))
    assert payload["summary"]["missed"] == 2
    assert payload["atlas"]["AML.T0086"] == COVERED


def test_cli_gates(capsys, tmp_path):
    assert main(["run"]) == 0
    assert main(["run", "--min-coverage", "80", "--max-noisy", "0"]) == 0
    assert main(["run", "--min-coverage", "95"]) == 1
    assert main(["run", "--max-missed", "1"]) == 1
    assert main(["run", "--rules", str(NAIVE_RULES), "--max-noisy", "0"]) == 1
    assert "GATE FAILED" in capsys.readouterr().err

    markdown = tmp_path / "report.md"
    assert main(["run", "--md", str(markdown)]) == 0
    assert markdown.read_text(encoding="utf-8").startswith("## firedrill detection coverage")


def test_cli_export_then_scan(capsys, tmp_path):
    trace = tmp_path / "attack.json"
    assert main(["export", "FD-ASI05-002", "--out", str(trace)]) == 0
    assert main(["scan", str(trace), "--fail-on-alert"]) == 1
    assert "Agent opened a reverse shell" in capsys.readouterr().out

    benign = tmp_path / "benign.json"
    assert main(["export", "FD-ASI05-002", "--benign", "--out", str(benign)]) == 0
    assert main(["scan", str(benign), "--fail-on-alert"]) == 0
    assert main(["export", "FD-NOPE-000"]) == 2


def test_cli_reports_errors_without_a_traceback(capsys, tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("title: t\ndetection:\n  sel: { 'a|base64': x }\n  condition: sel\n", encoding="utf-8")
    assert main(["check-rules", "--rules", str(bad)]) == 2
    assert "unsupported modifier 'base64'" in capsys.readouterr().err
    assert main(["scan", str(tmp_path / "missing.json")]) == 2
    assert main(["check-rules"]) == 0
    assert main(["list"]) == 0

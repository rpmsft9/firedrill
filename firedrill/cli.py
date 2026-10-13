"""Command line: `firedrill run | list | scan | export | check-rules`."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, report
from .atomics import AtomicError, load_atomics
from .events import load_events, to_otlp
from .runner import MISSED, NOISY, run_drill
from .sigma import RuleError, load_rules

PACKAGE_DIR = Path(__file__).parent
DEFAULT_RULES = PACKAGE_DIR / "rules"
DEFAULT_ATOMICS = PACKAGE_DIR / "atomics"


def _rules(args: argparse.Namespace):
    return load_rules(args.rules or [DEFAULT_RULES])


def cmd_run(args: argparse.Namespace) -> int:
    drill = run_drill(_rules(args), load_atomics(args.atomics))
    print(report.to_json(drill) if args.json else report.to_text(drill, verbose=args.verbose))
    markdown = report.to_markdown(drill)
    if args.md:
        Path(args.md).write_text(markdown, encoding="utf-8")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(markdown)

    failures = []
    if args.min_coverage is not None and drill.coverage < args.min_coverage:
        failures.append(f"coverage {drill.coverage:.1f}% is below the {args.min_coverage:g}% gate")
    if args.max_noisy is not None and drill.count(NOISY) > args.max_noisy:
        failures.append(f"{drill.count(NOISY)} noisy detections exceed the limit of {args.max_noisy}")
    if args.max_missed is not None and drill.count(MISSED) > args.max_missed:
        failures.append(f"{drill.count(MISSED)} missed atomics exceed the limit of {args.max_missed}")
    for failure in failures:
        print(f"GATE FAILED: {failure}", file=sys.stderr)
    return 1 if failures else 0


def cmd_list(args: argparse.Namespace) -> int:
    for atomic in load_atomics(args.atomics):
        mapping = ", ".join(atomic.asi + atomic.atlas)
        print(f"{atomic.id:<14}{atomic.severity:<10}{atomic.name}")
        print(f"{'':14}{mapping}")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    ruleset = _rules(args)
    found = {str(trace): ruleset.evaluate(load_events(trace)) for trace in args.traces}
    if args.json:
        payload = {trace: [alert.__dict__ for alert in alerts] for trace, alerts in found.items()}
        print(json.dumps(payload, indent=2))
    else:
        for trace, alerts in found.items():
            print(f"{trace}: {len(alerts)} alert(s)")
            for alert in alerts:
                spans = ", ".join(alert.span_ids[:3]) + (" ..." if len(alert.span_ids) > 3 else "")
                print(f"  [{alert.level}] {alert.title}  (spans: {spans})")
    return 1 if args.fail_on_alert and any(found.values()) else 0


def cmd_export(args: argparse.Namespace) -> int:
    atomics = {atomic.id: atomic for atomic in load_atomics(args.atomics)}
    if args.id not in atomics:
        print(f"unknown atomic '{args.id}' (see `firedrill list`)", file=sys.stderr)
        return 2
    events = atomics[args.id].benign if args.benign else atomics[args.id].attack
    text = json.dumps(to_otlp(events), indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text)
    return 0


def cmd_check_rules(args: argparse.Namespace) -> int:
    ruleset = _rules(args)
    print(
        f"{len(ruleset.rules)} rules and {len(ruleset.correlations)} correlations parsed; "
        f"{len(ruleset.alerting)} can raise an alert"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="firedrill",
        description="Detection validation for AI agents: do your detections fire on agent attacks?",
    )
    parser.add_argument("--version", action="version", version=f"firedrill {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    def add_rules(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--rules", action="append", metavar="PATH",
                         help="Sigma rule file or directory (repeatable; default: bundled starter pack)")

    def add_atomics(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("--atomics", default=DEFAULT_ATOMICS, metavar="DIR",
                         help="atomics directory (default: bundled library)")

    run = commands.add_parser("run", help="replay every atomic against the rules and score coverage")
    add_rules(run)
    add_atomics(run)
    run.add_argument("--json", action="store_true", help="print the report as JSON")
    run.add_argument("--md", metavar="FILE", help="also write a Markdown report")
    run.add_argument("-v", "--verbose", action="store_true", help="list every atomic and what fired")
    run.add_argument("--min-coverage", type=float, metavar="PCT", help="exit 1 below this coverage")
    run.add_argument("--max-noisy", type=int, metavar="N", help="exit 1 above this many noisy detections")
    run.add_argument("--max-missed", type=int, metavar="N", help="exit 1 above this many missed atomics")
    run.set_defaults(handler=cmd_run)

    listing = commands.add_parser("list", help="list the atomics and their framework mappings")
    add_atomics(listing)
    listing.set_defaults(handler=cmd_list)

    scan = commands.add_parser("scan", help="run the rules over your own trace files")
    add_rules(scan)
    scan.add_argument("traces", nargs="+", metavar="TRACE", help="OTLP/JSON or JSON-lines trace file")
    scan.add_argument("--json", action="store_true", help="print alerts as JSON")
    scan.add_argument("--fail-on-alert", action="store_true", help="exit 1 if anything alerts")
    scan.set_defaults(handler=cmd_scan)

    export = commands.add_parser("export", help="write an atomic's trace as OTLP/JSON for replay into a real pipeline")
    add_atomics(export)
    export.add_argument("id", help="atomic id, e.g. FD-ASI01-001")
    export.add_argument("--benign", action="store_true", help="export the benign twin instead of the attack")
    export.add_argument("--out", metavar="FILE", help="write to a file instead of stdout")
    export.set_defaults(handler=cmd_export)

    check = commands.add_parser("check-rules", help="parse the rules and report unsupported Sigma features")
    add_rules(check)
    check.set_defaults(handler=cmd_check_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    # The Windows console defaults to cp1252 and chokes on non-ASCII trace content.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    try:
        return args.handler(args)
    except (RuleError, AtomicError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

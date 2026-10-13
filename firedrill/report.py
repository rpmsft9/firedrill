"""Render a drill report as console text, Markdown or JSON."""

from __future__ import annotations

import json
from typing import Any

from . import __version__
from .runner import COVERED, MISSED, NOISY, DrillReport
from .taxonomy import MITRE_ATLAS, MITRE_ATLAS_VERSION, OWASP_ASI_VERSION

_MARK = {COVERED: "ok", NOISY: "NOISY", MISSED: "MISSED"}


def _headline(report: DrillReport) -> str:
    return (
        f"Coverage {report.coverage:.1f}% ({report.count(COVERED)}/{report.total} covered)   "
        f"detection rate {report.detection_rate:.1f}%   "
        f"noisy {report.count(NOISY)}   missed {report.count(MISSED)}"
    )


def to_text(report: DrillReport, verbose: bool = False) -> str:
    lines = [
        f"firedrill {__version__}: {report.total} atomics x {report.rule_count} alerting rules",
        "",
        f"{'':7}{'OWASP Agentic Top 10 ' + OWASP_ASI_VERSION:<40}{'atomics':>8}{'covered':>9}{'noisy':>7}{'missed':>8}",
    ]
    for row in report.by_category():
        lines.append(
            f"{row.asi:<7}{row.name:<40}{row.total:>8}{row.covered:>9}{row.noisy:>7}{row.missed:>8}"
        )
    lines += ["", _headline(report)]

    for outcome, heading in ((MISSED, "MISSED: no alert on the attack trace"),
                             (NOISY, "NOISY: alerted on the attack and on its benign twin")):
        hits = [r for r in report.results if r.outcome == outcome]
        if not hits:
            continue
        lines += ["", heading]
        for result in hits:
            lines.append(f"  {result.atomic.id}  {result.atomic.name}")
            if outcome == NOISY:
                lines.append(f"      benign twin tripped: {', '.join(result.benign_rules)}")
            elif result.atomic.detection_note:
                lines.append(f"      {result.atomic.detection_note}")

    if report.unexercised:
        lines += ["", "UNEXERCISED: rules that fired on no attack trace (no atomic tests them)"]
        lines += [f"  {title}" for title in report.unexercised]

    if verbose:
        lines += ["", "ALL ATOMICS"]
        for result in report.results:
            fired = ", ".join(result.attack_rules) or "-"
            lines.append(f"  {_MARK[result.outcome]:<7}{result.atomic.id}  {result.atomic.name}")
            lines.append(f"         fired: {fired}")
    return "\n".join(lines)


def to_markdown(report: DrillReport) -> str:
    lines = [
        "## firedrill detection coverage",
        "",
        f"**{_headline(report)}**",
        "",
        f"| | OWASP Agentic Top 10 ({OWASP_ASI_VERSION}) | Atomics | Covered | Noisy | Missed |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for row in report.by_category():
        lines.append(f"| {row.asi} | {row.name} | {row.total} | {row.covered} | {row.noisy} | {row.missed} |")
    lines += ["", "| Atomic | Technique | Outcome | Rules that fired |", "|---|---|---|---|"]
    for result in report.results:
        fired = "; ".join(result.attack_rules) or "none"
        lines.append(f"| {result.atomic.id} | {result.atomic.name} | {_MARK[result.outcome]} | {fired} |")
    lines += ["", f"| MITRE ATLAS ({MITRE_ATLAS_VERSION}) | Technique | Best outcome |", "|---|---|---|"]
    for technique, outcome in report.atlas_coverage().items():
        lines.append(f"| {technique} | {MITRE_ATLAS[technique]} | {_MARK[outcome]} |")
    if report.unexercised:
        lines += ["", "**Unexercised rules** (fired on no attack trace):", ""]
        lines += [f"- {title}" for title in report.unexercised]
    return "\n".join(lines) + "\n"


def to_dict(report: DrillReport) -> dict[str, Any]:
    return {
        "version": __version__,
        "summary": {
            "atomics": report.total,
            "alerting_rules": report.rule_count,
            "coverage_pct": round(report.coverage, 1),
            "detection_rate_pct": round(report.detection_rate, 1),
            "covered": report.count(COVERED),
            "noisy": report.count(NOISY),
            "missed": report.count(MISSED),
            "benign_twins_alerting": report.benign_alerting,
        },
        "categories": [row.__dict__ for row in report.by_category()],
        "atlas": report.atlas_coverage(),
        "atomics": [
            {
                "id": result.atomic.id,
                "name": result.atomic.name,
                "severity": result.atomic.severity,
                "owasp_asi": list(result.atomic.asi),
                "atlas": list(result.atomic.atlas),
                "outcome": result.outcome,
                "attack_rules": list(result.attack_rules),
                "benign_rules": list(result.benign_rules),
            }
            for result in report.results
        ],
        "unexercised_rules": list(report.unexercised),
    }


def to_json(report: DrillReport) -> str:
    return json.dumps(to_dict(report), indent=2)

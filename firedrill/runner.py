"""Run a rule set against the atomics and score the outcome."""

from __future__ import annotations

from dataclasses import dataclass

from .atomics import Atomic
from .sigma import Alert, RuleSet
from .taxonomy import OWASP_ASI

COVERED = "covered"  # fired on the attack, quiet on the benign twin
NOISY = "noisy"  # fired on the attack and on the benign twin
MISSED = "missed"  # did not fire on the attack


@dataclass(frozen=True)
class AtomicResult:
    atomic: Atomic
    attack_alerts: tuple[Alert, ...]
    benign_alerts: tuple[Alert, ...]

    @property
    def outcome(self) -> str:
        if not self.attack_alerts:
            return MISSED
        return NOISY if self.benign_alerts else COVERED

    @property
    def attack_rules(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(alert.title for alert in self.attack_alerts))

    @property
    def benign_rules(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(alert.title for alert in self.benign_alerts))


@dataclass(frozen=True)
class CategoryRow:
    asi: str
    name: str
    total: int
    covered: int
    noisy: int
    missed: int


@dataclass(frozen=True)
class DrillReport:
    results: tuple[AtomicResult, ...]
    rule_count: int
    unexercised: tuple[str, ...]  # alerting rules that fired on no attack trace

    def count(self, outcome: str) -> int:
        return sum(1 for result in self.results if result.outcome == outcome)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def coverage(self) -> float:
        """Percent of atomics detected without also alerting on the benign twin."""
        return 100.0 * self.count(COVERED) / self.total if self.total else 0.0

    @property
    def detection_rate(self) -> float:
        """Percent of attack traces that raised any alert, clean or not."""
        return 100.0 * (self.count(COVERED) + self.count(NOISY)) / self.total if self.total else 0.0

    @property
    def benign_alerting(self) -> int:
        """Benign twins that raised an alert, whether or not the attack was caught."""
        return sum(1 for result in self.results if result.benign_alerts)

    def by_category(self) -> list[CategoryRow]:
        rows = []
        for asi, name in OWASP_ASI.items():
            outcomes = [r.outcome for r in self.results if r.atomic.primary_asi == asi]
            rows.append(
                CategoryRow(
                    asi=asi,
                    name=name,
                    total=len(outcomes),
                    covered=outcomes.count(COVERED),
                    noisy=outcomes.count(NOISY),
                    missed=outcomes.count(MISSED),
                )
            )
        return rows

    def atlas_coverage(self) -> dict[str, str]:
        """Best outcome seen for each ATLAS technique exercised by an atomic."""
        rank = {MISSED: 0, NOISY: 1, COVERED: 2}
        best: dict[str, str] = {}
        for result in self.results:
            for technique in result.atomic.atlas:
                if rank[result.outcome] >= rank.get(best.get(technique, MISSED), 0):
                    best[technique] = result.outcome
        return dict(sorted(best.items()))


def run_drill(ruleset: RuleSet, atomics: list[Atomic]) -> DrillReport:
    results = tuple(
        AtomicResult(
            atomic=atomic,
            attack_alerts=tuple(ruleset.evaluate(atomic.attack)),
            benign_alerts=tuple(ruleset.evaluate(atomic.benign)),
        )
        for atomic in atomics
    )
    fired = {title for result in results for title in result.attack_rules}
    unexercised = tuple(rule.title for rule in ruleset.alerting if rule.title not in fired)
    return DrillReport(results=results, rule_count=len(ruleset.alerting), unexercised=unexercised)

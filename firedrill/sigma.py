"""A deterministic evaluator for a subset of Sigma, including correlations.

Supported in detection rules: field matching with the modifiers `contains`,
`startswith`, `endswith`, `re` (with `i`/`m`/`s`), `all`, `cased`, `exists`,
`gt`/`gte`/`lt`/`lte`; `*` and `?` wildcards; keyword lists; and conditions
built from `and`, `or`, `not`, parentheses, `1 of`, `all of` and `them`.

Supported correlation types: `event_count`, `value_count`, `temporal` and
`temporal_ordered`, with `group-by` and `timespan`.

Anything outside that subset raises `RuleError`. A rule that cannot be
evaluated faithfully must fail loudly, never pass or miss silently.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from .events import Event, Scalar

Predicate = Callable[[Event], bool]


class RuleError(ValueError):
    """A rule is malformed or uses a Sigma feature this engine does not support."""


# --------------------------------------------------------------------------
# field matching
# --------------------------------------------------------------------------

_STRING_OPS = ("contains", "startswith", "endswith")
_NUMERIC_OPS = {
    "gt": lambda a, b: a > b,
    "gte": lambda a, b: a >= b,
    "lt": lambda a, b: a < b,
    "lte": lambda a, b: a <= b,
}
_RE_FLAGS = {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}


def _as_text(value: Scalar) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _wildcard_pattern(value: str) -> str:
    """Translate a Sigma string (`*` and `?` wildcards, `\\` escapes) to a regex."""
    out: list[str] = []
    i = 0
    while i < len(value):
        char = value[i]
        if char == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if char == "*" else "." if char == "?" else re.escape(char))
        i += 1
    return "".join(out)


def _value_test(op: str, raw: Any, flags: int, where: str) -> Callable[[Scalar], bool]:
    if op in _NUMERIC_OPS:
        try:
            bound = float(raw)
        except (TypeError, ValueError):
            raise RuleError(f"{where}: '{op}' needs a number, got {raw!r}") from None
        compare = _NUMERIC_OPS[op]

        def numeric(value: Scalar) -> bool:
            try:
                return compare(float(value), bound)  # type: ignore[arg-type]
            except (TypeError, ValueError):
                return False

        return numeric

    if op == "re":
        try:
            pattern = re.compile(str(raw), flags)
        except re.error as exc:
            raise RuleError(f"{where}: bad regex {raw!r}: {exc}") from None
        return lambda value: (text := _as_text(value)) is not None and bool(pattern.search(text))

    if raw is None:
        if op != "eq":
            raise RuleError(f"{where}: null is only valid for an exact match")
        return lambda value: value is None

    body = _wildcard_pattern(_as_text(raw) or "")
    if op == "eq":
        pattern = re.compile(body, flags | re.DOTALL)
        return lambda value: (text := _as_text(value)) is not None and bool(pattern.fullmatch(text))
    if op == "startswith":
        pattern = re.compile(body, flags | re.DOTALL)
        return lambda value: (text := _as_text(value)) is not None and bool(pattern.match(text))
    if op == "endswith":
        body += r"\Z"
    pattern = re.compile(body, flags | re.DOTALL)
    return lambda value: (text := _as_text(value)) is not None and bool(pattern.search(text))


def _field_predicate(key: str, raw: Any, where: str) -> Predicate:
    name, *modifiers = key.split("|")
    where = f"{where}: {key}"
    op = "eq"
    match_all = False
    cased = False
    re_flags = 0
    for modifier in modifiers:
        if modifier in _STRING_OPS or modifier in _NUMERIC_OPS or modifier in ("re", "exists"):
            if op != "eq":
                raise RuleError(f"{where}: cannot combine '{op}' and '{modifier}'")
            op = modifier
        elif modifier == "all":
            match_all = True
        elif modifier == "cased":
            cased = True
        elif modifier in _RE_FLAGS and op == "re":
            re_flags |= _RE_FLAGS[modifier]
        else:
            raise RuleError(f"{where}: unsupported modifier '{modifier}'")

    if op == "exists":
        if not isinstance(raw, bool):
            raise RuleError(f"{where}: 'exists' needs true or false")
        return lambda event: (event.get(name) is not None) == raw

    values = raw if isinstance(raw, list) else [raw]
    if not values:
        raise RuleError(f"{where}: empty value list")
    flags = re_flags if op == "re" else (0 if cased else re.IGNORECASE)
    tests = [_value_test(op, value, flags, where) for value in values]
    combine = all if match_all else any
    return lambda event: combine(test(event.get(name)) for test in tests)


def _keyword_predicate(keyword: Any) -> Predicate:
    needle = str(keyword).lower()
    return lambda event: any(
        needle in text.lower() for value in event.fields.values() if (text := _as_text(value))
    )


def _map_predicate(mapping: dict[str, Any], where: str) -> Predicate:
    if not mapping:
        raise RuleError(f"{where}: empty selection")
    tests = [_field_predicate(str(key), value, where) for key, value in mapping.items()]
    return lambda event: all(test(event) for test in tests)


def _selection_predicate(body: Any, where: str) -> Predicate:
    if isinstance(body, dict):
        return _map_predicate(body, where)
    if isinstance(body, list) and body:
        tests = [
            _map_predicate(item, where) if isinstance(item, dict) else _keyword_predicate(item)
            for item in body
        ]
        return lambda event: any(test(event) for test in tests)
    raise RuleError(f"{where}: a selection must be a mapping or a non-empty list")


# --------------------------------------------------------------------------
# condition expressions
# --------------------------------------------------------------------------

_TOKEN = re.compile(r"\(|\)|[^\s()]+")


class _ConditionParser:
    """Recursive descent over `or` < `and` < `not` < atom."""

    def __init__(self, text: str, selections: dict[str, Predicate], where: str):
        self.tokens = _TOKEN.findall(text)
        self.position = 0
        self.selections = selections
        self.where = f"{where}: condition '{text}'"

    def parse(self) -> Predicate:
        if not self.tokens:
            raise RuleError(f"{self.where}: empty condition")
        predicate = self._or()
        if self.position != len(self.tokens):
            raise RuleError(f"{self.where}: unexpected '{self.tokens[self.position]}'")
        return predicate

    def _peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def _take(self) -> str:
        if self.position >= len(self.tokens):
            raise RuleError(f"{self.where}: ended unexpectedly")
        self.position += 1
        return self.tokens[self.position - 1]

    def _or(self) -> Predicate:
        terms = [self._and()]
        while (self._peek() or "").lower() == "or":
            self._take()
            terms.append(self._and())
        return terms[0] if len(terms) == 1 else lambda event: any(t(event) for t in terms)

    def _and(self) -> Predicate:
        terms = [self._not()]
        while (self._peek() or "").lower() == "and":
            self._take()
            terms.append(self._not())
        return terms[0] if len(terms) == 1 else lambda event: all(t(event) for t in terms)

    def _not(self) -> Predicate:
        if (self._peek() or "").lower() == "not":
            self._take()
            inner = self._not()
            return lambda event: not inner(event)
        return self._atom()

    def _atom(self) -> Predicate:
        token = self._take()
        if token == "(":
            inner = self._or()
            if self._take() != ")":
                raise RuleError(f"{self.where}: missing ')'")
            return inner
        if token.lower() in ("1", "any", "all") and (self._peek() or "").lower() == "of":
            self._take()
            targets = self._targets(self._take())
            combine = all if token.lower() == "all" else any
            return lambda event: combine(t(event) for t in targets)
        if token not in self.selections:
            raise RuleError(f"{self.where}: unknown selection '{token}'")
        return self.selections[token]

    def _targets(self, pattern: str) -> list[Predicate]:
        if pattern.lower() == "them":
            names = [name for name in self.selections if not name.startswith("_")]
        else:
            names = [name for name in self.selections if fnmatch.fnmatchcase(name, pattern)]
        if not names:
            raise RuleError(f"{self.where}: '{pattern}' matches no selection")
        return [self.selections[name] for name in names]


# --------------------------------------------------------------------------
# rules and correlations
# --------------------------------------------------------------------------

_TIMESPAN = re.compile(r"^(\d+)([smhd])$")
_TIMESPAN_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
_CORRELATION_TYPES = ("event_count", "value_count", "temporal", "temporal_ordered")
_COUNT_OPS = {"gte": lambda count, bound: count >= bound, "gt": lambda count, bound: count > bound}


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    title: str
    level: str
    tags: tuple[str, ...]
    description: str
    source: str
    predicate: Predicate = field(repr=False, compare=False)

    @property
    def refs(self) -> tuple[str, ...]:
        return tuple(ref for ref in (self.name, self.id) if ref)


@dataclass(frozen=True)
class Correlation:
    id: str
    name: str
    title: str
    level: str
    tags: tuple[str, ...]
    description: str
    source: str
    type: str
    rules: tuple[str, ...]
    group_by: tuple[str, ...]
    timespan: float
    count_op: str = "gte"
    count_bound: float = 1
    count_field: str = ""
    generate: bool = False


@dataclass(frozen=True)
class Alert:
    rule_id: str
    title: str
    level: str
    tags: tuple[str, ...]
    kind: str  # "rule" | "correlation"
    span_ids: tuple[str, ...]
    group: tuple[Scalar, ...] = ()


def _parse_timespan(value: Any, where: str) -> float:
    match = _TIMESPAN.match(str(value))
    if not match:
        raise RuleError(f"{where}: bad timespan {value!r} (use e.g. 30s, 5m, 1h)")
    return int(match.group(1)) * _TIMESPAN_SECONDS[match.group(2)]


def _common(doc: dict[str, Any], source: str) -> dict[str, Any]:
    title = doc.get("title")
    if not title:
        raise RuleError(f"{source}: rule has no title")
    return {
        "id": str(doc.get("id", "")),
        "name": str(doc.get("name", "")),
        "title": str(title),
        "level": str(doc.get("level", "medium")),
        "tags": tuple(str(tag).lower() for tag in doc.get("tags", []) or []),
        "description": str(doc.get("description", "")).strip(),
        "source": source,
    }


def _parse_rule(doc: dict[str, Any], source: str) -> Rule:
    common = _common(doc, source)
    where = f"{source}: {common['title']}"
    detection = doc["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleError(f"{where}: detection needs a condition")
    selections = {
        str(name): _selection_predicate(body, f"{where}: {name}")
        for name, body in detection.items()
        if name != "condition"
    }
    conditions = detection["condition"]
    conditions = conditions if isinstance(conditions, list) else [conditions]
    parsed = [_ConditionParser(str(text), selections, where).parse() for text in conditions]
    predicate = parsed[0] if len(parsed) == 1 else lambda event: any(p(event) for p in parsed)
    return Rule(predicate=predicate, **common)


def _parse_correlation(doc: dict[str, Any], source: str) -> Correlation:
    common = _common(doc, source)
    where = f"{source}: {common['title']}"
    body = doc["correlation"]
    kind = body.get("type")
    if kind not in _CORRELATION_TYPES:
        raise RuleError(f"{where}: unsupported correlation type {kind!r}")
    rules = tuple(str(ref) for ref in body.get("rules", []) or [])
    if not rules:
        raise RuleError(f"{where}: correlation references no rules")
    if "timespan" not in body:
        raise RuleError(f"{where}: correlation needs a timespan")
    extra: dict[str, Any] = {}
    if kind in ("event_count", "value_count"):
        condition = dict(body.get("condition") or {})
        count_field = str(condition.pop("field", ""))
        if kind == "value_count" and not count_field:
            raise RuleError(f"{where}: value_count needs condition.field")
        if len(condition) != 1 or next(iter(condition)) not in _COUNT_OPS:
            raise RuleError(f"{where}: condition must be exactly one of gte / gt")
        op, bound = next(iter(condition.items()))
        extra = {"count_op": op, "count_bound": float(bound), "count_field": count_field}
    return Correlation(
        type=kind,
        rules=rules,
        group_by=tuple(str(name) for name in body.get("group-by", []) or []),
        timespan=_parse_timespan(body["timespan"], where),
        generate=bool(body.get("generate", False)),
        **extra,
        **common,
    )


def _first_window(times: list[float], span: float, hit: Callable[[int, int], bool]) -> tuple[int, int] | None:
    """First [start, end] index window no longer than `span` for which `hit` holds."""
    start = 0
    for end in range(len(times)):
        while times[end] - times[start] > span:
            start += 1
        if hit(start, end):
            return start, end
    return None


@dataclass
class RuleSet:
    rules: list[Rule]
    correlations: list[Correlation]

    def __post_init__(self) -> None:
        self._by_ref: dict[str, Rule] = {}
        for rule in self.rules:
            for ref in rule.refs:
                if ref in self._by_ref:
                    raise RuleError(f"{rule.source}: duplicate rule name/id '{ref}'")
                self._by_ref[ref] = rule
        self._silent: set[int] = set()
        for correlation in self.correlations:
            for ref in correlation.rules:
                if ref not in self._by_ref:
                    raise RuleError(f"{correlation.source}: {correlation.title}: unknown rule '{ref}'")
                # Sigma: rules referenced by a correlation do not alert on their
                # own unless the correlation sets `generate: true`.
                if not correlation.generate:
                    self._silent.add(id(self._by_ref[ref]))

    @property
    def alerting(self) -> list[Rule | Correlation]:
        """Everything that can raise an alert, i.e. excluding correlation-only base rules."""
        return [r for r in self.rules if id(r) not in self._silent] + list(self.correlations)

    def evaluate(self, events: Iterable[Event]) -> list[Alert]:
        events = list(events)
        matches: dict[int, list[int]] = {
            id(rule): [i for i, event in enumerate(events) if rule.predicate(event)]
            for rule in self.rules
        }
        alerts: list[Alert] = []
        for rule in self.rules:
            if id(rule) in self._silent:
                continue
            for index in matches[id(rule)]:
                alerts.append(self._alert(rule, "rule", [events[index]]))
        for correlation in self.correlations:
            alerts.extend(self._correlate(correlation, events, matches))
        return alerts

    @staticmethod
    def _alert(source: Rule | Correlation, kind: str, events: list[Event], group: tuple = ()) -> Alert:
        return Alert(
            rule_id=source.id or source.name or source.title,
            title=source.title,
            level=source.level,
            tags=source.tags,
            kind=kind,
            span_ids=tuple(str(event.get("span_id") or "") for event in events),
            group=group,
        )

    def _correlate(
        self, correlation: Correlation, events: list[Event], matches: dict[int, list[int]]
    ) -> list[Alert]:
        # Per group: time-ordered (event index, position of the matching rule).
        groups: dict[tuple, list[tuple[int, int]]] = {}
        for position, ref in enumerate(correlation.rules):
            for index in matches[id(self._by_ref[ref])]:
                key = tuple(events[index].get(name) for name in correlation.group_by)
                groups.setdefault(key, []).append((index, position))
        alerts = []
        for key, hits in groups.items():
            hits.sort()
            window = self._window(correlation, events, hits)
            if window:
                alerts.append(
                    self._alert(correlation, "correlation", [events[i] for i in window], key)
                )
        return alerts

    @staticmethod
    def _window(
        correlation: Correlation, events: list[Event], hits: list[tuple[int, int]]
    ) -> list[int] | None:
        """Event indices of the first window in one group that satisfies the correlation."""
        times = [events[index].time for index, _ in hits]
        span = correlation.timespan

        if correlation.type == "temporal_ordered":
            stages = len(correlation.rules)
            for first, (_, position) in enumerate(hits):
                if position != 0:
                    continue
                chain = [first]
                for later in range(first + 1, len(hits)):
                    if times[later] - times[first] > span:
                        break
                    if len(chain) < stages and hits[later][1] == len(chain):
                        chain.append(later)
                if len(chain) == stages:
                    return [hits[i][0] for i in chain]
            return None

        if correlation.type == "temporal":
            needed = set(range(len(correlation.rules)))
            hit = lambda start, end: {hits[i][1] for i in range(start, end + 1)} == needed
        elif correlation.type == "event_count":
            passes = _COUNT_OPS[correlation.count_op]
            hit = lambda start, end: passes(end - start + 1, correlation.count_bound)
        else:  # value_count
            passes = _COUNT_OPS[correlation.count_op]

            def hit(start: int, end: int) -> bool:
                values = {events[hits[i][0]].get(correlation.count_field) for i in range(start, end + 1)}
                values.discard(None)
                return passes(len(values), correlation.count_bound)

        found = _first_window(times, span, hit)
        return [hits[i][0] for i in range(found[0], found[1] + 1)] if found else None


def parse_documents(docs: Iterable[Any], source: str) -> tuple[list[Rule], list[Correlation]]:
    rules: list[Rule] = []
    correlations: list[Correlation] = []
    for doc in docs:
        if doc is None:
            continue
        if not isinstance(doc, dict):
            raise RuleError(f"{source}: a rule must be a YAML mapping")
        if "correlation" in doc:
            correlations.append(_parse_correlation(doc, source))
        elif "detection" in doc:
            rules.append(_parse_rule(doc, source))
        else:
            raise RuleError(f"{source}: document has neither 'detection' nor 'correlation'")
    return rules, correlations


def rule_files(paths: Iterable[str | Path]) -> list[Path]:
    files: list[Path] = []
    for path in map(Path, paths):
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.suffix in (".yml", ".yaml")))
        elif path.is_file():
            files.append(path)
        else:
            raise RuleError(f"{path}: no such rule file or directory")
    return files


def load_rules(paths: Iterable[str | Path]) -> RuleSet:
    rules: list[Rule] = []
    correlations: list[Correlation] = []
    for file in rule_files(paths):
        try:
            docs = list(yaml.safe_load_all(file.read_text(encoding="utf-8")))
        except yaml.YAMLError as exc:
            raise RuleError(f"{file.name}: invalid YAML: {exc}") from None
        file_rules, file_correlations = parse_documents(docs, file.name)
        rules.extend(file_rules)
        correlations.extend(file_correlations)
    if not rules and not correlations:
        raise RuleError("no rules found")
    return RuleSet(rules, correlations)

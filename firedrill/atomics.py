"""Atomic tests: one small, replayable attack trace plus its benign twin.

Each atomic is a YAML file. The `attack` trace is what the technique looks
like in OpenTelemetry GenAI telemetry; the `benign` trace is ordinary agent
work chosen to look as similar as possible. A detection only counts when it
fires on the first and stays quiet on the second.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .events import Event, make_event, sort_events
from .taxonomy import MITRE_ATLAS, OWASP_ASI, OWASP_LLM, SEVERITIES

# Fixed so traces, span ids and reports are byte-identical across runs.
BASE_TIME = 1767225600.0  # 2026-01-01T00:00:00Z


class AtomicError(ValueError):
    """An atomic test file is malformed."""


@dataclass(frozen=True)
class Atomic:
    id: str
    name: str
    description: str
    severity: str
    asi: tuple[str, ...]
    atlas: tuple[str, ...]
    llm: tuple[str, ...]
    attack: tuple[Event, ...]
    benign: tuple[Event, ...]
    benign_note: str
    detection_note: str
    source: str

    @property
    def primary_asi(self) -> str:
        return self.asi[0]


def _hex(seed: str, length: int) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:length]


def _span_name(attributes: dict[str, Any]) -> str:
    operation = attributes.get("gen_ai.operation.name", "")
    target = (
        attributes.get("gen_ai.tool.name")
        or attributes.get("gen_ai.agent.name" if operation == "invoke_agent" else "gen_ai.request.model")
        or ""
    )
    return f"{operation} {target}".strip()


def _build_trace(atomic_id: str, variant: str, spans: Any, defaults: dict[str, Any]) -> tuple[Event, ...]:
    where = f"{atomic_id}: {variant}"
    if not isinstance(spans, list) or not spans:
        raise AtomicError(f"{where}: needs a non-empty list of spans")
    events: list[Event] = []
    for position, span in enumerate(spans):
        if not isinstance(span, dict) or not isinstance(span.get("attrs"), dict):
            raise AtomicError(f"{where}: span {position} needs an 'attrs' mapping")
        repeat = int(span.get("repeat", 1))
        every = float(span.get("every", 1))
        for copy in range(repeat):
            attributes = {
                "gen_ai.conversation.id": f"{atomic_id}-{variant}".lower(),
                **defaults,
                **span["attrs"],
            }
            events.append(
                make_event(
                    time=BASE_TIME + float(span.get("at", 0)) + copy * every,
                    attributes=attributes,
                    trace_id=_hex(f"{atomic_id}:{variant}:{span.get('trace', 0)}", 32),
                    span_id=_hex(f"{atomic_id}:{variant}:{position}:{copy}", 16),
                    name=str(span.get("name") or _span_name(attributes)),
                )
            )
    return tuple(sort_events(events))


def _ids(doc: dict[str, Any], key: str, known: dict[str, str], where: str) -> tuple[str, ...]:
    values = tuple(str(value) for value in doc.get(key, []) or [])
    for value in values:
        if value not in known:
            raise AtomicError(f"{where}: unknown {key} id '{value}'")
    return values


def parse_atomic(doc: Any, source: str) -> Atomic:
    if not isinstance(doc, dict):
        raise AtomicError(f"{source}: an atomic must be a YAML mapping")
    for key in ("id", "name", "description", "owasp_asi", "attack", "benign"):
        if not doc.get(key):
            raise AtomicError(f"{source}: missing '{key}'")
    atomic_id = str(doc["id"])
    where = f"{source}: {atomic_id}"
    severity = str(doc.get("severity", "medium"))
    if severity not in SEVERITIES:
        raise AtomicError(f"{where}: unknown severity '{severity}'")
    defaults = doc.get("defaults") or {}
    return Atomic(
        id=atomic_id,
        name=str(doc["name"]),
        description=" ".join(str(doc["description"]).split()),
        severity=severity,
        asi=_ids(doc, "owasp_asi", OWASP_ASI, where),
        atlas=_ids(doc, "atlas", MITRE_ATLAS, where),
        llm=_ids(doc, "owasp_llm", OWASP_LLM, where),
        attack=_build_trace(atomic_id, "attack", doc["attack"], defaults),
        benign=_build_trace(atomic_id, "benign", doc["benign"], defaults),
        benign_note=" ".join(str(doc.get("benign_note", "")).split()),
        detection_note=" ".join(str(doc.get("detection_note", "")).split()),
        source=source,
    )


def load_atomics(directory: str | Path) -> list[Atomic]:
    directory = Path(directory)
    if not directory.is_dir():
        raise AtomicError(f"{directory}: no such atomics directory")
    atomics: list[Atomic] = []
    seen: set[str] = set()
    for file in sorted(p for p in directory.rglob("*") if p.suffix in (".yml", ".yaml")):
        try:
            doc = yaml.safe_load(file.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise AtomicError(f"{file.name}: invalid YAML: {exc}") from None
        atomic = parse_atomic(doc, file.name)
        if atomic.id in seen:
            raise AtomicError(f"{file.name}: duplicate atomic id '{atomic.id}'")
        seen.add(atomic.id)
        atomics.append(atomic)
    if not atomics:
        raise AtomicError(f"{directory}: no atomics found")
    return sorted(atomics, key=lambda atomic: atomic.id)

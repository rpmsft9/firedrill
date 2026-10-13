"""Normalise agent telemetry into flat events the rule engine matches on.

The wire format is OpenTelemetry GenAI spans. Two encodings are accepted:

* OTLP/JSON, as written by the collector's file exporter (`resourceSpans`),
  one request per file or one per line.
* A simplified span per line: `{"trace_id", "span_id", "name", "time",
  "attributes": {...}}`.

Either way an event is a flat mapping of dotted attribute names to scalars,
plus `trace_id`, `span_id`, `parent_span_id` and `span_name`. Structured
attribute values (message arrays, tool arguments) are kept as JSON strings so
rules can pattern-match them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

Scalar = str | int | float | bool | None


@dataclass(frozen=True)
class Event:
    time: float  # seconds since the epoch
    fields: dict[str, Scalar]

    def get(self, name: str) -> Scalar:
        return self.fields.get(name)


def to_scalar(value: Any) -> Scalar:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value, ensure_ascii=False)


def parse_time(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        number = float(value)
    elif str(value).isdigit():
        number = float(int(value))
    else:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    # OTLP timestamps are nanoseconds; anything that large cannot be seconds.
    return number / 1e9 if number > 1e14 else number


def make_event(
    *,
    time: float,
    attributes: dict[str, Any],
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str = "",
    name: str = "",
) -> Event:
    fields: dict[str, Scalar] = {k: to_scalar(v) for k, v in attributes.items()}
    fields["trace_id"] = trace_id
    fields["span_id"] = span_id
    if parent_span_id:
        fields["parent_span_id"] = parent_span_id
    fields["span_name"] = name
    return Event(time=time, fields=fields)


def _otlp_value(value: dict[str, Any]) -> Any:
    if "stringValue" in value:
        return value["stringValue"]
    if "intValue" in value:
        return int(value["intValue"])
    if "doubleValue" in value:
        return float(value["doubleValue"])
    if "boolValue" in value:
        return bool(value["boolValue"])
    if "arrayValue" in value:
        return [_otlp_value(v) for v in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value:
        return _otlp_attributes(value["kvlistValue"].get("values", []))
    return None


def _otlp_attributes(items: Iterable[dict[str, Any]]) -> dict[str, Any]:
    return {item["key"]: _otlp_value(item.get("value", {})) for item in items}


def _from_otlp(doc: dict[str, Any]) -> list[Event]:
    events: list[Event] = []
    for resource_spans in doc.get("resourceSpans", []):
        resource = _otlp_attributes(resource_spans.get("resource", {}).get("attributes", []))
        for scope_spans in resource_spans.get("scopeSpans", []):
            for span in scope_spans.get("spans", []):
                attributes = {**resource, **_otlp_attributes(span.get("attributes", []))}
                events.append(
                    make_event(
                        time=parse_time(span.get("startTimeUnixNano")),
                        attributes=attributes,
                        trace_id=span.get("traceId", ""),
                        span_id=span.get("spanId", ""),
                        parent_span_id=span.get("parentSpanId", ""),
                        name=span.get("name", ""),
                    )
                )
    return events


def _from_simple(doc: dict[str, Any]) -> Event:
    return make_event(
        time=parse_time(doc.get("time", doc.get("start_time"))),
        attributes=doc.get("attributes", doc.get("attrs", {})) or {},
        trace_id=str(doc.get("trace_id", "")),
        span_id=str(doc.get("span_id", "")),
        parent_span_id=str(doc.get("parent_span_id", "")),
        name=str(doc.get("name", "")),
    )


def events_from_docs(docs: Iterable[Any]) -> list[Event]:
    events: list[Event] = []
    for doc in docs:
        if not isinstance(doc, dict):
            raise ValueError(f"expected a JSON object per span, got {type(doc).__name__}")
        if "resourceSpans" in doc:
            events.extend(_from_otlp(doc))
        else:
            events.append(_from_simple(doc))
    return sort_events(events)


def sort_events(events: list[Event]) -> list[Event]:
    return sorted(events, key=lambda e: e.time)  # stable: ties keep file order


def load_events(path: str | Path) -> list[Event]:
    """Load a trace file: one JSON document, a JSON array, or JSON lines."""
    text = Path(path).read_text(encoding="utf-8")
    try:
        whole = json.loads(text)
    except json.JSONDecodeError:
        docs = [json.loads(line) for line in text.splitlines() if line.strip()]
    else:
        docs = whole if isinstance(whole, list) else [whole]
    return events_from_docs(docs)


_ENVELOPE_FIELDS = ("trace_id", "span_id", "parent_span_id", "span_name")


def _to_otlp_value(value: Scalar) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": "" if value is None else value}


def to_otlp(events: Iterable[Event], service_name: str = "firedrill") -> dict[str, Any]:
    """Encode events as an OTLP/JSON trace export, ready to POST to a collector."""
    spans = []
    for event in events:
        span: dict[str, Any] = {
            "traceId": event.get("trace_id") or "",
            "spanId": event.get("span_id") or "",
            "name": event.get("span_name") or "",
            "kind": 1,
            "startTimeUnixNano": str(int(event.time * 1e9)),
            "endTimeUnixNano": str(int(event.time * 1e9) + 1_000_000),
            "attributes": [
                {"key": key, "value": _to_otlp_value(value)}
                for key, value in event.fields.items()
                if key not in _ENVELOPE_FIELDS
            ],
        }
        if event.get("parent_span_id"):
            span["parentSpanId"] = event.get("parent_span_id")
        spans.append(span)
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [{"key": "service.name", "value": {"stringValue": service_name}}]
                },
                "scopeSpans": [{"scope": {"name": "firedrill"}, "spans": spans}],
            }
        ]
    }

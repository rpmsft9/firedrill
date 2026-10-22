# Changelog

## 0.1.0 - 2026-10-22

First release.

- 17 atomic tests covering all ten OWASP Agentic Top 10 (2026) categories,
  mapped to MITRE ATLAS, each with an attack trace and a benign twin.
- Sigma rule engine (subset) with correlation rules: `event_count`,
  `value_count`, `temporal`, `temporal_ordered`. Unsupported features raise.
- Starter rule pack (15 alerting detections) and a naive keyword pack for
  comparison.
- `run`, `list`, `scan`, `export` (OTLP/JSON) and `check-rules` commands;
  text, Markdown and JSON reports; CI gates on coverage, noisy and missed.

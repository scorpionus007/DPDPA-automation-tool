# Flow Goldens Guide

This document explains how to maintain and extend golden-style tests for flow rules
and the supporting flow analysis modules.

## Architecture

```
dpdp_scanner/flow/
├── __init__.py
├── symbol_tracker.py     # PII symbol extraction & field→arg continuity
├── taint_tracker.py      # Regex-based taint propagation across files
├── consent_proximity.py  # Consent-near-sink detection (function/module level)
├── fk_graph.py           # FK/relationship graph for entity-aware deletion
└── ml_classifier.py      # ML-based flow validity classification
```

All modules are integrated into `dpdp_scanner/rules/data_flow.py` via
`_compute_flow_confidence()` which produces a multi-signal confidence score.

## How confidence is computed

The final flow confidence is a weighted blend of five signals:

| Signal | Weight | Source module |
|--------|--------|--------------|
| Structural (path/sink/hop/PII) | 35% | `data_flow.py` inline |
| Symbol continuity | 25% | `symbol_tracker.py` |
| Taint propagation | 20% | `taint_tracker.py` |
| Consent proximity (inverted) | 20% | `consent_proximity.py` |

The combined score is then blended 60/40 with an ML classifier probability:

```
final = 0.60 * combined + 0.40 * ml_probability
```

## Module details

### Symbol Tracker (`symbol_tracker.py`)

Extracts PII-like variable names at source and sink, checks whether PII symbols
propagate through assignments and function call arguments across the flow path.

Key function: `compute_symbol_evidence(flow_path, file_contents)` returns a dict
with `symbol_continuity_score`, `source_pii_symbols`, `sink_pii_symbols`, `sink_call_arg_pii`.

### Taint Tracker (`taint_tracker.py`)

Lightweight regex-based taint analysis. Propagates PII seed symbols through
assignment chains, return values, and function call arguments across ordered
file paths. Does not require an AST.

Key function: `trace_taint_across_path(path, file_contents, seed_pii)` returns
`{reached_sink, taint_at_sink, total_events, path_events, confidence}`.

### Consent Proximity (`consent_proximity.py`)

Checks whether consent patterns exist near sink callsites — at function level
(strongest) or module level (weaker). Purpose-specific consent (e.g. `analytics_consent`,
`marketing_consent`) scores higher than generic consent.

Key function: `has_consent_near_sink(sink_content, sink_type)` returns
`{found, purpose_specific, consent_tokens, proximity}`.

### FK Graph (`fk_graph.py`)

Parses ORM relationship declarations (ForeignKey, has_many, belongs_to, etc.)
to build an entity dependency graph. `deletion_must_cover()` expands root PII
entities to include all transitive FK dependents that must also be deleted.

Supports: SQLAlchemy, Django, Sequelize, Prisma, TypeORM, Rails, Laravel.

### ML Classifier (`ml_classifier.py`)

Ships with a `RuleBasedFlowClassifier` (14-feature weighted sigmoid) by default.
Can be replaced with a trained `TrainedFlowClassifier` (GradientBoosting via
scikit-learn) if labeled data is available.

Feature vector includes: symbol continuity, taint signals, consent proximity,
structural features (hop count, sink type, PII count, path length).

## Run tests

Flow goldens only:

```powershell
py -3 -m pytest -m flow_goldens -v
```

Full test suite:

```powershell
py -3 -m pytest -q
```

## Golden test design rules

- Keep each test focused on **one behavior**.
- Use small synthetic `extracted` fixtures with realistic content (multi-line functions with actual variable usage so symbol/taint trackers have signal to work with).
- Assert both:
  - rule presence/absence,
  - key evidence contract fields (`confidence`, `scorable`, `coverage_pct`, `flow_evidence`, etc.).
- For scoring tests, always compare before/after score deltas explicitly.
- For ambiguous-flow tests, set verifier cap deterministically:
  - `data_flow.FLOW_VERIFY_MAX = 0` to disable LLM verifier path in unit tests.

## Suggested quality targets (regression gates)

Track these by sink type as suite grows:

- `analytics` flow precision: `>= 0.80`
- `marketing` flow precision: `>= 0.80`
- `error_logging` flow precision: `>= 0.75`
- false positive rate per sink type: `< 0.20`

## Current test coverage (33 tests)

| Area | Tests | Notes |
|------|-------|-------|
| Analytics flow | 3 | emit, consent-suppress, weak-consent |
| Marketing flow | 2 | emit, consent-near-sink suppress |
| Logging flow | 2 | sensitive PII, non-sensitive suppress |
| Symbol tracker | 4 | PII extraction, continuity, evidence keys |
| Taint tracker | 3 | propagation, cross-path, no-PII |
| Consent proximity | 4 | function-level, absent, score, purpose-specific |
| FK graph | 3 | detect FK, transitive deps, must-cover |
| Deletion coverage | 1 | entities, FK edges in evidence |
| Purpose mismatch | 2 | auth→marketing, same-purpose suppress |
| Score impact | 2 | non-scorable no-change, scorable deduction |
| ML classifier | 4 | feature vector, probabilities, end-to-end, consent effect |
| Edge cases | 3 | empty graph, same-dir, self-loop |

## Adding new goldens

When adding a new flow rule or changing confidence logic:

1. Add one **positive** case (must trigger).
2. Add one **negative** case (must not trigger).
3. Add one **score-impact** case.
4. If evidence schema changed, assert required keys in `evidence`.
5. Use realistic multi-line content so symbol/taint trackers engage.

## Common pitfalls

- Do not rely on order of findings unless rule guarantees it.
- Do not depend on external API/model availability.
- Avoid brittle assertions on full description text; prefer stable fields.
- Include realistic function bodies in `_file_contents` so new multi-signal
  scoring produces meaningful confidence values.

## Maintenance checklist

When flow rules change:

- [ ] Update/add relevant golden tests
- [ ] Run `py -3 -m pytest -m flow_goldens -v`
- [ ] Run at least one regression scan (`--no-llm --no-deep-review`)
- [ ] Verify report still renders for changed evidence shape

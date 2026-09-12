# Risk and control model

AegisGraph intentionally exposes its scoring assumptions. The default path score is:

```text
clamp(round(criticality * 10 - cost * 1 + 25), 1, 100)
```

This score is a deterministic prioritization heuristic. It is **not** a probability of compromise, CVSS score, loss expectancy, or empirical frequency estimate.

## Inputs

- `criticality`: integer 1..10 on a crown-jewel node.
- `cost`: sum of edge costs along a path; each edge cost is 1..100.
- `criticality_weight`, `cost_weight`, and `base_offset`: configurable model-level scoring parameters.

A team should calibrate these values against its own threat model rather than treating the defaults as universal truth.

## Path completeness

AegisGraph enumerates simple paths up to `--max-depth`. It ranks the complete candidate set and applies `--limit` only after ranking. If exploration exceeds `--max-states`, the command exits with code 2 instead of returning partial results that could be mistaken for a complete top-K list.

The simple-path rule intentionally excludes revisiting a node within one path. Systems where repeated traversal itself changes state should be represented with explicit state nodes rather than cycles that imply hidden state transitions.

## Control recommendation model

An edge's `controls` list means those controls are relevant to that modeled transition. Control metadata can include:

- `effectiveness` in 0..1;
- `status`: `planned`, `implemented`, or `validated`;
- `evidence`: a human-readable evidence reference.

Recommendation weighting uses the declared effectiveness and a status factor:

- planned: 0.25
- implemented: 0.65
- validated: 1.0

The resulting `expected_risk_reduction` is a prioritization signal over modeled path risk, not proof that the control will prevent compromise. A control with weak or absent evidence should be treated accordingly by reviewers.

## Known limits

The model does not estimate exploit probability, attacker prevalence, control dependency, correlated failures, time-to-detection, or monetary impact. Those can be layered on later, but v0.2 keeps the model deliberately explicit and auditable.

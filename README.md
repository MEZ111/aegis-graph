# AegisGraph

Explainable attack-path modeling with bounded exhaustive ranking and evidence-aware security-control recommendations.

AegisGraph finds simple paths from modeled entry points to crown-jewel assets, scores them with an explicit configurable heuristic, then ranks controls by how much modeled risk they are expected to reduce.

## What changed in v0.2

- path limits are applied **after** complete bounded enumeration instead of stopping at the first paths discovered by DFS;
- analysis fails explicitly at `--max-states` rather than silently returning partial results;
- path identity includes edge IDs, so parallel edges cannot collapse to the same fingerprint;
- controls can declare `effectiveness`, `status`, and `evidence`;
- risk scoring is configurable and emitted in machine-readable output;
- model validation is strict for nodes, edges, costs, criticality, controls, IDs, and scoring;
- Mermaid output uses safe internal aliases rather than raw node IDs.

## Install and run

```bash
git clone https://github.com/MEZ111/aegis-graph.git
cd aegis-graph
python3 -m pip install .
aegis-graph examples/model.json
```

Machine-readable and visual output:

```bash
aegis-graph examples/model.json --format json -o paths.json
aegis-graph examples/model.json --format mermaid -o attack-paths.md
aegis-graph examples/model.json --limit 100 --max-depth 8 --max-states 100000
aegis-graph examples/model.json --fail-risk 80
```

## Model contract

```json
{
  "nodes": [
    {"id":"internet","kind":"attacker","entry":true},
    {"id":"vault","crown_jewel":true,"criticality":10}
  ],
  "edges": [
    {"id":"internet-vault","from":"internet","to":"vault","technique":"stolen identity","cost":35,
     "controls":["phishing-resistant-mfa","least-privilege"]}
  ],
  "controls": {
    "phishing-resistant-mfa": {
      "effectiveness": 0.9,
      "status": "validated",
      "evidence": "red-team replay blocked"
    }
  },
  "scoring": {
    "criticality_weight": 10,
    "cost_weight": 1,
    "base_offset": 25
  }
}
```

The formal JSON Schema is in [`docs/model.schema.json`](docs/model.schema.json).

## Risk semantics

Default path score:

```text
clamp(round(criticality*10 - cost*1 + 25), 1, 100)
```

That number is a **policy heuristic**, not a measured probability of compromise. The formula is deliberately exposed in JSON output and can be calibrated per environment. See [`docs/RISK_MODEL.md`](docs/RISK_MODEL.md).

## Control recommendations

A control attached to an edge means it is relevant to disrupting that transition. Optional metadata changes the recommendation weight:

- `effectiveness`: declared value from `0.0` to `1.0`;
- `status`: `planned`, `implemented`, or `validated`;
- `evidence`: optional human-readable evidence reference.

Undeclared controls remain backward-compatible and default to effectiveness `1.0`, status `implemented`, with no evidence. Recommendations say **paths covered** and **expected risk reduction** rather than claiming that a control certainly breaks a path.

## Completeness and limits

AegisGraph enumerates bounded simple paths, ranks the full candidate set, and only then applies `--limit`. If exploration exceeds `--max-states`, analysis exits with an error instead of presenting incomplete rankings as complete. This trades silent incompleteness for an explicit operational limit.

## Exit-code contract

- `0`: analysis completed and no path met `--fail-risk`;
- `1`: at least one path met `--fail-risk`;
- `2`: invalid model, state-budget exhaustion, unreadable input, or another analysis error.

## Design boundaries

The graph is an explicit threat model, not an automatic compromise detector. Completeness depends on model completeness. Costs, criticality, effectiveness, and status are policy inputs and should be calibrated with evidence. Cycles are prevented within a path, depth is bounded, and large graphs may require a larger state budget or a narrower model.

## Verification

```bash
python3 -m pip install ".[dev]"
ruff check src tests
mypy src
PYTHONPATH=src python3 -m unittest -v tests/test_aegis_graph.py
python3 -m build
pip-audit
```

CI runs on Python 3.10, 3.11, 3.12, and 3.13 with GitHub Actions pinned by commit SHA.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

MIT

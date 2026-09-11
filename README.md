# AegisGraph

Explainable attack-path modeling with counterfactual security-control ranking.
AegisGraph finds routes from entry points to crown-jewel assets, ranks them by
cost and criticality, then answers the useful remediation question:

> Which control breaks the most dangerous paths?

## Analysis

The input model describes assets and directed attack transitions. Each edge has
an attacker cost, technique, and the controls capable of blocking it. AegisGraph:

1. enumerates bounded simple paths from entry nodes to crown jewels;
2. calculates deterministic path risk;
3. preserves the technique chain and control coverage;
4. uses a greedy weighted hitting-set analysis to rank remediations;
5. exports Markdown, JSON, or a Mermaid attack graph.

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
    {"from":"internet","to":"vault","technique":"stolen identity","cost":35,
     "controls":["phishing-resistant-mfa","least-privilege"]}
  ]
}
```

## Design boundaries

The graph is an explicit threat model, not an automatic compromise detector.
Path completeness depends on model completeness. Cost and criticality are policy
inputs that teams should calibrate. Cycles are prevented within a path and depth
is bounded to keep results reviewable.

## Verification

```bash
PYTHONPATH=src python3 -m unittest -v tests/test_aegis_graph.py
```

Tests verify ranked path enumeration, multi-path control impact, and model
integrity checks.

## License

MIT

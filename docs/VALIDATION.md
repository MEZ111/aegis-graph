# Validation corpus

AegisGraph v0.2 separates focused unit tests from a table-driven graph outcome corpus.

`tests/test_validation_corpus.py` contains 10 known models covering direct paths, cost ordering, criticality effects, multiple entries, attacker-kind entry inference, cycles, parallel edges, deeper paths, dead ends, and deterministic ties. `tests/test_aegis_graph.py` separately exercises parser failures, state-budget behavior, edge-identity fingerprints, control evidence/effectiveness, scoring clamps, depth boundaries, and Mermaid-safe aliases.

Both suites run on every CI job across Python 3.10–3.13. The corpus validates deterministic model behavior; it does not claim empirical attack probability or completeness against real infrastructure.

Future scoring or search changes should update the corpus only when the intended model semantics change, not merely to make a failing test pass.

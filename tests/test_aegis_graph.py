import unittest

from aegis_graph import ScoringConfig, enumerate_paths, mermaid, parse, recommend, score_path

MODEL = {
    "nodes": [
        {"id": "internet", "kind": "attacker", "entry": True},
        {"id": "api"},
        {"id": "worker"},
        {"id": "vault", "crown_jewel": True, "criticality": 10},
    ],
    "edges": [
        {"id": "internet-api", "from": "internet", "to": "api", "technique": "public exploit", "cost": 20,
         "controls": ["patch-api", "waf-rule"]},
        {"id": "api-vault", "from": "api", "to": "vault", "technique": "stolen identity", "cost": 15,
         "controls": ["least-privilege", "token-binding"]},
        {"id": "internet-worker", "from": "internet", "to": "worker", "technique": "exposed queue", "cost": 30,
         "controls": ["private-endpoint"]},
        {"id": "worker-vault", "from": "worker", "to": "vault", "technique": "service identity", "cost": 10,
         "controls": ["least-privilege"]},
    ],
}


class AegisGraphTests(unittest.TestCase):
    def test_enumerates_and_ranks_paths(self):
        nodes, edges = parse(dict(MODEL))
        paths = enumerate_paths(nodes, edges)
        self.assertEqual(len(paths), 2)
        self.assertEqual(paths[0].nodes, ("internet", "api", "vault"))

    def test_limit_is_applied_after_ranking_not_discovery(self):
        model = {
            "nodes": [
                {"id": "entry", "entry": True}, {"id": "slow"}, {"id": "fast"},
                {"id": "target", "crown_jewel": True, "criticality": 10},
            ],
            "edges": [
                {"id": "a", "from": "entry", "to": "slow", "cost": 1},
                {"id": "b", "from": "slow", "to": "target", "cost": 90},
                {"id": "c", "from": "entry", "to": "fast", "cost": 50},
                {"id": "d", "from": "fast", "to": "target", "cost": 1},
            ],
        }
        nodes, edges = parse(model)
        paths = enumerate_paths(nodes, edges, limit=1)
        self.assertEqual(paths[0].nodes, ("entry", "fast", "target"))

    def test_parallel_edges_get_distinct_path_ids(self):
        model = {
            "nodes": [{"id": "a", "entry": True}, {"id": "z", "crown_jewel": True}],
            "edges": [
                {"id": "e1", "from": "a", "to": "z", "technique": "same", "cost": 10, "controls": ["x"]},
                {"id": "e2", "from": "a", "to": "z", "technique": "same", "cost": 20, "controls": ["y"]},
            ],
        }
        nodes, edges = parse(model)
        paths = enumerate_paths(nodes, edges)
        self.assertEqual(len({path.path_id for path in paths}), 2)

    def test_cycles_are_bounded_by_simple_path_rule(self):
        model = {
            "nodes": [{"id": "a", "entry": True}, {"id": "b"}, {"id": "z", "crown_jewel": True}],
            "edges": [{"from": "a", "to": "b"}, {"from": "b", "to": "a"}, {"from": "b", "to": "z"}],
        }
        nodes, edges = parse(model)
        self.assertEqual(len(enumerate_paths(nodes, edges)), 1)

    def test_max_states_fails_instead_of_returning_partial_results(self):
        nodes, edges = parse(dict(MODEL))
        with self.assertRaisesRegex(RuntimeError, "partial results"):
            enumerate_paths(nodes, edges, max_states=1)

    def test_control_recommendation_uses_effectiveness_and_status(self):
        model = dict(MODEL)
        model["controls"] = {
            "least-privilege": {"effectiveness": 0.8, "status": "validated", "evidence": "IAM test"},
            "patch-api": {"effectiveness": 1.0, "status": "planned"},
        }
        nodes, edges = parse(model)
        recommendations = recommend(enumerate_paths(nodes, edges), model)
        least = next(item for item in recommendations if item.control == "least-privilege")
        self.assertEqual(least.paths_covered, 2)
        self.assertEqual(least.effectiveness, 0.8)
        self.assertEqual(least.status, "validated")
        self.assertEqual(least.evidence, "IAM test")

    def test_default_controls_are_explicitly_implemented(self):
        model = dict(MODEL)
        nodes, edges = parse(model)
        item = recommend(enumerate_paths(nodes, edges), model)[0]
        self.assertIn(item.status, {"implemented", "validated", "planned"})

    def test_custom_scoring_is_deterministic(self):
        config = ScoringConfig(criticality_weight=5, cost_weight=2, base_offset=10)
        self.assertEqual(score_path(10, 20, config), 20)

    def test_risk_is_clamped(self):
        self.assertEqual(score_path(10, 1, ScoringConfig(100, 0, 100)), 100)
        self.assertEqual(score_path(1, 100, ScoringConfig(1, 10, 0)), 1)

    def test_rejects_unknown_nodes(self):
        broken = {"nodes": MODEL["nodes"], "edges": [{"from": "internet", "to": "missing"}]}
        with self.assertRaises(ValueError):
            parse(broken)

    def test_rejects_invalid_controls_shape(self):
        broken = {"nodes": MODEL["nodes"], "edges": [{"from": "internet", "to": "vault", "controls": "waf"}]}
        with self.assertRaisesRegex(ValueError, "controls must be an array"):
            parse(broken)

    def test_rejects_invalid_criticality(self):
        broken = {"nodes": [{"id": "a", "entry": True}, {"id": "z", "crown_jewel": True, "criticality": 11}], "edges": []}
        with self.assertRaisesRegex(ValueError, "criticality"):
            parse(broken)

    def test_rejects_duplicate_edge_ids(self):
        broken = {
            "nodes": [{"id": "a", "entry": True}, {"id": "z", "crown_jewel": True}],
            "edges": [{"id": "dup", "from": "a", "to": "z"}, {"id": "dup", "from": "a", "to": "z"}],
        }
        with self.assertRaisesRegex(ValueError, "duplicate edge id"):
            parse(broken)

    def test_requires_entry_and_crown_jewel(self):
        nodes, edges = parse({"nodes": [{"id": "a"}], "edges": []})
        with self.assertRaisesRegex(ValueError, "entry"):
            enumerate_paths(nodes, edges)

    def test_depth_limit_is_edges_not_nodes(self):
        nodes, edges = parse(dict(MODEL))
        self.assertEqual(enumerate_paths(nodes, edges, max_depth=1), [])
        self.assertEqual(len(enumerate_paths(nodes, edges, max_depth=2)), 2)

    def test_mermaid_uses_safe_aliases_for_unsafe_node_ids(self):
        model = {
            "nodes": [{"id": "internet user", "entry": True}, {"id": "vault:prod", "crown_jewel": True}],
            "edges": [{"id": "e", "from": "internet user", "to": "vault:prod", "technique": 'quote " test'}],
        }
        nodes, edges = parse(model)
        output = mermaid(model, enumerate_paths(nodes, edges))
        self.assertIn("n0", output)
        self.assertIn("n1", output)
        self.assertNotIn("internet user[", output)


if __name__ == "__main__":
    unittest.main()

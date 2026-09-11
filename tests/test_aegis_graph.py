import unittest

from aegis_graph import enumerate_paths, parse, recommend


MODEL = {
    "nodes": [
        {"id": "internet", "kind": "attacker", "entry": True},
        {"id": "api"}, {"id": "worker"},
        {"id": "vault", "crown_jewel": True, "criticality": 10},
    ],
    "edges": [
        {"from": "internet", "to": "api", "technique": "public exploit", "cost": 20,
         "controls": ["patch-api", "waf-rule"]},
        {"from": "api", "to": "vault", "technique": "stolen identity", "cost": 15,
         "controls": ["least-privilege", "token-binding"]},
        {"from": "internet", "to": "worker", "technique": "exposed queue", "cost": 30,
         "controls": ["private-endpoint"]},
        {"from": "worker", "to": "vault", "technique": "service identity", "cost": 10,
         "controls": ["least-privilege"]},
    ],
}


class AegisGraphTests(unittest.TestCase):
    def test_enumerates_and_ranks_paths(self):
        nodes, edges = parse(MODEL)
        paths = enumerate_paths(nodes, edges)
        self.assertEqual(len(paths), 2)
        self.assertEqual(paths[0].nodes, ("internet", "api", "vault"))

    def test_counterfactual_control_breaks_multiple_paths(self):
        nodes, edges = parse(MODEL)
        recommendations = recommend(enumerate_paths(nodes, edges))
        self.assertEqual(recommendations[0].control, "least-privilege")
        self.assertEqual(recommendations[0].paths_broken, 2)

    def test_rejects_unknown_nodes(self):
        broken = {"nodes": MODEL["nodes"], "edges": [{"from": "internet", "to": "missing"}]}
        with self.assertRaises(ValueError):
            parse(broken)


if __name__ == "__main__":
    unittest.main()

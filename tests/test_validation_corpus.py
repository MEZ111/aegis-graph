import unittest

from aegis_graph import enumerate_paths, parse


def analyze(model, **kwargs):
    nodes, edges = parse(model)
    return enumerate_paths(nodes, edges, **kwargs)


def base(nodes, edges):
    return {"nodes": nodes, "edges": edges}


class GraphValidationCorpusTests(unittest.TestCase):
    def test_ten_known_graph_outcomes(self):
        cases = [
            (
                "direct path",
                base([{"id": "a", "entry": True}, {"id": "z", "crown_jewel": True, "criticality": 10}],
                     [{"id": "e", "from": "a", "to": "z", "cost": 10}]),
                ("a", "z"),
            ),
            (
                "lower cost wins",
                base([{"id": "a", "entry": True}, {"id": "x"}, {"id": "y"}, {"id": "z", "crown_jewel": True, "criticality": 10}],
                     [{"id": "ax", "from": "a", "to": "x", "cost": 30}, {"id": "xz", "from": "x", "to": "z", "cost": 10},
                      {"id": "ay", "from": "a", "to": "y", "cost": 10}, {"id": "yz", "from": "y", "to": "z", "cost": 10}]),
                ("a", "y", "z"),
            ),
            (
                "higher criticality can win",
                base([{"id": "a", "entry": True}, {"id": "low", "crown_jewel": True, "criticality": 3},
                      {"id": "high", "crown_jewel": True, "criticality": 10}],
                     [{"id": "al", "from": "a", "to": "low", "cost": 1}, {"id": "ah", "from": "a", "to": "high", "cost": 30}]),
                ("a", "high"),
            ),
            (
                "multiple entries",
                base([{"id": "a", "entry": True}, {"id": "b", "entry": True}, {"id": "z", "crown_jewel": True, "criticality": 8}],
                     [{"id": "az", "from": "a", "to": "z", "cost": 40}, {"id": "bz", "from": "b", "to": "z", "cost": 10}]),
                ("b", "z"),
            ),
            (
                "attacker kind is entry",
                base([{"id": "a", "kind": "attacker"}, {"id": "z", "crown_jewel": True}],
                     [{"id": "az", "from": "a", "to": "z"}]),
                ("a", "z"),
            ),
            (
                "simple cycle ignored",
                base([{"id": "a", "entry": True}, {"id": "b"}, {"id": "z", "crown_jewel": True}],
                     [{"id": "ab", "from": "a", "to": "b"}, {"id": "ba", "from": "b", "to": "a"}, {"id": "bz", "from": "b", "to": "z"}]),
                ("a", "b", "z"),
            ),
            (
                "parallel edge cheaper wins",
                base([{"id": "a", "entry": True}, {"id": "z", "crown_jewel": True}],
                     [{"id": "slow", "from": "a", "to": "z", "cost": 50}, {"id": "fast", "from": "a", "to": "z", "cost": 5}]),
                ("a", "z"),
            ),
            (
                "three hop path",
                base([{"id": "a", "entry": True}, {"id": "b"}, {"id": "c"}, {"id": "z", "crown_jewel": True}],
                     [{"id": "ab", "from": "a", "to": "b"}, {"id": "bc", "from": "b", "to": "c"}, {"id": "cz", "from": "c", "to": "z"}]),
                ("a", "b", "c", "z"),
            ),
            (
                "branch dead end excluded",
                base([{"id": "a", "entry": True}, {"id": "dead"}, {"id": "z", "crown_jewel": True}],
                     [{"id": "ad", "from": "a", "to": "dead", "cost": 1}, {"id": "az", "from": "a", "to": "z", "cost": 20}]),
                ("a", "z"),
            ),
            (
                "deterministic tie",
                base([{"id": "a", "entry": True}, {"id": "x"}, {"id": "y"}, {"id": "z", "crown_jewel": True}],
                     [{"id": "ax", "from": "a", "to": "x", "cost": 10}, {"id": "xz", "from": "x", "to": "z", "cost": 10},
                      {"id": "ay", "from": "a", "to": "y", "cost": 10}, {"id": "yz", "from": "y", "to": "z", "cost": 10}]),
                ("a", "x", "z"),
            ),
        ]
        self.assertEqual(len(cases), 10)
        for name, model, expected_top in cases:
            with self.subTest(name=name):
                paths = analyze(model)
                self.assertTrue(paths)
                self.assertEqual(paths[0].nodes, expected_top)


if __name__ == "__main__":
    unittest.main()

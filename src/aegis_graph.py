#!/usr/bin/env python3
"""Explainable attack-path analysis with counterfactual control ranking."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    technique: str
    cost: int
    controls: tuple[str, ...]


@dataclass(frozen=True)
class AttackPath:
    path_id: str
    nodes: tuple[str, ...]
    techniques: tuple[str, ...]
    controls: tuple[str, ...]
    cost: int
    risk: int


@dataclass(frozen=True)
class Recommendation:
    control: str
    paths_broken: int
    weighted_risk_reduced: int


def load_model(path: Path) -> dict:
    model = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(model, dict) or not isinstance(model.get("nodes"), list) or not isinstance(model.get("edges"), list):
        raise ValueError("model must contain nodes and edges arrays")
    return model


def parse(model: dict) -> tuple[dict[str, dict], list[Edge]]:
    nodes = {}
    for node in model["nodes"]:
        if not isinstance(node, dict) or not node.get("id"):
            raise ValueError("every node needs an id")
        identifier = str(node["id"])
        if identifier in nodes:
            raise ValueError(f"duplicate node: {identifier}")
        nodes[identifier] = node
    edges = []
    for raw in model["edges"]:
        source, target = str(raw.get("from", "")), str(raw.get("to", ""))
        if source not in nodes or target not in nodes:
            raise ValueError(f"edge references unknown node: {source} -> {target}")
        cost = int(raw.get("cost", 5))
        if not 1 <= cost <= 100:
            raise ValueError("edge cost must be within 1..100")
        edges.append(Edge(source, target, str(raw.get("technique") or "unspecified"), cost,
                          tuple(sorted(set(map(str, raw.get("controls", [])))))))
    return nodes, edges


def enumerate_paths(nodes: dict[str, dict], edges: list[Edge], max_depth: int = 8,
                    limit: int = 1000) -> list[AttackPath]:
    adjacency: dict[str, list[Edge]] = defaultdict(list)
    for edge in edges:
        adjacency[edge.source].append(edge)
    sources = sorted(node for node, data in nodes.items() if data.get("entry") or data.get("kind") == "attacker")
    targets = {node for node, data in nodes.items() if data.get("crown_jewel")}
    found: list[AttackPath] = []

    def walk(current: str, visited: tuple[str, ...], used: tuple[Edge, ...]) -> None:
        if len(found) >= limit or len(used) > max_depth:
            return
        if current in targets and used:
            cost = sum(edge.cost for edge in used)
            criticality = max(1, min(10, int(nodes[current].get("criticality", 5))))
            risk = max(1, min(100, criticality * 10 - cost + 25))
            techniques = tuple(edge.technique for edge in used)
            controls = tuple(sorted({control for edge in used for control in edge.controls}))
            identity = json.dumps([visited, techniques], separators=(",", ":"))
            found.append(AttackPath(hashlib.sha256(identity.encode()).hexdigest()[:12], visited,
                                    techniques, controls, cost, risk))
            return
        for edge in sorted(adjacency[current], key=lambda item: (item.cost, item.target)):
            if edge.target not in visited:
                walk(edge.target, (*visited, edge.target), (*used, edge))

    for source in sources:
        walk(source, (source,), ())
    return sorted(found, key=lambda path: (-path.risk, path.cost, path.nodes))


def recommend(paths: list[AttackPath]) -> list[Recommendation]:
    remaining = list(paths)
    result = []
    while remaining:
        candidates: dict[str, tuple[int, int]] = {}
        for control in {control for path in remaining for control in path.controls}:
            affected = [path for path in remaining if control in path.controls]
            candidates[control] = (sum(path.risk for path in affected), len(affected))
        if not candidates:
            break
        control = max(candidates, key=lambda item: (candidates[item][0], candidates[item][1], item))
        weighted, count = candidates[control]
        result.append(Recommendation(control, count, weighted))
        remaining = [path for path in remaining if control not in path.controls]
    return result


def markdown(paths: list[AttackPath], recommendations: list[Recommendation]) -> str:
    lines = ["# AegisGraph", "", f"**Attack paths:** {len(paths)}", "",
             "## Ranked paths", "", "| Risk | Cost | Route | Techniques |", "| ---: | ---: | --- | --- |"]
    for path in paths:
        route = " → ".join(path.nodes).replace("|", "\\|")
        techniques = ", ".join(path.techniques).replace("|", "\\|")
        lines.append(f"| {path.risk} | {path.cost} | {route} | {techniques} |")
    lines += ["", "## Counterfactual controls", "",
              "| Priority | Control | Paths broken | Weighted risk reduced |",
              "| ---: | --- | ---: | ---: |"]
    for number, item in enumerate(recommendations, 1):
        lines.append(f"| {number} | {item.control} | {item.paths_broken} | {item.weighted_risk_reduced} |")
    lines += ["", "> A modeled path is a hypothesis for validation, not proof of compromise.", ""]
    return "\n".join(lines)


def mermaid(model: dict, paths: list[AttackPath]) -> str:
    nodes, edges = parse(model)
    active = {(a, b) for path in paths for a, b in zip(path.nodes, path.nodes[1:])}
    lines = ["flowchart LR"]
    for identifier, data in nodes.items():
        label = str(data.get("label") or identifier).replace('"', "'")
        lines.append(f'  {identifier}["{label}"]')
    for edge in edges:
        arrow = "==>" if (edge.source, edge.target) in active else "-.->"
        label = edge.technique.replace('"', "'")
        lines.append(f'  {edge.source} {arrow}|"{label}"| {edge.target}')
    return "```mermaid\n" + "\n".join(lines) + "\n```\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--format", choices=("markdown", "json", "mermaid"), default="markdown")
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--fail-risk", type=int, default=101)
    args = parser.parse_args()
    model = load_model(args.model)
    nodes, edges = parse(model)
    paths = enumerate_paths(nodes, edges, max_depth=args.max_depth)
    recommendations = recommend(paths)
    if args.format == "json":
        output = json.dumps({"paths": [asdict(path) for path in paths],
                             "recommendations": [asdict(item) for item in recommendations]}, indent=2)
    elif args.format == "mermaid":
        output = mermaid(model, paths)
    else:
        output = markdown(paths, recommendations)
    args.output.write_text(output, encoding="utf-8") if args.output else print(output)
    return 1 if any(path.risk >= args.fail_risk for path in paths) else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Explainable attack-path analysis with bounded exhaustive ranking."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

VALID_CONTROL_STATUS = {"planned", "implemented", "validated"}


@dataclass(frozen=True)
class Control:
    name: str
    effectiveness: float
    status: str
    evidence: str | None = None


@dataclass(frozen=True)
class Edge:
    edge_id: str
    source: str
    target: str
    technique: str
    cost: int
    controls: tuple[str, ...]


@dataclass(frozen=True)
class ScoringConfig:
    criticality_weight: float = 10.0
    cost_weight: float = 1.0
    base_offset: float = 25.0


@dataclass(frozen=True)
class AttackPath:
    path_id: str
    nodes: tuple[str, ...]
    edge_ids: tuple[str, ...]
    techniques: tuple[str, ...]
    controls: tuple[str, ...]
    cost: int
    risk: int
    risk_formula: str


@dataclass(frozen=True)
class Recommendation:
    control: str
    paths_covered: int
    expected_risk_reduction: int
    effectiveness: float
    status: str
    evidence: str | None


def load_model(path: Path) -> dict[str, Any]:
    model = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(model, dict):
        raise ValueError("model must be a JSON object")
    return model


def _parse_controls(model: dict[str, Any]) -> dict[str, Control]:
    raw_controls = model.get("controls", {})
    if raw_controls is None:
        raw_controls = {}
    if not isinstance(raw_controls, dict):
        raise ValueError("controls must be an object keyed by control name")
    controls: dict[str, Control] = {}
    for name, raw in raw_controls.items():
        if not isinstance(name, str) or not name:
            raise ValueError("control names must be non-empty strings")
        if not isinstance(raw, dict):
            raise ValueError(f"control {name} must be an object")
        effectiveness = raw.get("effectiveness", 1.0)
        if isinstance(effectiveness, bool) or not isinstance(effectiveness, (int, float)):
            raise ValueError(f"control {name} effectiveness must be numeric")
        effectiveness = float(effectiveness)
        if not 0.0 <= effectiveness <= 1.0:
            raise ValueError(f"control {name} effectiveness must be within 0..1")
        status = raw.get("status", "implemented")
        if status not in VALID_CONTROL_STATUS:
            raise ValueError(f"control {name} status must be one of: {', '.join(sorted(VALID_CONTROL_STATUS))}")
        evidence = raw.get("evidence")
        if evidence is not None and not isinstance(evidence, str):
            raise ValueError(f"control {name} evidence must be a string")
        controls[name] = Control(name, effectiveness, status, evidence)
    return controls


def _parse_scoring(model: dict[str, Any]) -> ScoringConfig:
    raw = model.get("scoring", {})
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("scoring must be an object")
    values: dict[str, float] = {}
    for key, default in (("criticality_weight", 10.0), ("cost_weight", 1.0), ("base_offset", 25.0)):
        value = raw.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"scoring.{key} must be numeric")
        values[key] = float(value)
    if values["criticality_weight"] <= 0 or values["cost_weight"] < 0:
        raise ValueError("scoring weights must be non-negative and criticality_weight must be positive")
    return ScoringConfig(**values)


def parse(model: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[Edge]]:
    if not isinstance(model.get("nodes"), list) or not isinstance(model.get("edges"), list):
        raise ValueError("model must contain nodes and edges arrays")
    nodes: dict[str, dict[str, Any]] = {}
    for index, node in enumerate(model["nodes"]):
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not node["id"]:
            raise ValueError(f"nodes[{index}] needs a non-empty string id")
        identifier = node["id"]
        if identifier in nodes:
            raise ValueError(f"duplicate node: {identifier}")
        if "criticality" in node:
            criticality = node["criticality"]
            if isinstance(criticality, bool) or not isinstance(criticality, int) or not 1 <= criticality <= 10:
                raise ValueError(f"node {identifier} criticality must be an integer within 1..10")
        for flag in ("entry", "crown_jewel"):
            if flag in node and not isinstance(node[flag], bool):
                raise ValueError(f"node {identifier} {flag} must be boolean")
        nodes[identifier] = node

    edges: list[Edge] = []
    edge_ids: set[str] = set()
    for index, raw in enumerate(model["edges"]):
        if not isinstance(raw, dict):
            raise ValueError(f"edges[{index}] must be an object")
        source, target = raw.get("from"), raw.get("to")
        if not isinstance(source, str) or not isinstance(target, str) or source not in nodes or target not in nodes:
            raise ValueError(f"edge references unknown node: {source} -> {target}")
        cost = raw.get("cost", 5)
        if isinstance(cost, bool) or not isinstance(cost, int) or not 1 <= cost <= 100:
            raise ValueError("edge cost must be an integer within 1..100")
        technique = raw.get("technique", "unspecified")
        if not isinstance(technique, str) or not technique:
            raise ValueError("edge technique must be a non-empty string")
        raw_controls = raw.get("controls", [])
        if not isinstance(raw_controls, list) or not all(isinstance(item, str) and item for item in raw_controls):
            raise ValueError("edge controls must be an array of non-empty strings")
        edge_id = raw.get("id")
        if edge_id is None:
            identity = json.dumps([source, target, technique, cost, raw_controls, index], separators=(",", ":"))
            edge_id = "e-" + hashlib.sha256(identity.encode()).hexdigest()[:12]
        if not isinstance(edge_id, str) or not edge_id:
            raise ValueError("edge id must be a non-empty string")
        if edge_id in edge_ids:
            raise ValueError(f"duplicate edge id: {edge_id}")
        edge_ids.add(edge_id)
        edges.append(Edge(edge_id, source, target, technique, cost, tuple(sorted(set(raw_controls)))))

    catalog = _parse_controls(model)
    referenced = {control for edge in edges for control in edge.controls}
    for control in referenced - set(catalog):
        catalog[control] = Control(control, 1.0, "implemented", None)
    model["_parsed_controls"] = catalog
    model["_parsed_scoring"] = _parse_scoring(model)
    return nodes, edges


def score_path(criticality: int, cost: int, scoring: ScoringConfig) -> int:
    raw = criticality * scoring.criticality_weight - cost * scoring.cost_weight + scoring.base_offset
    return max(1, min(100, int(round(raw))))


def _risk_formula(scoring: ScoringConfig) -> str:
    return (
        f"clamp(round(criticality*{scoring.criticality_weight:g} - "
        f"cost*{scoring.cost_weight:g} + {scoring.base_offset:g}), 1, 100)"
    )


def enumerate_paths(
    nodes: dict[str, dict[str, Any]],
    edges: list[Edge],
    max_depth: int = 8,
    limit: int = 1000,
    max_states: int = 100_000,
    scoring: ScoringConfig | None = None,
) -> list[AttackPath]:
    if max_depth < 1:
        raise ValueError("max_depth must be at least 1")
    if limit < 1:
        raise ValueError("limit must be at least 1")
    if max_states < 1:
        raise ValueError("max_states must be at least 1")
    scoring = scoring or ScoringConfig()
    adjacency: dict[str, list[Edge]] = defaultdict(list)
    for edge in edges:
        adjacency[edge.source].append(edge)
    for outgoing in adjacency.values():
        outgoing.sort(key=lambda item: (item.cost, item.target, item.edge_id))
    sources = sorted(node for node, data in nodes.items() if data.get("entry") or data.get("kind") == "attacker")
    targets = {node for node, data in nodes.items() if data.get("crown_jewel")}
    if not sources:
        raise ValueError("model needs at least one entry node or kind=attacker node")
    if not targets:
        raise ValueError("model needs at least one crown_jewel node")

    found: list[AttackPath] = []
    states_explored = 0

    def walk(current: str, visited: tuple[str, ...], used: tuple[Edge, ...]) -> None:
        nonlocal states_explored
        states_explored += 1
        if states_explored > max_states:
            raise RuntimeError(
                f"analysis exceeded max_states={max_states}; increase the budget or reduce graph/depth instead of accepting partial results"
            )
        if current in targets and used:
            cost = sum(edge.cost for edge in used)
            criticality = int(nodes[current].get("criticality", 5))
            risk = score_path(criticality, cost, scoring)
            edge_ids = tuple(edge.edge_id for edge in used)
            techniques = tuple(edge.technique for edge in used)
            controls = tuple(sorted({control for edge in used for control in edge.controls}))
            identity = json.dumps([visited, edge_ids], separators=(",", ":"))
            found.append(AttackPath(
                hashlib.sha256(identity.encode()).hexdigest()[:16], visited, edge_ids, techniques,
                controls, cost, risk, _risk_formula(scoring)))
            return
        if len(used) >= max_depth:
            return
        for edge in adjacency[current]:
            if edge.target not in visited:
                walk(edge.target, (*visited, edge.target), (*used, edge))

    for source in sources:
        walk(source, (source,), ())
    ranked = sorted(found, key=lambda path: (-path.risk, path.cost, path.nodes, path.edge_ids))
    return ranked[:limit]


def _control_catalog(model: dict[str, Any] | None, paths: list[AttackPath]) -> dict[str, Control]:
    if model is not None:
        parsed = model.get("_parsed_controls")
        if isinstance(parsed, dict) and all(isinstance(item, Control) for item in parsed.values()):
            return parsed
    return {name: Control(name, 1.0, "implemented", None) for path in paths for name in path.controls}


def recommend(paths: list[AttackPath], model: dict[str, Any] | None = None) -> list[Recommendation]:
    catalog = _control_catalog(model, paths)
    recommendations: list[Recommendation] = []
    for control_name in sorted({control for path in paths for control in path.controls}):
        affected = [path for path in paths if control_name in path.controls]
        meta = catalog[control_name]
        status_factor = {"planned": 0.25, "implemented": 0.65, "validated": 1.0}[meta.status]
        expected = round(sum(path.risk for path in affected) * meta.effectiveness * status_factor)
        recommendations.append(Recommendation(
            control_name, len(affected), expected, meta.effectiveness, meta.status, meta.evidence))
    return sorted(recommendations,
                  key=lambda item: (-item.expected_risk_reduction, -item.paths_covered, item.control))


def markdown(paths: list[AttackPath], recommendations: list[Recommendation]) -> str:
    lines = ["# AegisGraph", "", f"**Ranked attack paths:** {len(paths)}", "", "## Ranked paths", "",
             "| Risk | Cost | Route | Techniques |", "| ---: | ---: | --- | --- |"]
    for path in paths:
        route = " → ".join(path.nodes).replace("|", "\\|")
        techniques = ", ".join(path.techniques).replace("|", "\\|")
        lines.append(f"| {path.risk} | {path.cost} | {route} | {techniques} |")
    lines += ["", "## Control opportunities", "",
              "| Priority | Control | Paths covered | Expected risk reduction | Effectiveness | Status |",
              "| ---: | --- | ---: | ---: | ---: | --- |"]
    for number, item in enumerate(recommendations, 1):
        lines.append(f"| {number} | {item.control} | {item.paths_covered} | {item.expected_risk_reduction} | "
                     f"{item.effectiveness:.2f} | {item.status} |")
    lines += ["", "> Risk is a transparent policy heuristic, not a probability of compromise. Control reduction is expectation-weighted by declared effectiveness/status.", ""]
    return "\n".join(lines)


def mermaid(model: dict[str, Any], paths: list[AttackPath]) -> str:
    nodes, edges = parse(model)
    active_edges = {edge_id for path in paths for edge_id in path.edge_ids}
    lines = ["flowchart LR"]
    aliases: dict[str, str] = {}
    for index, (identifier, data) in enumerate(nodes.items()):
        alias = f"n{index}"
        aliases[identifier] = alias
        label = str(data.get("label") or identifier).replace("\\", "\\\\").replace('"', "'").replace("\n", " ")
        lines.append(f'  {alias}["{label}"]')
    for edge in edges:
        arrow = "==>" if edge.edge_id in active_edges else "-.->"
        label = edge.technique.replace("\\", "\\\\").replace('"', "'").replace("\n", " ")
        lines.append(f'  {aliases[edge.source]} {arrow}|"{label}"| {aliases[edge.target]}')
    return "```mermaid\n" + "\n".join(lines) + "\n```\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--format", choices=("markdown", "json", "mermaid"), default="markdown")
    parser.add_argument("--max-depth", type=int, default=8)
    parser.add_argument("--limit", type=int, default=1000, help="return the top K paths after complete bounded enumeration")
    parser.add_argument("--max-states", type=int, default=100_000, help="fail instead of silently returning partial analysis")
    parser.add_argument("--fail-risk", type=int, default=101)
    args = parser.parse_args()
    try:
        model = load_model(args.model)
        nodes, edges = parse(model)
        scoring = model["_parsed_scoring"]
        assert isinstance(scoring, ScoringConfig)
        paths = enumerate_paths(nodes, edges, max_depth=args.max_depth, limit=args.limit,
                                max_states=args.max_states, scoring=scoring)
        recommendations = recommend(paths, model)
        if args.format == "json":
            output = json.dumps({
                "meta": {"risk_is_probability": False, "risk_formula": _risk_formula(scoring),
                         "max_depth": args.max_depth, "limit": args.limit, "max_states": args.max_states},
                "paths": [asdict(path) for path in paths],
                "recommendations": [asdict(item) for item in recommendations]}, indent=2)
        elif args.format == "mermaid":
            output = mermaid(model, paths)
        else:
            output = markdown(paths, recommendations)
        args.output.write_text(output, encoding="utf-8") if args.output else print(output)
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"aegis-graph: error: {exc}", file=sys.stderr)
        return 2
    return 1 if any(path.risk >= args.fail_risk for path in paths) else 0


if __name__ == "__main__":
    raise SystemExit(main())

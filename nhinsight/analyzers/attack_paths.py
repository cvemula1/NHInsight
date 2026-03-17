# MIT License — Copyright (c) 2026 cvemula1
# Attack Path Analysis — detects identity chains that reach privileged resources

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from nhinsight.analyzers.graph import (
    EdgeType,
    GraphEdge,
    IdentityGraph,
    build_graph,
)
from nhinsight.core.models import Identity, Severity

logger = logging.getLogger(__name__)


@dataclass
class AttackPathStep:
    """A single step in an attack path."""
    node_id: str
    node_label: str
    node_type: str
    provider: str
    edge_type: Optional[str] = None
    edge_label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_label": self.node_label,
            "node_type": self.node_type,
            "provider": self.provider,
            "edge_type": self.edge_type,
            "edge_label": self.edge_label,
        }


@dataclass
class AttackPath:
    """A complete attack path from entry point to privileged resource."""
    id: str
    steps: List[AttackPathStep] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    blast_radius: float = 0.0
    cross_system: bool = False
    description: str = ""
    recommendation: str = ""

    @property
    def length(self) -> int:
        return len(self.steps)

    @property
    def entry_point(self) -> Optional[AttackPathStep]:
        return self.steps[0] if self.steps else None

    @property
    def target(self) -> Optional[AttackPathStep]:
        return self.steps[-1] if self.steps else None

    @property
    def providers_involved(self) -> List[str]:
        return list(dict.fromkeys(s.provider for s in self.steps))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity.value,
            "blast_radius": round(self.blast_radius, 1),
            "cross_system": self.cross_system,
            "length": self.length,
            "providers": self.providers_involved,
            "description": self.description,
            "recommendation": self.recommendation,
            "steps": [s.to_dict() for s in self.steps],
        }


@dataclass
class AttackPathResult:
    """Complete attack path analysis results."""
    paths: List[AttackPath] = field(default_factory=list)
    graph_stats: Dict[str, int] = field(default_factory=dict)

    @property
    def critical_paths(self) -> List[AttackPath]:
        return [p for p in self.paths if p.severity == Severity.CRITICAL]

    @property
    def high_paths(self) -> List[AttackPath]:
        return [p for p in self.paths if p.severity == Severity.HIGH]

    @property
    def cross_system_paths(self) -> List[AttackPath]:
        return [p for p in self.paths if p.cross_system]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_paths": len(self.paths),
            "critical": len(self.critical_paths),
            "high": len(self.high_paths),
            "cross_system": len(self.cross_system_paths),
            "graph": self.graph_stats,
            "paths": [p.to_dict() for p in self.paths],
        }


# ── Main entry point ────────────────────────────────────────────────

def analyze_attack_paths(identities: List[Identity]) -> AttackPathResult:
    """Run full attack path analysis on scan results.

    1. Build identity graph from scan data
    2. Find all paths from entry points to privileged nodes
    3. Score each path by blast radius
    4. Return sorted results
    """
    graph = build_graph(identities)

    result = AttackPathResult(
        graph_stats=graph.to_dict(),
    )

    entry_nodes = graph.entry_points()
    priv_ids = {n.id for n in graph.privileged_nodes()}

    if not entry_nodes or not priv_ids:
        logger.info("No attack paths: %d entries, %d privileged",
                     len(entry_nodes), len(priv_ids))
        return result

    # Find all paths from entry points to privileged nodes
    path_id = 0
    seen_path_keys: Set[str] = set()

    for entry in entry_nodes:
        paths = _bfs_paths(graph, entry.id, priv_ids, max_depth=8)
        for node_path, edge_path in paths:
            # Deduplicate by (entry, target) pair
            path_key = f"{node_path[0]}→{node_path[-1]}"
            if path_key in seen_path_keys:
                continue
            seen_path_keys.add(path_key)

            path_id += 1
            attack_path = _build_attack_path(
                graph, node_path, edge_path, f"AP-{path_id:03d}"
            )
            result.paths.append(attack_path)

    # Sort by severity then blast radius
    sev_order = {
        Severity.CRITICAL: 0, Severity.HIGH: 1,
        Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
    }
    result.paths.sort(
        key=lambda p: (sev_order.get(p.severity, 5), -p.blast_radius)
    )

    logger.info("Found %d attack paths (%d critical, %d high)",
                len(result.paths), len(result.critical_paths),
                len(result.high_paths))

    return result


# ── BFS path finder ─────────────────────────────────────────────────

def _bfs_paths(
    graph: IdentityGraph,
    start_id: str,
    target_ids: Set[str],
    max_depth: int = 8,
) -> List[tuple]:
    """BFS to find all paths from start to any target node.

    Returns list of (node_id_path, edge_path) tuples.
    """
    results = []
    # Queue: (current_node, path_of_nodes, path_of_edges)
    queue = [(start_id, [start_id], [])]

    while queue:
        current, node_path, edge_path = queue.pop(0)

        if len(node_path) > max_depth:
            continue

        # Check if we reached a privileged node (not the start itself)
        if current in target_ids and current != start_id:
            results.append((list(node_path), list(edge_path)))
            continue  # Don't explore past privileged nodes

        for edge in graph.neighbors(current):
            next_id = edge.target_id
            if next_id not in node_path:  # Avoid cycles
                queue.append((
                    next_id,
                    node_path + [next_id],
                    edge_path + [edge],
                ))

    return results


# ── Path construction ───────────────────────────────────────────────

def _build_attack_path(
    graph: IdentityGraph,
    node_ids: List[str],
    edges: List[GraphEdge],
    path_id: str,
) -> AttackPath:
    """Build an AttackPath object from a graph traversal result."""
    steps: List[AttackPathStep] = []

    for i, nid in enumerate(node_ids):
        node = graph.nodes.get(nid)
        if not node:
            continue

        edge_type = None
        edge_label = ""
        if i > 0 and i - 1 < len(edges):
            edge_type = edges[i - 1].edge_type.value
            edge_label = edges[i - 1].label

        steps.append(AttackPathStep(
            node_id=nid,
            node_label=node.label,
            node_type=node.node_type,
            provider=node.provider,
            edge_type=edge_type,
            edge_label=edge_label,
        ))

    # Determine properties
    providers = list(dict.fromkeys(s.provider for s in steps))
    cross_system = len(providers) > 1

    # Compute blast radius
    blast = _compute_blast_radius(graph, node_ids, edges, cross_system)

    # Determine severity
    severity = _compute_path_severity(
        graph, node_ids, edges, cross_system, blast
    )

    # Build description — reviewer-friendly wording
    entry_label = steps[0].node_label if steps else "?"
    target_label = steps[-1].node_label if steps else "?"
    target_node = graph.nodes.get(node_ids[-1])
    desc = f"{entry_label} can reach {target_label}"
    if target_node and target_node.is_privileged:
        meta = target_node.metadata
        role = meta.get("role_name", "")
        if role:
            desc = f"{entry_label} can reach {role} via {target_label}"
    if cross_system:
        desc += f" (crosses {' → '.join(providers)})"

    # Recommendation
    rec = _generate_recommendation(graph, node_ids, edges, cross_system)

    return AttackPath(
        id=path_id,
        steps=steps,
        severity=severity,
        blast_radius=blast,
        cross_system=cross_system,
        description=desc,
        recommendation=rec,
    )


# ── Blast radius scoring ───────────────────────────────────────────

def _compute_blast_radius(
    graph: IdentityGraph,
    node_ids: List[str],
    edges: List[GraphEdge],
    cross_system: bool,
) -> float:
    """Compute blast radius score (0–100) for an attack path.

    Factors:
    - Privilege level of target (0–30)
    - Cross-system reach (0–20)
    - Path length penalty (shorter = more dangerous) (0–15)
    - Credential age / risk flags (0–20)
    - Owner presence (0–15)
    """
    score = 0.0

    # 1. Privilege level of target node
    target_node = graph.nodes.get(node_ids[-1])
    if target_node and target_node.is_privileged:
        score += 30.0
        # Subscription-scope Azure or AWS admin gets extra
        meta = target_node.metadata
        if meta.get("role_name") in (
            "Owner", "User Access Administrator",
            "AdministratorAccess",
        ):
            score += 10.0

    # 2. Cross-system reach
    if cross_system:
        providers = set()
        for nid in node_ids:
            n = graph.nodes.get(nid)
            if n:
                providers.add(n.provider)
        score += min(len(providers) * 10.0, 20.0)

    # 3. Path length (shorter = more dangerous)
    path_len = len(node_ids)
    if path_len <= 2:
        score += 15.0
    elif path_len <= 3:
        score += 10.0
    elif path_len <= 5:
        score += 5.0

    # 4. Risk flags on identities in the path
    risk_bonus = 0.0
    for nid in node_ids:
        node = graph.nodes.get(nid)
        if node and node.identity:
            for flag in node.identity.risk_flags:
                if flag.severity == Severity.CRITICAL:
                    risk_bonus += 5.0
                elif flag.severity == Severity.HIGH:
                    risk_bonus += 3.0
    score += min(risk_bonus, 20.0)

    # 5. Owner presence (no owner = higher risk)
    no_owner_count = 0
    total_idents = 0
    for nid in node_ids:
        node = graph.nodes.get(nid)
        if node and node.identity:
            total_idents += 1
            if not node.identity.owner and not node.identity.created_by:
                no_owner_count += 1
    if total_idents > 0:
        orphan_ratio = no_owner_count / total_idents
        score += orphan_ratio * 15.0

    return min(score, 100.0)


# ── Severity classification ─────────────────────────────────────────

def _compute_path_severity(
    graph: IdentityGraph,
    node_ids: List[str],
    edges: List[GraphEdge],
    cross_system: bool,
    blast: float,
) -> Severity:
    """Determine severity of an attack path."""
    # Critical: cross-system path to admin, or blast > 70
    if blast >= 70:
        return Severity.CRITICAL
    if cross_system and blast >= 50:
        return Severity.CRITICAL

    # High: reaches privileged node, or blast > 50
    target = graph.nodes.get(node_ids[-1])
    if target and target.is_privileged and blast >= 40:
        return Severity.HIGH
    if blast >= 50:
        return Severity.HIGH

    # Medium: has some privilege or cross-system
    if cross_system or blast >= 25:
        return Severity.MEDIUM

    return Severity.LOW


# ── Recommendations ─────────────────────────────────────────────────

EDGE_RECOMMENDATIONS = {
    EdgeType.IRSA_MAPS_TO: (
        "Scope the IRSA role to least-privilege. "
        "Use condition keys to restrict to specific SA."
    ),
    EdgeType.AZURE_WI_MAPS_TO: (
        "Scope Azure role assignments to resource group level. "
        "Avoid subscription-wide Contributor/Owner."
    ),
    EdgeType.BOUND_TO_RBAC: (
        "Replace cluster-admin binding with namespace-scoped roles. "
        "Use Role instead of ClusterRole where possible."
    ),
    EdgeType.ASSUMES_ROLE: (
        "Tighten the role trust policy. "
        "Use condition keys (sts:ExternalId, source IP)."
    ),
    EdgeType.OWNS_KEY: (
        "Rotate or delete long-lived access keys. "
        "Prefer IAM roles with temporary credentials."
    ),
    EdgeType.APP_HAS_SECRET: (
        "Rotate expired/expiring client secrets. "
        "Use certificate credentials or federated identity."
    ),
    EdgeType.GCP_SA_HAS_KEY: (
        "Delete long-lived SA keys. "
        "Use Workload Identity Federation or attached service accounts instead."
    ),
    EdgeType.GCP_IAM_BINDING: (
        "Replace Owner/Editor with least-privilege custom roles. "
        "Scope bindings to specific resources."
    ),
    EdgeType.GCP_WI_MAPS_TO: (
        "Scope the GCP SA to least-privilege. "
        "Use IAM Conditions to restrict to specific K8s namespace/SA."
    ),
    EdgeType.OIDC_ASSUMES_ROLE: (
        "Restrict the OIDC trust policy to specific repos/branches. "
        "Use sub claim conditions (repo:org/repo:ref:refs/heads/main). "
        "Replace admin policies with least-privilege scoped to deployment needs."
    ),
    EdgeType.ACCESSES_RESOURCE: (
        "Apply least-privilege access to each cloud resource. "
        "Scope credentials to only the specific resources and actions needed. "
        "Add environment protection rules and branch restrictions on the workflow."
    ),
}


def _generate_recommendation(
    graph: IdentityGraph,
    node_ids: List[str],
    edges: List[GraphEdge],
    cross_system: bool,
) -> str:
    """Generate a targeted recommendation for an attack path."""
    recs = []

    for edge in edges:
        rec = EDGE_RECOMMENDATIONS.get(edge.edge_type)
        if rec and rec not in recs:
            recs.append(rec)

    if cross_system:
        recs.append(
            "This path crosses system boundaries. "
            "Apply defense-in-depth at each boundary."
        )

    if not recs:
        recs.append("Review and reduce permissions along this path.")

    return " ".join(recs[:3])

# MIT License — Copyright (c) 2026 cvemula1
# Mermaid diagram renderer for NHInsight attack path analysis

from __future__ import annotations

import re
import sys
from typing import TextIO

from nhinsight.core.models import Severity

# Provider → Mermaid CSS class color
PROVIDER_STYLES = {
    "aws": "fill:#FF9900,stroke:#232F3E,color:#232F3E",
    "azure": "fill:#0078D4,stroke:#002050,color:#fff",
    "gcp": "fill:#4285F4,stroke:#174EA6,color:#fff",
    "github": "fill:#6e40c9,stroke:#3b1f6e,color:#fff",
    "kubernetes": "fill:#326CE5,stroke:#1a3a6e,color:#fff",
}

SEVERITY_STYLES = {
    Severity.CRITICAL: "fill:#d32f2f,stroke:#b71c1c,color:#fff",
    Severity.HIGH: "fill:#e65100,stroke:#bf360c,color:#fff",
    Severity.MEDIUM: "fill:#f9a825,stroke:#f57f17,color:#000",
    Severity.LOW: "fill:#1565c0,stroke:#0d47a1,color:#fff",
    Severity.INFO: "fill:#2e7d32,stroke:#1b5e20,color:#fff",
}

SEVERITY_LABELS = {
    Severity.CRITICAL: "🔴 CRITICAL",
    Severity.HIGH: "🟠 HIGH",
    Severity.MEDIUM: "🟡 MEDIUM",
    Severity.LOW: "🔵 LOW",
    Severity.INFO: "🟢 INFO",
}


def _sanitize_id(raw_id: str) -> str:
    """Convert a node ID into a Mermaid-safe identifier."""
    return re.sub(r"[^a-zA-Z0-9_]", "_", raw_id)


def _sanitize_label(label: str) -> str:
    """Escape characters that break Mermaid labels."""
    return label.replace('"', "'").replace("<", "‹").replace(">", "›")


def render_attack_paths(ap_result, out: TextIO = sys.stdout) -> None:
    """Render attack path results as a Mermaid flowchart.

    Produces a single ``flowchart LR`` diagram with all discovered paths.
    Nodes are colored by provider; edges carry relationship labels.
    """
    paths = ap_result.paths
    if not paths:
        out.write("```mermaid\nflowchart LR\n  NO_PATHS[\"✅ No privilege escalation paths found\"]\n```\n")
        return

    lines: list[str] = []
    lines.append("```mermaid")
    lines.append("flowchart LR")

    # Collect unique nodes and edges across all paths
    seen_nodes: dict[str, tuple[str, str, str]] = {}  # sanitized_id → (label, provider, node_type)
    seen_edges: list[tuple[str, str, str]] = []  # (src, dst, label)
    edge_set: set[str] = set()
    path_node_sets: list[tuple[str, list[str]]] = []  # (path_id, [sanitized_ids])

    for path in paths:
        path_nodes = []
        for i, step in enumerate(path.steps):
            sid = _sanitize_id(step.node_id)
            if sid not in seen_nodes:
                seen_nodes[sid] = (step.node_label, step.provider, step.node_type)
            path_nodes.append(sid)

            if i > 0:
                prev_sid = _sanitize_id(path.steps[i - 1].node_id)
                edge_label = step.edge_label or ""
                edge_key = f"{prev_sid}→{sid}"
                if edge_key not in edge_set:
                    edge_set.add(edge_key)
                    seen_edges.append((prev_sid, sid, edge_label))

        path_node_sets.append((path.id, path_nodes))

    # Group nodes by provider for subgraphs
    by_provider: dict[str, list[str]] = {}
    for sid, (label, provider, node_type) in seen_nodes.items():
        by_provider.setdefault(provider, []).append(sid)

    # Emit subgraphs per provider
    for provider, node_ids in sorted(by_provider.items()):
        provider_label = {
            "aws": "AWS", "azure": "Azure", "gcp": "GCP",
            "github": "GitHub", "kubernetes": "Kubernetes",
        }.get(provider, provider.upper())

        lines.append(f"  subgraph {provider_label}")
        for sid in node_ids:
            label, _, node_type = seen_nodes[sid]
            safe_label = _sanitize_label(label)
            # Use different shapes: rounded for identities, hexagon for privileged roles
            if "rbac" in node_type or "iam_role" in node_type or "permissions" in node_type:
                lines.append(f'    {sid}{{{{{safe_label}}}}}')
            else:
                lines.append(f'    {sid}["{safe_label}"]')
        lines.append("  end")

    # Emit edges
    for src, dst, label in seen_edges:
        safe_label = _sanitize_label(label)
        if safe_label:
            lines.append(f'  {src} -->|"{safe_label}"| {dst}')
        else:
            lines.append(f"  {src} --> {dst}")

    # Emit style classes per provider
    for provider, node_ids in by_provider.items():
        style = PROVIDER_STYLES.get(provider, "fill:#999,stroke:#666,color:#fff")
        for sid in node_ids:
            lines.append(f"  style {sid} {style}")

    lines.append("```")

    out.write("\n".join(lines))
    out.write("\n")


def render_attack_paths_individual(ap_result, out: TextIO = sys.stdout) -> None:
    """Render each attack path as its own small Mermaid diagram.

    Useful for PR comments where you want one diagram per finding.
    """
    paths = ap_result.paths
    if not paths:
        out.write("```mermaid\nflowchart LR\n  OK[\"✅ No privilege escalation paths found\"]\n```\n")
        return

    for path in paths:
        sev_label = SEVERITY_LABELS.get(path.severity, path.severity.value.upper())
        out.write(f"\n**{path.id}** — {sev_label} — risk {path.blast_radius:.0f}/100")
        if path.cross_system:
            out.write(" ⚡ cross-system")
        out.write("\n\n")

        lines: list[str] = []
        lines.append("```mermaid")
        lines.append("flowchart LR")

        for i, step in enumerate(path.steps):
            sid = _sanitize_id(step.node_id)
            safe_label = _sanitize_label(step.node_label)
            prov = step.provider

            # Shape by node type
            if "rbac" in step.node_type or "iam_role" in step.node_type or "permissions" in step.node_type:
                lines.append(f'  {sid}{{{{{safe_label}<br/><i>{prov}</i>}}}}')
            else:
                lines.append(f'  {sid}["{safe_label}<br/><i>{prov}</i>"]')

            # Style
            style = PROVIDER_STYLES.get(prov, "fill:#999,stroke:#666,color:#fff")
            lines.append(f"  style {sid} {style}")

            # Edge to next
            if i > 0:
                prev_sid = _sanitize_id(path.steps[i - 1].node_id)
                edge_label = _sanitize_label(step.edge_label or "")
                if edge_label:
                    lines.append(f'  {prev_sid} -->|"{edge_label}"| {sid}')
                else:
                    lines.append(f"  {prev_sid} --> {sid}")

        lines.append("```")
        out.write("\n".join(lines))
        out.write("\n")

        if path.recommendation:
            out.write(f"\n> 💡 {path.recommendation[:200]}\n")


def render_summary_table(ap_result, out: TextIO = sys.stdout) -> None:
    """Render a markdown summary table of attack paths."""
    paths = ap_result.paths
    stats = ap_result.graph_stats

    out.write("## Privilege Escalation Paths\n\n")
    out.write(f"Graph: {stats.get('nodes', 0)} nodes, ")
    out.write(f"{stats.get('edges', 0)} edges, ")
    out.write(f"{stats.get('entry_points', 0)} entry points, ")
    out.write(f"{stats.get('privileged_nodes', 0)} privileged\n\n")

    if not paths:
        out.write("✅ No privilege escalation paths found.\n")
        return

    out.write("| Path | Severity | Risk | Entry → Target | Providers | Fix |\n")
    out.write("|------|----------|------|----------------|-----------|-----|\n")

    for path in paths:
        sev = path.severity.value.upper()
        risk = f"{path.blast_radius:.0f}/100"
        entry = path.steps[0].node_label if path.steps else "?"
        target = path.steps[-1].node_label if path.steps else "?"
        provs = " → ".join(path.providers_involved)
        rec = (path.recommendation or "")[:80]
        cross = " ⚡" if path.cross_system else ""
        out.write(f"| {path.id} | {sev} | {risk} | {entry} → {target}{cross} | {provs} | {rec} |\n")

    out.write("\n")

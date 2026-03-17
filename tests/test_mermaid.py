# MIT License — Copyright (c) 2026 cvemula1
# Tests for Mermaid diagram renderer

import io
import json
import subprocess
import sys
import tempfile

from nhinsight.analyzers.attack_paths import (
    AttackPath,
    AttackPathResult,
    AttackPathStep,
    analyze_attack_paths,
)
from nhinsight.core.mermaid import (
    render_attack_paths,
    render_attack_paths_individual,
    render_summary_table,
)
from nhinsight.core.models import (
    Identity,
    IdentityType,
    Provider,
    RiskFlag,
    Severity,
)


# ── Helpers ────────────────────────────────────────────────────────────


def _iam_user(name, policies=None, arn=""):
    return Identity(
        id=f"aws:iam:user:123:{name}",
        name=name,
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_USER,
        arn=arn or f"arn:aws:iam::123:user/{name}",
        policies=policies or [],
    )


def _iam_role(name, policies=None, trusted=None):
    return Identity(
        id=f"aws:iam:role:123:{name}",
        name=name,
        provider=Provider.AWS,
        identity_type=IdentityType.IAM_ROLE,
        arn=f"arn:aws:iam::123:role/{name}",
        policies=policies or [],
        raw={"trusted_principals": trusted or [], "path": "/"},
    )


def _access_key(user, key_id="AKIA1234"):
    return Identity(
        id=f"aws:iam:key:123:{key_id}",
        name=f"{user}/{key_id}",
        provider=Provider.AWS,
        identity_type=IdentityType.ACCESS_KEY,
        raw={"parent_user": user, "key_id": key_id, "status": "Active"},
    )


def _k8s_sa(ns, name, irsa_arn="", policies=None):
    return Identity(
        id=f"k8s:sa:ctx:{ns}:{name}",
        name=f"{ns}/{name}",
        provider=Provider.KUBERNETES,
        identity_type=IdentityType.SERVICE_ACCOUNT,
        policies=policies or [],
        raw={
            "namespace": ns,
            "sa_name": name,
            "irsa_role_arn": irsa_arn,
            "workload_identity_azure": "",
            "deployments": [],
            "secret_count": 0,
            "automount_token": True,
        },
    )


def _build_simple_ap_result():
    """Build a minimal AttackPathResult for testing."""
    steps = [
        AttackPathStep(
            node_id="k8s:sa:ctx:prod:deploy-sa",
            node_label="prod/deploy-sa",
            node_type="service_account",
            provider="kubernetes",
        ),
        AttackPathStep(
            node_id="aws:iam:role:123:eks-admin",
            node_label="eks-admin",
            node_type="iam_role",
            provider="aws",
            edge_type="irsa_maps_to",
            edge_label="IRSA → eks-admin",
        ),
    ]
    path = AttackPath(
        id="AP-001",
        steps=steps,
        severity=Severity.CRITICAL,
        blast_radius=85.0,
        cross_system=True,
        description="prod/deploy-sa → eks-admin (cross-system: kubernetes → aws)",
        recommendation="Scope the IRSA role to least-privilege.",
    )
    return AttackPathResult(
        paths=[path],
        graph_stats={"nodes": 5, "edges": 4, "entry_points": 2, "privileged_nodes": 1},
    )


# ── render_attack_paths tests ──────────────────────────────────────────


def test_render_attack_paths_basic():
    """Basic Mermaid rendering produces valid flowchart."""
    ap_result = _build_simple_ap_result()
    out = io.StringIO()
    render_attack_paths(ap_result, out=out)
    output = out.getvalue()

    assert "```mermaid" in output
    assert "flowchart LR" in output
    assert "```" in output
    assert "deploy_sa" in output or "deploy-sa" in output  # sanitized ID
    assert "eks_admin" in output or "eks-admin" in output


def test_render_attack_paths_empty():
    """Empty result produces 'no paths found' diagram."""
    ap_result = AttackPathResult(paths=[], graph_stats={})
    out = io.StringIO()
    render_attack_paths(ap_result, out=out)
    output = out.getvalue()

    assert "```mermaid" in output
    assert "No privilege escalation paths found" in output


def test_render_attack_paths_has_subgraphs():
    """Cross-system paths produce provider subgraphs."""
    ap_result = _build_simple_ap_result()
    out = io.StringIO()
    render_attack_paths(ap_result, out=out)
    output = out.getvalue()

    assert "subgraph AWS" in output
    assert "subgraph Kubernetes" in output


def test_render_attack_paths_has_styles():
    """Nodes get provider-colored styles."""
    ap_result = _build_simple_ap_result()
    out = io.StringIO()
    render_attack_paths(ap_result, out=out)
    output = out.getvalue()

    assert "fill:#FF9900" in output  # AWS orange
    assert "fill:#326CE5" in output  # K8s blue


def test_render_attack_paths_edge_labels():
    """Edges carry relationship labels."""
    ap_result = _build_simple_ap_result()
    out = io.StringIO()
    render_attack_paths(ap_result, out=out)
    output = out.getvalue()

    assert "IRSA" in output


# ── render_attack_paths_individual tests ───────────────────────────────


def test_render_individual_basic():
    """Individual rendering produces separate diagrams per path."""
    ap_result = _build_simple_ap_result()
    out = io.StringIO()
    render_attack_paths_individual(ap_result, out=out)
    output = out.getvalue()

    assert "AP-001" in output
    assert "CRITICAL" in output
    assert "```mermaid" in output
    assert "💡" in output  # recommendation


def test_render_individual_empty():
    """Empty result produces 'no paths' diagram."""
    ap_result = AttackPathResult(paths=[], graph_stats={})
    out = io.StringIO()
    render_attack_paths_individual(ap_result, out=out)
    output = out.getvalue()

    assert "No privilege escalation paths found" in output


# ── render_summary_table tests ─────────────────────────────────────────


def test_summary_table_basic():
    """Summary table includes headers and path data."""
    ap_result = _build_simple_ap_result()
    out = io.StringIO()
    render_summary_table(ap_result, out=out)
    output = out.getvalue()

    assert "## Privilege Escalation Paths" in output
    assert "| Path |" in output
    assert "AP-001" in output
    assert "CRITICAL" in output
    assert "85/100" in output
    assert "⚡" in output  # cross-system


def test_summary_table_empty():
    """Empty result shows no-paths message."""
    ap_result = AttackPathResult(paths=[], graph_stats={"nodes": 0, "edges": 0})
    out = io.StringIO()
    render_summary_table(ap_result, out=out)
    output = out.getvalue()

    assert "No privilege escalation paths found" in output


# ── Integration with real attack path analysis ─────────────────────────


def test_mermaid_from_real_analysis():
    """Render Mermaid from a real analyze_attack_paths result."""
    role = _iam_role("admin", policies=["AdministratorAccess"])
    sa = _k8s_sa("prod", "app", irsa_arn=role.arn)

    ap_result = analyze_attack_paths([role, sa])

    out = io.StringIO()
    render_attack_paths(ap_result, out=out)
    output = out.getvalue()

    assert "```mermaid" in output
    assert "flowchart LR" in output


def test_mermaid_from_multi_provider():
    """Mermaid renders correctly with multiple providers."""
    role = _iam_role("eks-admin", policies=["AdministratorAccess"])
    sa = _k8s_sa("prod", "deploy", irsa_arn=role.arn)
    user = _iam_user("deploy-bot", arn="arn:aws:iam::123:user/deploy-bot")
    key = _access_key("deploy-bot", "AKIA5678")

    ap_result = analyze_attack_paths([role, sa, user, key])

    out = io.StringIO()
    render_attack_paths(ap_result, out=out)
    output = out.getvalue()

    assert "```mermaid" in output
    # Should have at least one path
    if ap_result.paths:
        assert "subgraph" in output


# ── CLI integration tests ──────────────────────────────────────────────


def test_demo_mermaid_flag():
    """nhinsight demo --mermaid produces Mermaid output."""
    result = subprocess.run(
        [sys.executable, "-m", "nhinsight.cli", "demo", "--mermaid"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "```mermaid" in result.stdout or "Privilege Escalation Paths" in result.stdout


def test_demo_attack_paths_flag():
    """nhinsight demo --attack-paths produces attack path output."""
    result = subprocess.run(
        [sys.executable, "-m", "nhinsight.cli", "demo", "--attack-paths"],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "Privilege Escalation Paths" in result.stdout


def test_graph_command_with_json():
    """nhinsight graph --input file.json renders Mermaid from saved JSON."""
    ap_result = _build_simple_ap_result()
    data = {"attack_paths": ap_result.to_dict()}

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(data, f)
        f.flush()
        json_path = f.name

    result = subprocess.run(
        [sys.executable, "-m", "nhinsight.cli", "graph", "--input", json_path],
        capture_output=True, text=True,
    )
    assert result.returncode == 0
    assert "```mermaid" in result.stdout
    assert "AP-001" in result.stdout


def test_graph_command_missing_file():
    """nhinsight graph --input nonexistent.json fails gracefully."""
    result = subprocess.run(
        [sys.executable, "-m", "nhinsight.cli", "graph", "--input", "/tmp/nonexistent_nhinsight.json"],
        capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "file not found" in result.stdout


def test_graph_command_invalid_json():
    """nhinsight graph --input bad.json fails gracefully."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("not json")
        f.flush()
        bad_path = f.name

    result = subprocess.run(
        [sys.executable, "-m", "nhinsight.cli", "graph", "--input", bad_path],
        capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "invalid JSON" in result.stdout

# MIT License — Copyright (c) 2026 cvemula1
# Identity Graph — models NHIs and their relationships as a directed graph

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from nhinsight.core.models import Identity, IdentityType, Provider

logger = logging.getLogger(__name__)


class EdgeType(str, Enum):
    """Relationship types between identity graph nodes."""
    OWNS_KEY = "owns_key"                   # IAM user → access key
    ASSUMES_ROLE = "assumes_role"           # principal → IAM role (trust)
    HAS_POLICY = "has_policy"               # identity → policy/role binding
    IRSA_MAPS_TO = "irsa_maps_to"           # K8s SA → AWS IAM role (IRSA)
    AZURE_WI_MAPS_TO = "azure_wi_maps_to"  # K8s SA → Azure MI (WI)
    BOUND_TO_RBAC = "bound_to_rbac"         # K8s SA → ClusterRole/Role
    USES_SECRET = "uses_secret"             # K8s SA → K8s secret
    RUNS_AS = "runs_as"                     # K8s deployment → K8s SA
    AUTHENTICATES = "authenticates"         # credential → service/resource
    APP_HAS_SECRET = "app_has_secret"       # Azure app → app secret/cert
    AZURE_RBAC = "azure_rbac"              # Azure SP/MI → RBAC role
    GCP_SA_HAS_KEY = "gcp_sa_has_key"       # GCP SA key → GCP SA
    GCP_IAM_BINDING = "gcp_iam_binding"     # GCP SA → IAM role
    GCP_WI_MAPS_TO = "gcp_wi_maps_to"       # K8s SA → GCP SA (GKE WI)
    DEPLOYS_TO = "deploys_to"               # GitHub App → target
    OIDC_ASSUMES_ROLE = "oidc_assumes_role"  # GH Actions OIDC → cloud role
    ACCESSES_RESOURCE = "accesses_resource"  # identity → cloud/infra resource


@dataclass
class GraphNode:
    """A node in the identity graph."""
    id: str
    label: str
    node_type: str          # identity type or "resource"
    provider: str
    identity: Optional[Identity] = None
    is_privileged: bool = False
    is_entry_point: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """A directed edge in the identity graph."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IdentityGraph:
    """Directed graph of identities and their relationships."""
    nodes: Dict[str, GraphNode] = field(default_factory=dict)
    edges: List[GraphEdge] = field(default_factory=list)
    _adjacency: Dict[str, List[GraphEdge]] = field(default_factory=dict)
    _reverse_adj: Dict[str, List[GraphEdge]] = field(default_factory=dict)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)
        self._adjacency.setdefault(edge.source_id, []).append(edge)
        self._reverse_adj.setdefault(edge.target_id, []).append(edge)

    def neighbors(self, node_id: str) -> List[GraphEdge]:
        """Get outgoing edges from a node."""
        return self._adjacency.get(node_id, [])

    def predecessors(self, node_id: str) -> List[GraphEdge]:
        """Get incoming edges to a node."""
        return self._reverse_adj.get(node_id, [])

    def entry_points(self) -> List[GraphNode]:
        """Get all entry point nodes (external-facing identities)."""
        return [n for n in self.nodes.values() if n.is_entry_point]

    def privileged_nodes(self) -> List[GraphNode]:
        """Get all privileged/sensitive nodes."""
        return [n for n in self.nodes.values() if n.is_privileged]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "entry_points": len(self.entry_points()),
            "privileged_nodes": len(self.privileged_nodes()),
        }


# ── Privileged resource patterns ────────────────────────────────────

ADMIN_POLICIES = {
    "AdministratorAccess", "IAMFullAccess", "PowerUserAccess",
    "AmazonS3FullAccess", "AmazonEC2FullAccess",
}

DANGEROUS_AZURE_ROLES = {
    "Owner", "Contributor", "User Access Administrator",
    "Key Vault Administrator", "Key Vault Secrets Officer",
}

K8S_ADMIN_ROLES = {"cluster-admin", "admin"}

GCP_DANGEROUS_ROLES = {
    "roles/owner", "roles/editor",
    "roles/iam.securityAdmin", "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountKeyAdmin", "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser", "roles/resourcemanager.projectIamAdmin",
    "roles/compute.admin", "roles/container.admin",
    "roles/storage.admin", "roles/secretmanager.admin",
}

ADMIN_GH_SCOPES = {
    "admin:org", "admin:repo_hook", "admin:enterprise", "delete_repo",
}

# Identity types that are external entry points
# Credentials, tokens, and identities assignable to compute resources
ENTRY_POINT_TYPES = {
    IdentityType.ACCESS_KEY,
    IdentityType.GITHUB_APP,
    IdentityType.GITHUB_PAT,
    IdentityType.DEPLOY_KEY,
    IdentityType.WEBHOOK,
    IdentityType.AZURE_APP_SECRET,
    IdentityType.AZURE_APP_CERT,
    IdentityType.AZURE_SP,
    IdentityType.AZURE_MANAGED_IDENTITY,
    IdentityType.GCP_SERVICE_ACCOUNT,
    IdentityType.GCP_SA_KEY,
    IdentityType.K8S_SECRET,
    IdentityType.IAM_USER,
    IdentityType.GITHUB_ACTIONS_OIDC,
}


# ── Graph Construction ──────────────────────────────────────────────

def build_graph(identities: List[Identity]) -> IdentityGraph:
    """Build an identity graph from scan results.

    Constructs nodes for each identity and edges for relationships
    detected from raw provider data.
    """
    graph = IdentityGraph()

    # Index identities by various keys for cross-referencing
    by_id: Dict[str, Identity] = {}
    by_arn: Dict[str, Identity] = {}
    by_type: Dict[IdentityType, List[Identity]] = {}
    azure_by_appid: Dict[str, Identity] = {}
    azure_by_objectid: Dict[str, Identity] = {}
    gcp_sa_by_email: Dict[str, Identity] = {}
    k8s_sa_by_key: Dict[str, Identity] = {}

    for ident in identities:
        by_id[ident.id] = ident
        by_type.setdefault(ident.identity_type, []).append(ident)

        if ident.arn:
            by_arn[ident.arn] = ident

        if ident.provider == Provider.AZURE:
            app_id = ident.raw.get("app_id", "")
            obj_id = ident.raw.get("object_id", "")
            # Only index SP/MI, not secrets (avoid overwrite)
            if app_id and ident.identity_type in (
                IdentityType.AZURE_SP,
                IdentityType.AZURE_MANAGED_IDENTITY,
            ):
                azure_by_appid[app_id] = ident
            if obj_id:
                azure_by_objectid[obj_id] = ident

        if ident.identity_type == IdentityType.GCP_SERVICE_ACCOUNT:
            email = ident.raw.get("email", "")
            if email:
                gcp_sa_by_email[email] = ident

        if ident.identity_type == IdentityType.SERVICE_ACCOUNT:
            ns = ident.raw.get("namespace", "")
            sa = ident.raw.get("sa_name", "")
            if ns and sa:
                k8s_sa_by_key[f"{ns}/{sa}"] = ident

    # ── 1. Create nodes ─────────────────────────────────────────
    for ident in identities:
        is_priv = _is_privileged(ident)
        is_entry = ident.identity_type in ENTRY_POINT_TYPES

        # All K8s SAs are entry points (any pod compromise = SA access)
        if ident.identity_type == IdentityType.SERVICE_ACCOUNT:
            is_entry = True

        node = GraphNode(
            id=ident.id,
            label=ident.name,
            node_type=ident.identity_type.value,
            provider=ident.provider.value,
            identity=ident,
            is_privileged=is_priv,
            is_entry_point=is_entry,
        )
        graph.add_node(node)

    # ── 2. Build edges ──────────────────────────────────────────

    # AWS: access key → user (attacker perspective: steal key, act as user)
    for key in by_type.get(IdentityType.ACCESS_KEY, []):
        parent = key.raw.get("parent_user", "")
        if parent:
            parent_id = _find_user_id(parent, by_id)
            if parent_id:
                graph.add_edge(GraphEdge(
                    source_id=key.id,
                    target_id=parent_id,
                    edge_type=EdgeType.OWNS_KEY,
                    label=f"authenticates as {parent}",
                ))

    # AWS: role trust → who can assume it
    for role in by_type.get(IdentityType.IAM_ROLE, []):
        trusted = role.raw.get("trusted_principals", [])
        for principal in trusted:
            # Match principal ARN to known identities
            if principal in by_arn:
                graph.add_edge(GraphEdge(
                    source_id=by_arn[principal].id,
                    target_id=role.id,
                    edge_type=EdgeType.ASSUMES_ROLE,
                    label=f"assumes role {role.name}",
                ))
            elif principal == "*":
                # Wildcard trust — any AWS principal
                role_node = graph.nodes.get(role.id)
                if role_node:
                    role_node.metadata["wildcard_trust"] = True

    # K8s SA → AWS role (IRSA)
    for sa in by_type.get(IdentityType.SERVICE_ACCOUNT, []):
        irsa_arn = sa.raw.get("irsa_role_arn", "")
        if irsa_arn:
            # Find the matching AWS role by ARN
            target = by_arn.get(irsa_arn)
            if target:
                graph.add_edge(GraphEdge(
                    source_id=sa.id,
                    target_id=target.id,
                    edge_type=EdgeType.IRSA_MAPS_TO,
                    label=f"IRSA → {target.name}",
                ))
            else:
                # Create a synthetic node for the AWS role
                synth_id = f"aws:iam:role:irsa:{irsa_arn}"
                role_name = irsa_arn.split("/")[-1] if "/" in irsa_arn else irsa_arn
                graph.add_node(GraphNode(
                    id=synth_id,
                    label=role_name,
                    node_type="iam_role",
                    provider="aws",
                    is_privileged=False,
                    metadata={"arn": irsa_arn, "synthetic": True},
                ))
                graph.add_edge(GraphEdge(
                    source_id=sa.id,
                    target_id=synth_id,
                    edge_type=EdgeType.IRSA_MAPS_TO,
                    label=f"IRSA → {role_name}",
                ))

    # K8s SA → Azure Managed Identity (Workload Identity)
    for sa in by_type.get(IdentityType.SERVICE_ACCOUNT, []):
        wi_client_id = sa.raw.get("workload_identity_azure", "")
        if wi_client_id:
            # Match by app_id (client_id == app_id for MIs)
            target = azure_by_appid.get(wi_client_id)
            if target:
                graph.add_edge(GraphEdge(
                    source_id=sa.id,
                    target_id=target.id,
                    edge_type=EdgeType.AZURE_WI_MAPS_TO,
                    label=f"Azure WI → {target.name}",
                ))
            else:
                synth_id = f"azure:mi:wi:{wi_client_id}"
                graph.add_node(GraphNode(
                    id=synth_id,
                    label=f"Azure MI ({wi_client_id[:8]}...)",
                    node_type="azure_managed_identity",
                    provider="azure",
                    metadata={"client_id": wi_client_id, "synthetic": True},
                ))
                graph.add_edge(GraphEdge(
                    source_id=sa.id,
                    target_id=synth_id,
                    edge_type=EdgeType.AZURE_WI_MAPS_TO,
                    label=f"Azure WI → {wi_client_id[:8]}...",
                ))

    # K8s SA → RBAC role bindings
    for sa in by_type.get(IdentityType.SERVICE_ACCOUNT, []):
        for policy in sa.policies:
            role_id = f"k8s:rbac:{policy}"
            is_admin = any(
                admin in policy for admin in K8S_ADMIN_ROLES
            )
            if role_id not in graph.nodes:
                graph.add_node(GraphNode(
                    id=role_id,
                    label=policy,
                    node_type="k8s_rbac_role",
                    provider="kubernetes",
                    is_privileged=is_admin,
                    metadata={"role_ref": policy},
                ))
            graph.add_edge(GraphEdge(
                source_id=sa.id,
                target_id=role_id,
                edge_type=EdgeType.BOUND_TO_RBAC,
                label=f"bound to {policy}",
            ))

    # K8s secret → SA (token secrets)
    for secret in by_type.get(IdentityType.K8S_SECRET, []):
        sa_name = secret.raw.get("service_account", "")
        ns = secret.raw.get("namespace", "")
        if sa_name and ns:
            sa_key = f"{ns}/{sa_name}"
            target = k8s_sa_by_key.get(sa_key)
            if target:
                graph.add_edge(GraphEdge(
                    source_id=secret.id,
                    target_id=target.id,
                    edge_type=EdgeType.USES_SECRET,
                    label=f"token for SA {sa_key}",
                ))

    # K8s deployment → SA (from raw deployment data)
    for sa in by_type.get(IdentityType.SERVICE_ACCOUNT, []):
        deploys = sa.raw.get("deployments", [])
        for dep_name in deploys:
            ns = sa.raw.get("namespace", "")
            dep_id = f"k8s:deploy:{ns}:{dep_name}"
            if dep_id not in graph.nodes:
                graph.add_node(GraphNode(
                    id=dep_id,
                    label=f"{ns}/{dep_name}",
                    node_type="k8s_deployment",
                    provider="kubernetes",
                    is_entry_point=True,
                    metadata={"namespace": ns, "deployment": dep_name},
                ))
            graph.add_edge(GraphEdge(
                source_id=dep_id,
                target_id=sa.id,
                edge_type=EdgeType.RUNS_AS,
                label=f"runs as SA {sa.name}",
            ))

    # Azure: SP/MI → RBAC roles
    for ident in (
        by_type.get(IdentityType.AZURE_SP, [])
        + by_type.get(IdentityType.AZURE_MANAGED_IDENTITY, [])
    ):
        for policy in ident.policies:
            role_id = f"azure:rbac:{hash(policy) & 0xFFFFFFFF}"
            role_name = policy.split(" @ ")[0] if " @ " in policy else policy
            scope = policy.split(" @ ")[1] if " @ " in policy else ""
            is_dangerous = role_name in DANGEROUS_AZURE_ROLES and (
                "/subscriptions/" in scope and "/resourceGroups/" not in scope
            )
            if role_id not in graph.nodes:
                graph.add_node(GraphNode(
                    id=role_id,
                    label=policy,
                    node_type="azure_rbac_role",
                    provider="azure",
                    is_privileged=is_dangerous,
                    metadata={"role_name": role_name, "scope": scope},
                ))
            graph.add_edge(GraphEdge(
                source_id=ident.id,
                target_id=role_id,
                edge_type=EdgeType.AZURE_RBAC,
                label=f"has role {role_name}",
            ))

    # Azure: App registration → app secrets/certs
    for cred in (
        by_type.get(IdentityType.AZURE_APP_SECRET, [])
        + by_type.get(IdentityType.AZURE_APP_CERT, [])
    ):
        app_id = cred.raw.get("app_id", "")
        if app_id:
            # Find the matching SP
            sp = azure_by_appid.get(app_id)
            if sp and sp.id != cred.id:
                graph.add_edge(GraphEdge(
                    source_id=cred.id,
                    target_id=sp.id,
                    edge_type=EdgeType.APP_HAS_SECRET,
                    label=f"authenticates as {sp.name}",
                ))

    # GitHub App → permissions (create resource nodes for dangerous ones)
    for app in by_type.get(IdentityType.GITHUB_APP, []):
        perms = app.raw.get("all_permissions", {})
        dangerous = {
            k: v for k, v in perms.items()
            if v in ("write", "admin") and k in (
                "administration", "members", "organization",
                "actions", "contents", "packages",
            )
        }
        if dangerous:
            res_id = f"github:perms:{app.id}"
            graph.add_node(GraphNode(
                id=res_id,
                label=f"GH perms: {', '.join(dangerous.keys())}",
                node_type="github_permissions",
                provider="github",
                is_privileged=True,
                metadata={"permissions": dangerous},
            ))
            graph.add_edge(GraphEdge(
                source_id=app.id,
                target_id=res_id,
                edge_type=EdgeType.DEPLOYS_TO,
                label=f"has {', '.join(f'{k}:{v}' for k, v in dangerous.items())}",
            ))

    # GCP: SA key → GCP SA (attacker steals key, acts as SA)
    for key in by_type.get(IdentityType.GCP_SA_KEY, []):
        sa_email = key.raw.get("sa_email", "")
        if sa_email:
            target = gcp_sa_by_email.get(sa_email)
            if target:
                graph.add_edge(GraphEdge(
                    source_id=key.id,
                    target_id=target.id,
                    edge_type=EdgeType.GCP_SA_HAS_KEY,
                    label=f"authenticates as {target.name}",
                ))
            else:
                # Create synthetic node for the GCP SA
                synth_id = f"gcp:sa:synth:{sa_email}"
                sa_name = sa_email.split("@")[0] if "@" in sa_email else sa_email
                graph.add_node(GraphNode(
                    id=synth_id,
                    label=sa_name,
                    node_type="gcp_service_account",
                    provider="gcp",
                    metadata={"email": sa_email, "synthetic": True},
                ))
                graph.add_edge(GraphEdge(
                    source_id=key.id,
                    target_id=synth_id,
                    edge_type=EdgeType.GCP_SA_HAS_KEY,
                    label=f"authenticates as {sa_name}",
                ))

    # GCP: SA → IAM role bindings (dangerous roles become privileged nodes)
    for sa in by_type.get(IdentityType.GCP_SERVICE_ACCOUNT, []):
        for role in sa.policies:
            role_id = f"gcp:iam:{hash(role) & 0xFFFFFFFF}"
            is_dangerous = role in GCP_DANGEROUS_ROLES
            if role_id not in graph.nodes:
                graph.add_node(GraphNode(
                    id=role_id,
                    label=role,
                    node_type="gcp_iam_role",
                    provider="gcp",
                    is_privileged=is_dangerous,
                    metadata={"role": role},
                ))
            graph.add_edge(GraphEdge(
                source_id=sa.id,
                target_id=role_id,
                edge_type=EdgeType.GCP_IAM_BINDING,
                label=f"has role {role}",
            ))

    # K8s SA → GCP SA (GKE Workload Identity)
    for sa in by_type.get(IdentityType.SERVICE_ACCOUNT, []):
        wi_gcp = sa.raw.get("workload_identity_gcp", "") or sa.raw.get(
            "workload_identity_email", ""
        )
        if wi_gcp:
            target = gcp_sa_by_email.get(wi_gcp)
            if target:
                graph.add_edge(GraphEdge(
                    source_id=sa.id,
                    target_id=target.id,
                    edge_type=EdgeType.GCP_WI_MAPS_TO,
                    label=f"GKE WI → {target.name}",
                ))
            else:
                synth_id = f"gcp:sa:wi:{wi_gcp}"
                sa_name = wi_gcp.split("@")[0] if "@" in wi_gcp else wi_gcp
                graph.add_node(GraphNode(
                    id=synth_id,
                    label=sa_name,
                    node_type="gcp_service_account",
                    provider="gcp",
                    metadata={"email": wi_gcp, "synthetic": True},
                ))
                graph.add_edge(GraphEdge(
                    source_id=sa.id,
                    target_id=synth_id,
                    edge_type=EdgeType.GCP_WI_MAPS_TO,
                    label=f"GKE WI → {sa_name}",
                ))

    # GitHub Actions OIDC → cloud roles (AWS, Azure, GCP)
    for oidc in by_type.get(IdentityType.GITHUB_ACTIONS_OIDC, []):
        # AWS OIDC: role_arn in raw
        role_arn = oidc.raw.get("role_arn", "")
        if role_arn:
            target = by_arn.get(role_arn)
            if target:
                graph.add_edge(GraphEdge(
                    source_id=oidc.id,
                    target_id=target.id,
                    edge_type=EdgeType.OIDC_ASSUMES_ROLE,
                    label=f"OIDC → {target.name}",
                ))
            else:
                # Create synthetic AWS IAM role node
                synth_id = f"aws:iam:role:oidc:{role_arn}"
                role_name = role_arn.split("/")[-1] if "/" in role_arn else role_arn
                # Check if role is admin-privileged
                oidc_policies = oidc.raw.get("role_policies", [])
                is_priv = any(p in ADMIN_POLICIES for p in oidc_policies)
                if synth_id not in graph.nodes:
                    graph.add_node(GraphNode(
                        id=synth_id,
                        label=role_name,
                        node_type="iam_role",
                        provider="aws",
                        is_privileged=is_priv,
                        metadata={"arn": role_arn, "synthetic": True,
                                  "role_name": role_name,
                                  "policies": oidc_policies},
                    ))
                graph.add_edge(GraphEdge(
                    source_id=oidc.id,
                    target_id=synth_id,
                    edge_type=EdgeType.OIDC_ASSUMES_ROLE,
                    label=f"OIDC → {role_name}",
                ))
                # If the role has known policies, create policy nodes
                for pol in oidc_policies:
                    pol_id = f"aws:policy:oidc:{hash(pol) & 0xFFFFFFFF}"
                    is_admin_pol = pol in ADMIN_POLICIES
                    if pol_id not in graph.nodes:
                        graph.add_node(GraphNode(
                            id=pol_id,
                            label=pol,
                            node_type="iam_policy",
                            provider="aws",
                            is_privileged=is_admin_pol,
                            metadata={"policy": pol},
                        ))
                    graph.add_edge(GraphEdge(
                        source_id=synth_id,
                        target_id=pol_id,
                        edge_type=EdgeType.HAS_POLICY,
                        label=f"has {pol}",
                    ))

        # Azure OIDC: azure_client_id in raw
        az_client_id = oidc.raw.get("azure_client_id", "")
        if az_client_id:
            target = azure_by_appid.get(az_client_id)
            if target:
                graph.add_edge(GraphEdge(
                    source_id=oidc.id,
                    target_id=target.id,
                    edge_type=EdgeType.OIDC_ASSUMES_ROLE,
                    label=f"OIDC → {target.name}",
                ))
            else:
                synth_id = f"azure:sp:oidc:{az_client_id}"
                if synth_id not in graph.nodes:
                    graph.add_node(GraphNode(
                        id=synth_id,
                        label=f"Azure SP ({az_client_id[:8]}...)",
                        node_type="azure_sp",
                        provider="azure",
                        metadata={"client_id": az_client_id, "synthetic": True},
                    ))
                graph.add_edge(GraphEdge(
                    source_id=oidc.id,
                    target_id=synth_id,
                    edge_type=EdgeType.OIDC_ASSUMES_ROLE,
                    label="OIDC → Azure SP",
                ))

        # GCP OIDC: gcp_service_account in raw
        gcp_sa = oidc.raw.get("gcp_service_account", "")
        if gcp_sa:
            target = gcp_sa_by_email.get(gcp_sa)
            if target:
                graph.add_edge(GraphEdge(
                    source_id=oidc.id,
                    target_id=target.id,
                    edge_type=EdgeType.OIDC_ASSUMES_ROLE,
                    label=f"OIDC → {target.name}",
                ))
            else:
                synth_id = f"gcp:sa:oidc:{gcp_sa}"
                sa_name = gcp_sa.split("@")[0] if "@" in gcp_sa else gcp_sa
                if synth_id not in graph.nodes:
                    graph.add_node(GraphNode(
                        id=synth_id,
                        label=sa_name,
                        node_type="gcp_service_account",
                        provider="gcp",
                        metadata={"email": gcp_sa, "synthetic": True},
                    ))
                graph.add_edge(GraphEdge(
                    source_id=oidc.id,
                    target_id=synth_id,
                    edge_type=EdgeType.OIDC_ASSUMES_ROLE,
                    label=f"OIDC → {sa_name}",
                ))

    # GitHub Actions / OIDC identities → cloud resource access
    # Creates synthetic resource nodes for every detected cloud/infra resource
    _PRIVILEGED_RESOURCE_TYPES = {
        "azure_keyvault", "azure_aks", "azure_sql", "azure_cosmosdb",
        "azure_ad", "azure_iam", "azure_storage", "azure_dns",
        "aws_secrets", "aws_iam", "aws_s3", "aws_eks", "aws_rds",
        "gcp_secrets", "gcp_gke", "gcp_iam", "gcp_sql",
        "k8s_secret", "terraform", "pulumi",
    }
    _RESOURCE_PROVIDER_MAP = {
        "azure_": "azure", "aws_": "aws", "gcp_": "gcp",
        "k8s": "kubernetes", "helm": "kubernetes",
        "terraform": "iac", "pulumi": "iac", "ansible": "iac",
        "container_": "docker", "cloudflare": "cloudflare",
    }

    for oidc in by_type.get(IdentityType.GITHUB_ACTIONS_OIDC, []):
        cloud_resources = oidc.raw.get("cloud_resources", [])
        if not cloud_resources:
            continue

        for res in cloud_resources:
            rtype = res.get("resource_type", "") if isinstance(res, dict) else getattr(res, "resource_type", "")
            action = res.get("action", "") if isinstance(res, dict) else getattr(res, "action", "")
            rname = res.get("resource_name", "") if isinstance(res, dict) else getattr(res, "resource_name", "")
            severity = res.get("severity", "high") if isinstance(res, dict) else getattr(res, "severity", "high")

            if not rtype:
                continue

            # Determine provider for the resource node
            res_provider = "cloud"
            for prefix, prov in _RESOURCE_PROVIDER_MAP.items():
                if rtype.startswith(prefix):
                    res_provider = prov
                    break

            # Build a unique node ID for deduplication
            res_id = f"resource:{rtype}:{rname}" if rname else f"resource:{rtype}"
            label = f"{rname} ({action})" if rname else f"{rtype.replace('_', ' ').title()} ({action})"
            is_priv = rtype in _PRIVILEGED_RESOURCE_TYPES or severity == "critical"

            if res_id not in graph.nodes:
                graph.add_node(GraphNode(
                    id=res_id,
                    label=label,
                    node_type=rtype,
                    provider=res_provider,
                    is_privileged=is_priv,
                    metadata={
                        "resource_type": rtype,
                        "action": action,
                        "resource_name": rname,
                        "severity": severity,
                        "synthetic": True,
                    },
                ))
            graph.add_edge(GraphEdge(
                source_id=oidc.id,
                target_id=res_id,
                edge_type=EdgeType.ACCESSES_RESOURCE,
                label=f"{oidc.raw.get('auth_method', 'auth')} → {label}",
            ))

    logger.info(
        "Built identity graph: %d nodes, %d edges, "
        "%d entry points, %d privileged",
        len(graph.nodes), len(graph.edges),
        len(graph.entry_points()), len(graph.privileged_nodes()),
    )

    return graph


# ── Helpers ─────────────────────────────────────────────────────────

def _is_privileged(ident: Identity) -> bool:
    """Check if an identity has privileged access."""
    # Check policies
    for p in ident.policies:
        policy_name = p.split("/")[-1] if "/" in p else p
        if policy_name in ADMIN_POLICIES:
            return True
        # Azure role check
        role_name = p.split(" @ ")[0] if " @ " in p else p
        if role_name in DANGEROUS_AZURE_ROLES:
            scope = p.split(" @ ")[1] if " @ " in p else ""
            if "/subscriptions/" in scope and "/resourceGroups/" not in scope:
                return True

    # Check GCP IAM roles
    for p in ident.policies:
        if p in GCP_DANGEROUS_ROLES:
            return True

    # Check K8s RBAC
    for p in ident.policies:
        if any(admin in p for admin in K8S_ADMIN_ROLES):
            return True

    # Check risk flags
    admin_codes = {
        "AWS_ADMIN_ACCESS", "AWS_WILDCARD_TRUST",
        "AZURE_SP_DANGEROUS_ROLE", "AZURE_MI_DANGEROUS_ROLE",
        "GCP_SA_DANGEROUS_ROLE", "GCP_MANAGED_SA_OVERPRIVILEGED",
        "K8S_CLUSTER_ADMIN", "GH_ADMIN_SCOPE", "GH_APP_DANGEROUS_PERMS",
    }
    if any(f.code in admin_codes for f in ident.risk_flags):
        return True

    return False


def _find_user_id(username: str, by_id: Dict[str, Identity]) -> Optional[str]:
    """Find identity ID for an IAM user by username."""
    for ident_id, ident in by_id.items():
        if (
            ident.identity_type == IdentityType.IAM_USER
            and ident.name == username
        ):
            return ident_id
    return None

# MIT License — Copyright (c) 2026 cvemula1
# GitHub Actions Workflow Scanner — detect OIDC identity usage in CI/CD pipelines

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

from nhinsight.core.models import (
    Classification,
    Identity,
    IdentityType,
    Provider,
    RiskFlag,
    Severity,
)

logger = logging.getLogger(__name__)


# ── Known action patterns ─────────────────────────────────────────────

# AWS: aws-actions/configure-aws-credentials
_AWS_OIDC_RE = re.compile(
    r"uses:\s*aws-actions/configure-aws-credentials", re.IGNORECASE
)
_ROLE_ARN_RE = re.compile(
    r"role-to-assume:\s*(\S+)", re.IGNORECASE
)

# Azure: azure/login
_AZURE_OIDC_RE = re.compile(
    r"uses:\s*azure/login", re.IGNORECASE
)
_AZURE_CLIENT_ID_RE = re.compile(
    r"client-id:\s*(\S+)", re.IGNORECASE
)
_AZURE_TENANT_ID_RE = re.compile(
    r"tenant-id:\s*(\S+)", re.IGNORECASE
)

# GCP: google-github-actions/auth
_GCP_OIDC_RE = re.compile(
    r"uses:\s*google-github-actions/auth", re.IGNORECASE
)
_GCP_WIF_PROVIDER_RE = re.compile(
    r"workload_identity_provider:\s*(\S+)", re.IGNORECASE
)
_GCP_SA_RE = re.compile(
    r"service_account:\s*(\S+)", re.IGNORECASE
)

# OIDC permission detection (skip commented lines)
_OIDC_PERM_RE = re.compile(
    r"^[^#\n]*id-token:\s*write", re.IGNORECASE | re.MULTILINE
)
# permissions: write-all grants id-token: write implicitly
_WRITE_ALL_RE = re.compile(
    r"^[^#\n]*permissions:\s*write-all", re.IGNORECASE | re.MULTILINE
)

# Azure Managed Identity login (self-hosted runners)
_AZ_MI_LOGIN_RE = re.compile(
    r"az\s+login\s+--identity", re.IGNORECASE
)

# Key Vault secret access — match both arg orders, handle ${{ }} expressions
_KV_SECRET_RE = re.compile(
    r"az\s+keyvault\s+secret\s+show"
    r"(?=.*--vault-name\s+(?P<vault>\$\{\{[^}]+\}\}|\S+))"
    r"(?=.*--name\s+(?P<secret>\$\{\{[^}]+\}\}|\S+))",
    re.IGNORECASE,
)
# Key Vault name from env var assignment (e.g. BACKEND_VAULT_NAME: "seaionl-secrets")
_KV_NAME_ENV_RE = re.compile(
    r"(?:VAULT_NAME|KEY_VAULT).*?:\s*[\"']?([a-zA-Z0-9][\w-]+)[\"']?\s*$",
    re.IGNORECASE | re.MULTILINE,
)

# AKS get-credentials
_AKS_CREDS_RE = re.compile(
    r"az\s+aks\s+get-credentials", re.IGNORECASE
)

# Self-hosted runner detection — array format [label1, label2]
_SELF_HOSTED_ARRAY_RE = re.compile(
    r"runs-on:\s*\[([^\]]+)\]", re.IGNORECASE
)
# Self-hosted runner detection — string format (no brackets, no ${{ }}, no group:/labels: keys)
_SELF_HOSTED_STR_RE = re.compile(
    r"runs-on:\s*(?!\[)(?!\$)(?!group:)(?!labels:)(\S+)", re.IGNORECASE
)

# Secrets reference pattern
_SECRETS_RE = re.compile(r"\$\{\{\s*secrets\.(\w+)\s*\}\}")


# ── Resource access detection ──────────────────────────────────────────

@dataclass
class ResourceAccess:
    """A cloud/infra resource accessed from a workflow."""
    resource_type: str    # azure_keyvault, azure_acr, azure_aks, k8s, helm, etc.
    action: str           # e.g. "secret show", "login", "get-credentials"
    resource_name: str = ""  # e.g. vault name, ACR name, cluster name
    severity: str = "high"   # critical, high, medium, low
    details: str = ""


# Extensible table: (regex, resource_type, action, severity, name_group_index)
# name_group_index: which regex group contains the resource name (0 = none)
_RESOURCE_PATTERNS: List[tuple] = [
    # ── Azure ──
    (re.compile(r"az\s+keyvault\s+secret", re.I),
     "azure_keyvault", "secret access", "high", 0),
    (re.compile(r"az\s+acr\s+login\s+--name\s+(\S+)", re.I),
     "azure_acr", "registry login", "high", 1),
    (re.compile(r"az\s+acr\s+repository", re.I),
     "azure_acr", "repository access", "medium", 0),
    (re.compile(r"az\s+aks\s+get-credentials", re.I),
     "azure_aks", "cluster credentials", "high", 0),
    (re.compile(r"az\s+aks\s+show", re.I),
     "azure_aks", "cluster info", "low", 0),
    (re.compile(r"az\s+storage\s+(?:blob|container|account)", re.I),
     "azure_storage", "storage access", "high", 0),
    (re.compile(r"az\s+sql", re.I),
     "azure_sql", "database access", "high", 0),
    (re.compile(r"az\s+cosmosdb", re.I),
     "azure_cosmosdb", "cosmosdb access", "high", 0),
    (re.compile(r"az\s+servicebus", re.I),
     "azure_servicebus", "service bus access", "medium", 0),
    (re.compile(r"az\s+eventhubs?", re.I),
     "azure_eventhub", "event hub access", "medium", 0),
    (re.compile(r"az\s+appconfig", re.I),
     "azure_appconfig", "app configuration", "medium", 0),
    (re.compile(r"az\s+network", re.I),
     "azure_network", "network access", "medium", 0),
    (re.compile(r"az\s+dns", re.I),
     "azure_dns", "DNS management", "high", 0),
    (re.compile(r"az\s+webapp", re.I),
     "azure_webapp", "web app access", "high", 0),
    (re.compile(r"az\s+functionapp", re.I),
     "azure_functions", "function app access", "high", 0),
    (re.compile(r"az\s+ad\s+(?:app|sp)", re.I),
     "azure_ad", "AD app/SP management", "critical", 0),
    (re.compile(r"az\s+role\s+assignment", re.I),
     "azure_iam", "role assignment", "critical", 0),
    # ── AWS ──
    (re.compile(r"aws\s+s3", re.I),
     "aws_s3", "S3 access", "high", 0),
    (re.compile(r"aws\s+secretsmanager", re.I),
     "aws_secrets", "Secrets Manager access", "high", 0),
    (re.compile(r"aws\s+sts", re.I),
     "aws_sts", "STS assume-role", "high", 0),
    (re.compile(r"aws\s+ec2", re.I),
     "aws_ec2", "EC2 access", "high", 0),
    (re.compile(r"aws\s+iam", re.I),
     "aws_iam", "IAM management", "critical", 0),
    (re.compile(r"aws\s+lambda", re.I),
     "aws_lambda", "Lambda access", "high", 0),
    (re.compile(r"aws\s+ecr", re.I),
     "aws_ecr", "ECR access", "high", 0),
    (re.compile(r"aws\s+eks", re.I),
     "aws_eks", "EKS access", "high", 0),
    (re.compile(r"aws\s+rds", re.I),
     "aws_rds", "RDS access", "high", 0),
    (re.compile(r"aws\s+dynamodb", re.I),
     "aws_dynamodb", "DynamoDB access", "high", 0),
    (re.compile(r"aws\s+cloudformation", re.I),
     "aws_cloudformation", "CloudFormation access", "critical", 0),
    # ── GCP ──
    (re.compile(r"gcloud\s+compute", re.I),
     "gcp_compute", "Compute Engine access", "high", 0),
    (re.compile(r"gcloud\s+container\s+clusters", re.I),
     "gcp_gke", "GKE cluster access", "high", 0),
    (re.compile(r"gcloud\s+secrets", re.I),
     "gcp_secrets", "Secret Manager access", "high", 0),
    (re.compile(r"gcloud\s+sql", re.I),
     "gcp_sql", "Cloud SQL access", "high", 0),
    (re.compile(r"gcloud\s+iam", re.I),
     "gcp_iam", "IAM management", "critical", 0),
    (re.compile(r"gsutil", re.I),
     "gcp_storage", "Cloud Storage access", "high", 0),
    # ── Kubernetes ──
    (re.compile(r"kubectl\s+apply", re.I),
     "k8s", "resource apply", "high", 0),
    (re.compile(r"kubectl\s+create\s+secret", re.I),
     "k8s_secret", "secret creation", "high", 0),
    (re.compile(r"kubectl\s+create\s+configmap", re.I),
     "k8s_configmap", "configmap creation", "medium", 0),
    (re.compile(r"kubectl\s+(?:delete|patch|replace)", re.I),
     "k8s", "resource mutation", "high", 0),
    (re.compile(r"kubectl\s+exec", re.I),
     "k8s", "pod exec", "critical", 0),
    # ── Helm ──
    (re.compile(r"helm\s+(?:upgrade|install)", re.I),
     "helm", "deployment", "high", 0),
    # ── Docker / Container Registry ──
    (re.compile(r"docker\s+push", re.I),
     "container_registry", "image push", "high", 0),
    (re.compile(r"docker\s+(?:build|buildx)", re.I),
     "container_build", "image build", "medium", 0),
    # ── Infrastructure as Code ──
    (re.compile(r"terraform\s+apply", re.I),
     "terraform", "infra apply", "critical", 0),
    (re.compile(r"terraform\s+plan", re.I),
     "terraform", "infra plan", "high", 0),
    (re.compile(r"terraform\s+destroy", re.I),
     "terraform", "infra destroy", "critical", 0),
    (re.compile(r"pulumi\s+up", re.I),
     "pulumi", "infra apply", "critical", 0),
    (re.compile(r"ansible-playbook", re.I),
     "ansible", "config management", "high", 0),
    # ── External APIs ──
    (re.compile(r"cloudflare", re.I),
     "cloudflare", "DNS/CDN management", "high", 0),
]


def _detect_resource_access(content: str) -> List[ResourceAccess]:
    """Detect all cloud/infra resource access patterns in workflow content."""
    seen: set = set()
    resources: List[ResourceAccess] = []
    for pattern, rtype, action, severity, name_idx in _RESOURCE_PATTERNS:
        for m in pattern.finditer(content):
            key = (rtype, action)
            if key in seen:
                continue
            seen.add(key)
            name = ""
            if name_idx and name_idx <= len(m.groups()):
                name = m.group(name_idx)
            resources.append(ResourceAccess(
                resource_type=rtype,
                action=action,
                resource_name=_resolve_value(name) if name else "",
                severity=severity,
            ))
            break  # one match per pattern is enough
    return resources


@dataclass
class WorkflowOIDCConnection:
    """A single OIDC or cloud auth connection found in a workflow file."""
    workflow_file: str
    workflow_name: str
    job_name: str = ""
    cloud_provider: str = ""        # aws, azure, gcp
    auth_method: str = ""           # oidc, managed_identity, static_secret
    role_arn: str = ""              # AWS role ARN
    azure_client_id: str = ""       # Azure SP client ID
    azure_tenant_id: str = ""       # Azure tenant ID
    gcp_wif_provider: str = ""      # GCP Workload Identity pool
    gcp_service_account: str = ""   # GCP SA email
    has_oidc_permission: bool = False
    self_hosted_runner: str = ""    # Runner label if self-hosted
    keyvault_secrets: List[str] = field(default_factory=list)
    keyvault_name: str = ""
    has_aks_access: bool = False
    trigger_events: List[str] = field(default_factory=list)
    secrets_used: List[str] = field(default_factory=list)
    cloud_resources: List[ResourceAccess] = field(default_factory=list)
    raw_step: str = ""


@dataclass
class WorkflowScanResult:
    """Results of scanning workflow files."""
    workflows_scanned: int = 0
    oidc_connections: List[WorkflowOIDCConnection] = field(default_factory=list)
    identities: List[Identity] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ── Scanner ────────────────────────────────────────────────────────────

def scan_workflows(
    path: str = ".github/workflows",
    *,
    repo_name: str = "",
) -> WorkflowScanResult:
    """Scan GitHub Actions workflow files for OIDC identity connections.

    Parameters
    ----------
    path : str
        Path to the workflows directory or a single .yml/.yaml file.
    repo_name : str
        Repository name (org/repo) for labeling. Auto-detected from git if empty.

    Returns
    -------
    WorkflowScanResult
        Discovered OIDC connections and generated Identity objects.
    """
    result = WorkflowScanResult()
    wf_path = Path(path)

    if not repo_name:
        repo_name = _detect_repo_name(wf_path)

    # Collect workflow files
    if wf_path.is_file():
        files = [wf_path]
    elif wf_path.is_dir():
        files = sorted(wf_path.glob("*.yml")) + sorted(wf_path.glob("*.yaml"))
    else:
        result.errors.append(f"Path not found: {path}")
        return result

    if not files:
        result.errors.append(f"No workflow files found in {path}")
        return result

    # Resolve .github root for local composite action resolution
    github_root = None
    if wf_path.is_dir():
        # .github/workflows -> .github
        candidate = wf_path.parent
        if candidate.name == ".github":
            github_root = candidate
    elif wf_path.is_file():
        candidate = wf_path.parent.parent
        if candidate.name == ".github":
            github_root = candidate

    for wf_file in files:
        try:
            content = wf_file.read_text()
            # Inline local composite action content for pattern matching
            content = _inline_local_actions(content, github_root)
            connections = _parse_workflow(content, str(wf_file), repo_name)
            result.oidc_connections.extend(connections)
            result.workflows_scanned += 1
        except Exception as e:
            result.errors.append(f"{wf_file.name}: {e}")

    # Convert connections to Identity objects
    for conn in result.oidc_connections:
        identities = _connection_to_identities(conn, repo_name)
        result.identities.extend(identities)

    logger.info(
        "Scanned %d workflows, found %d OIDC connections",
        result.workflows_scanned, len(result.oidc_connections),
    )

    return result


# ── Local composite action inlining ───────────────────────────────────

_LOCAL_ACTION_RE = re.compile(
    r"uses:\s*\./\.github/actions/([\w._-]+)", re.IGNORECASE
)


def _inline_local_actions(content: str, github_root: Optional[Path]) -> str:
    """Append content from referenced local composite actions.

    When a workflow references ``uses: ./.github/actions/<name>``, read
    the corresponding ``action.yml`` / ``action.yaml`` and append its
    content so that regex-based pattern matching picks up commands
    defined inside composite actions (e.g. ``az login --identity``).
    """
    if not github_root:
        return content
    seen: set = set()
    for m in _LOCAL_ACTION_RE.finditer(content):
        action_name = m.group(1)
        if action_name in seen:
            continue
        seen.add(action_name)
        for ext in ("action.yml", "action.yaml"):
            action_file = github_root / "actions" / action_name / ext
            if action_file.is_file():
                try:
                    content += "\n" + action_file.read_text()
                except Exception:
                    pass
                break
    return content


def _parse_workflow(content: str, filepath: str, repo_name: str) -> List[WorkflowOIDCConnection]:
    """Parse a single workflow file for OIDC connections.

    Uses line-by-line regex parsing (no YAML dependency required).
    """
    connections: List[WorkflowOIDCConnection] = []
    filename = os.path.basename(filepath)

    # Extract workflow name
    wf_name = filename
    name_match = re.search(r"^name:\s*(.+)$", content, re.MULTILINE)
    if name_match:
        wf_name = name_match.group(1).strip().strip("'\"")

    # Check for OIDC permission (explicit id-token: write or permissions: write-all)
    has_oidc = bool(_OIDC_PERM_RE.search(content)) or bool(_WRITE_ALL_RE.search(content))

    # Extract trigger events
    triggers = _extract_triggers(content)

    # Extract secrets used
    secrets = _SECRETS_RE.findall(content)

    # Detect self-hosted runners (both array and string formats)
    runner_labels = []
    for m in _SELF_HOSTED_ARRAY_RE.finditer(content):
        for raw in m.group(1).split(","):
            cleaned = raw.strip().strip("'\"")
            if not cleaned.startswith("${{"):
                runner_labels.append(cleaned)
    for m in _SELF_HOSTED_STR_RE.finditer(content):
        runner_labels.append(m.group(1).strip().strip("'\""))
    # Filter out standard GitHub-hosted runners
    gh_hosted = {"ubuntu-latest", "ubuntu-22.04", "ubuntu-20.04", "ubuntu-24.04",
                 "windows-latest", "windows-2022", "windows-2019",
                 "macos-latest", "macos-14", "macos-13", "macos-12"}
    self_hosted_labels = [label for label in runner_labels if label not in gh_hosted]
    # Deduplicate while preserving order
    seen = set()
    unique_labels = []
    for label in self_hosted_labels:
        if label not in seen:
            seen.add(label)
            unique_labels.append(label)
    self_hosted_runner = ", ".join(unique_labels) if unique_labels else ""

    # Detect Key Vault secrets accessed
    kv_secrets = []
    kv_name = ""
    for m in _KV_SECRET_RE.finditer(content):
        vault = _resolve_value(m.group("vault"))
        secret_name = _resolve_value(m.group("secret"))
        kv_secrets.append(secret_name)
        # Pick up the vault name if it's a literal (not a ${{ }} ref)
        if not kv_name and not vault.startswith("$"):
            kv_name = vault
    # Fallback: extract vault name from env var assignments
    if not kv_name:
        env_match = _KV_NAME_ENV_RE.search(content)
        if env_match:
            kv_name = env_match.group(1)

    # Detect AKS credential access
    has_aks = bool(_AKS_CREDS_RE.search(content))

    # Detect all cloud/infra resource access patterns
    cloud_resources = _detect_resource_access(content)

    # ── AWS OIDC ──
    for match in _AWS_OIDC_RE.finditer(content):
        start = max(0, match.start() - 50)
        end = min(len(content), match.end() + 500)
        context = content[start:end]
        role_match = _ROLE_ARN_RE.search(context)
        role_arn = role_match.group(1) if role_match else ""
        role_arn = _resolve_value(role_arn)

        job = _find_job_name(content, match.start())
        connections.append(WorkflowOIDCConnection(
            workflow_file=filename,
            workflow_name=wf_name,
            job_name=job,
            cloud_provider="aws",
            auth_method="oidc",
            role_arn=role_arn,
            has_oidc_permission=has_oidc,
            self_hosted_runner=self_hosted_runner,
            keyvault_secrets=kv_secrets,
            keyvault_name=kv_name,
            has_aks_access=has_aks,
            trigger_events=triggers,
            secrets_used=secrets,
            cloud_resources=cloud_resources,
            raw_step=context.strip()[:200],
        ))

    # ── Azure OIDC (azure/login action) ──
    for match in _AZURE_OIDC_RE.finditer(content):
        start = max(0, match.start() - 50)
        end = min(len(content), match.end() + 500)
        context = content[start:end]
        client_match = _AZURE_CLIENT_ID_RE.search(context)
        tenant_match = _AZURE_TENANT_ID_RE.search(context)
        client_id = _resolve_value(client_match.group(1)) if client_match else ""
        tenant_id = _resolve_value(tenant_match.group(1)) if tenant_match else ""

        job = _find_job_name(content, match.start())
        connections.append(WorkflowOIDCConnection(
            workflow_file=filename,
            workflow_name=wf_name,
            job_name=job,
            cloud_provider="azure",
            auth_method="oidc",
            azure_client_id=client_id,
            azure_tenant_id=tenant_id,
            has_oidc_permission=has_oidc,
            self_hosted_runner=self_hosted_runner,
            keyvault_secrets=kv_secrets,
            keyvault_name=kv_name,
            has_aks_access=has_aks,
            trigger_events=triggers,
            secrets_used=secrets,
            cloud_resources=cloud_resources,
            raw_step=context.strip()[:200],
        ))

    # ── Azure Managed Identity (az login --identity) ──
    for match in _AZ_MI_LOGIN_RE.finditer(content):
        job = _find_job_name(content, match.start())
        connections.append(WorkflowOIDCConnection(
            workflow_file=filename,
            workflow_name=wf_name,
            job_name=job,
            cloud_provider="azure",
            auth_method="managed_identity",
            has_oidc_permission=has_oidc,
            self_hosted_runner=self_hosted_runner,
            keyvault_secrets=kv_secrets,
            keyvault_name=kv_name,
            has_aks_access=has_aks,
            trigger_events=triggers,
            secrets_used=secrets,
            cloud_resources=cloud_resources,
            raw_step=content[max(0, match.start() - 30):match.end() + 100].strip()[:200],
        ))

    # ── GCP OIDC ──
    for match in _GCP_OIDC_RE.finditer(content):
        start = max(0, match.start() - 50)
        end = min(len(content), match.end() + 500)
        context = content[start:end]
        wif_match = _GCP_WIF_PROVIDER_RE.search(context)
        sa_match = _GCP_SA_RE.search(context)
        wif_provider = _resolve_value(wif_match.group(1)) if wif_match else ""
        sa_email = _resolve_value(sa_match.group(1)) if sa_match else ""

        job = _find_job_name(content, match.start())
        connections.append(WorkflowOIDCConnection(
            workflow_file=filename,
            workflow_name=wf_name,
            job_name=job,
            cloud_provider="gcp",
            auth_method="oidc",
            gcp_wif_provider=wif_provider,
            gcp_service_account=sa_email,
            has_oidc_permission=has_oidc,
            self_hosted_runner=self_hosted_runner,
            keyvault_secrets=kv_secrets,
            keyvault_name=kv_name,
            has_aks_access=has_aks,
            trigger_events=triggers,
            secrets_used=secrets,
            cloud_resources=cloud_resources,
            raw_step=context.strip()[:200],
        ))

    return connections


def _connection_to_identities(conn: WorkflowOIDCConnection, repo_name: str) -> List[Identity]:
    """Convert a cloud auth connection to NHInsight Identity objects with risk flags."""
    identities: List[Identity] = []
    job_label = f"/{conn.job_name}" if conn.job_name else ""

    risk_flags: List[RiskFlag] = []

    # ── Common risk checks ──

    # Risk: OIDC without proper permission declaration (only for OIDC auth)
    if conn.auth_method == "oidc" and not conn.has_oidc_permission:
        risk_flags.append(RiskFlag(
            Severity.MEDIUM, "GH_OIDC_NO_PERMISSION",
            "Workflow uses cloud auth action but does not declare id-token: write",
            "Medium: without explicit id-token permission, the OIDC token may not be "
            "available or the workflow may be using long-lived secrets instead.",
        ))

    # Risk: PR trigger with cloud auth
    if any(t in ("pull_request", "pull_request_target") for t in conn.trigger_events):
        risk_flags.append(RiskFlag(
            Severity.HIGH, "GH_OIDC_PR_TRIGGER",
            "Cloud auth triggered on pull_request events",
            "High: any contributor or external PR author can trigger this workflow "
            "and obtain cloud credentials. Restrict to push/release events "
            "or add environment protection rules.",
        ))

    # Risk: Key Vault secret access (credential sprawl from vault to env vars)
    if conn.keyvault_secrets:
        kv_list = ", ".join(conn.keyvault_secrets[:5])
        suffix = f" (+{len(conn.keyvault_secrets) - 5} more)" if len(conn.keyvault_secrets) > 5 else ""
        risk_flags.append(RiskFlag(
            Severity.MEDIUM, "GH_WF_KEYVAULT_SECRETS",
            f"Workflow reads {len(conn.keyvault_secrets)} secrets from Key Vault "
            f"'{conn.keyvault_name}': {kv_list}{suffix}",
            "Medium: secrets fetched from Key Vault are exposed as environment "
            "variables in the workflow. Ensure the runner's managed identity has "
            "least-privilege Key Vault access and rotate secrets regularly.",
        ))

    # Risk: AKS cluster access
    if conn.has_aks_access:
        risk_flags.append(RiskFlag(
            Severity.MEDIUM, "GH_WF_AKS_ACCESS",
            "Workflow fetches AKS cluster credentials",
            "Medium: workflow obtains kubeconfig for AKS cluster. Compromise of "
            "the runner could lead to Kubernetes cluster access. Scope the "
            "managed identity to minimal AKS RBAC roles.",
        ))

    # Risk: Self-hosted runner with managed identity
    if conn.self_hosted_runner and conn.auth_method == "managed_identity":
        risk_flags.append(RiskFlag(
            Severity.HIGH, "GH_WF_SELF_HOSTED_MI",
            f"Self-hosted runner '{conn.self_hosted_runner}' uses Managed Identity "
            "for Azure access",
            "High: the runner VM's managed identity grants implicit Azure access "
            "to every workflow that runs on it. A compromised workflow or malicious "
            "PR could access Azure resources. Use environment protection rules and "
            "restrict runner labels to trusted workflows.",
        ))

    # ── Provider-specific identity creation ──

    if conn.cloud_provider == "aws" and conn.auth_method == "oidc":
        ident_id = f"github:oidc:aws:{conn.workflow_file}:{conn.role_arn or 'unknown'}"
        name = f"OIDC → AWS ({conn.workflow_name}{job_label})"

        role_name = conn.role_arn.split("/")[-1] if "/" in conn.role_arn else conn.role_arn
        admin_keywords = {"admin", "administrator", "poweruser", "fullaccess", "deploy-all"}
        if any(kw in role_name.lower() for kw in admin_keywords):
            risk_flags.append(RiskFlag(
                Severity.HIGH, "GH_OIDC_ADMIN_ROLE",
                f"OIDC workflow assumes role with admin-like name: {role_name}",
                f"High: workflow {conn.workflow_name} assumes {role_name} which "
                "suggests elevated privileges. Verify the role's actual policies "
                "and restrict to least-privilege.",
            ))

        if not conn.role_arn or conn.role_arn.startswith("$"):
            risk_flags.append(RiskFlag(
                Severity.INFO, "GH_OIDC_DYNAMIC_ROLE",
                "OIDC role ARN uses a secrets/variable reference",
                "Info: role ARN is resolved at runtime from secrets. "
                "Combine with --aws scan to correlate the actual role.",
            ))

        identities.append(Identity(
            id=ident_id,
            name=name,
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_ACTIONS_OIDC,
            classification=Classification.MACHINE,
            raw={
                "workflow_file": conn.workflow_file,
                "workflow_name": conn.workflow_name,
                "job_name": conn.job_name,
                "cloud_provider": "aws",
                "auth_method": "oidc",
                "role_arn": conn.role_arn,
                "trigger_events": conn.trigger_events,
                "has_oidc_permission": conn.has_oidc_permission,
                "cloud_resources": [
                    {"resource_type": r.resource_type, "action": r.action,
                     "resource_name": r.resource_name, "severity": r.severity}
                    for r in conn.cloud_resources
                ],
            },
            risk_flags=risk_flags,
        ))

    elif conn.cloud_provider == "azure" and conn.auth_method == "oidc":
        ident_id = f"github:oidc:azure:{conn.workflow_file}:{conn.azure_client_id or 'unknown'}"
        name = f"OIDC → Azure ({conn.workflow_name}{job_label})"

        identities.append(Identity(
            id=ident_id,
            name=name,
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_ACTIONS_OIDC,
            classification=Classification.MACHINE,
            raw={
                "workflow_file": conn.workflow_file,
                "workflow_name": conn.workflow_name,
                "job_name": conn.job_name,
                "cloud_provider": "azure",
                "auth_method": "oidc",
                "azure_client_id": conn.azure_client_id,
                "azure_tenant_id": conn.azure_tenant_id,
                "trigger_events": conn.trigger_events,
                "has_oidc_permission": conn.has_oidc_permission,
                "cloud_resources": [
                    {"resource_type": r.resource_type, "action": r.action,
                     "resource_name": r.resource_name, "severity": r.severity}
                    for r in conn.cloud_resources
                ],
            },
            risk_flags=risk_flags,
        ))

    elif conn.cloud_provider == "azure" and conn.auth_method == "managed_identity":
        runner_tag = conn.self_hosted_runner or "self-hosted"
        ident_id = f"github:mi:azure:{conn.workflow_file}:{runner_tag}"
        name = f"MI → Azure ({conn.workflow_name}{job_label})"

        identities.append(Identity(
            id=ident_id,
            name=name,
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_ACTIONS_OIDC,
            classification=Classification.MACHINE,
            raw={
                "workflow_file": conn.workflow_file,
                "workflow_name": conn.workflow_name,
                "job_name": conn.job_name,
                "cloud_provider": "azure",
                "auth_method": "managed_identity",
                "self_hosted_runner": conn.self_hosted_runner,
                "keyvault_name": conn.keyvault_name,
                "keyvault_secrets": conn.keyvault_secrets,
                "has_aks_access": conn.has_aks_access,
                "trigger_events": conn.trigger_events,
                "cloud_resources": [
                    {"resource_type": r.resource_type, "action": r.action,
                     "resource_name": r.resource_name, "severity": r.severity}
                    for r in conn.cloud_resources
                ],
            },
            risk_flags=risk_flags,
        ))

    elif conn.cloud_provider == "gcp" and conn.auth_method == "oidc":
        ident_id = f"github:oidc:gcp:{conn.workflow_file}:{conn.gcp_service_account or 'unknown'}"
        name = f"OIDC → GCP ({conn.workflow_name}{job_label})"

        identities.append(Identity(
            id=ident_id,
            name=name,
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_ACTIONS_OIDC,
            classification=Classification.MACHINE,
            raw={
                "workflow_file": conn.workflow_file,
                "workflow_name": conn.workflow_name,
                "job_name": conn.job_name,
                "cloud_provider": "gcp",
                "auth_method": "oidc",
                "gcp_service_account": conn.gcp_service_account,
                "gcp_wif_provider": conn.gcp_wif_provider,
                "trigger_events": conn.trigger_events,
                "has_oidc_permission": conn.has_oidc_permission,
                "cloud_resources": [
                    {"resource_type": r.resource_type, "action": r.action,
                     "resource_name": r.resource_name, "severity": r.severity}
                    for r in conn.cloud_resources
                ],
            },
            risk_flags=risk_flags,
        ))

    return identities


# ── Helpers ────────────────────────────────────────────────────────────

def _resolve_value(val: str) -> str:
    """Resolve a workflow value — leave secrets refs as-is, strip quotes."""
    if not val:
        return ""
    val = val.strip().strip("'\"")
    return val


_KNOWN_EVENTS = {
    "push", "pull_request", "pull_request_target", "workflow_dispatch",
    "workflow_call", "schedule", "release", "create", "delete",
    "deployment", "issue_comment", "issues", "label", "merge_group",
    "page_build", "repository_dispatch", "workflow_run",
}


def _extract_triggers(content: str) -> List[str]:
    """Extract trigger event names from a workflow file."""
    triggers = []
    # Match "on:" section
    on_match = re.search(r"^on:\s*$", content, re.MULTILINE)
    if on_match:
        # Multiline on: block — only pick top-level keys that are known events
        pos = on_match.end()
        for line in content[pos:].split("\n"):
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                # Must be exactly 2-space indented (top-level under on:)
                if re.match(r"^  \S", line) and stripped.endswith(":"):
                    candidate = stripped.rstrip(":").strip()
                    if candidate in _KNOWN_EVENTS:
                        triggers.append(candidate)
                elif not line.startswith(" "):
                    break  # End of on: block
    else:
        # Inline on: [push, pull_request] or on: push
        inline_match = re.search(r"^on:\s*(.+)$", content, re.MULTILINE)
        if inline_match:
            val = inline_match.group(1).strip()
            if val.startswith("["):
                triggers = [t.strip().strip("'\"") for t in val.strip("[]").split(",")]
            else:
                triggers = [val.strip().strip("'\"")]
    return triggers


def _find_job_name(content: str, pos: int) -> str:
    """Find the job name that contains the given position."""
    # Look backwards from pos for the nearest "jobs:\n  job_name:" pattern
    before = content[:pos]
    # Find all job headers before this position
    job_matches = list(re.finditer(r"^\s{2}(\w[\w-]*):\s*$", before, re.MULTILINE))
    if job_matches:
        return job_matches[-1].group(1)
    return ""


def _detect_repo_name(wf_path: Path) -> str:
    """Try to detect repository name from git remote."""
    try:
        # Walk up to find .git directory
        search = wf_path if wf_path.is_dir() else wf_path.parent
        for _ in range(10):
            git_dir = search / ".git"
            if git_dir.exists():
                config = (git_dir / "config").read_text()
                url_match = re.search(r"url\s*=\s*.*[:/]([^/]+/[^/\s]+?)(?:\.git)?\s*$", config, re.MULTILINE)
                if url_match:
                    return url_match.group(1)
            search = search.parent
    except Exception:
        pass
    return ""

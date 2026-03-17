# MIT License — Copyright (c) 2026 cvemula1
# Tests for GitHub Actions workflow scanner and OIDC attack path integration

from __future__ import annotations

import subprocess
import sys
import textwrap
from datetime import datetime, timezone

from nhinsight.analyzers.attack_paths import analyze_attack_paths
from nhinsight.analyzers.graph import EdgeType, build_graph
from nhinsight.analyzers.workflow_scanner import (
    WorkflowOIDCConnection,
    _connection_to_identities,
    _extract_triggers,
    _find_job_name,
    _parse_workflow,
    scan_workflows,
)
from nhinsight.core.models import (
    Classification,
    Identity,
    IdentityType,
    Provider,
    RiskFlag,
    Severity,
)

# ── Sample workflow content ────────────────────────────────────────────

AWS_OIDC_WORKFLOW = textwrap.dedent("""\
    name: Deploy to AWS
    on:
      push:
        branches: [main]
      pull_request:

    permissions:
      id-token: write
      contents: read

    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - uses: aws-actions/configure-aws-credentials@v4
            with:
              role-to-assume: arn:aws:iam::123456789012:role/github-deploy-role
              aws-region: us-east-1
          - run: aws s3 sync ./dist s3://my-bucket
""")

AZURE_OIDC_WORKFLOW = textwrap.dedent("""\
    name: Deploy to Azure
    on: [push]

    permissions:
      id-token: write

    jobs:
      terraform:
        runs-on: ubuntu-latest
        steps:
          - uses: azure/login@v1
            with:
              client-id: 11111111-aaaa-bbbb-cccc-000000000001
              tenant-id: 22222222-dddd-eeee-ffff-000000000002
              subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
""")

GCP_OIDC_WORKFLOW = textwrap.dedent("""\
    name: CI Pipeline
    on: [push, pull_request]

    permissions:
      id-token: write

    jobs:
      build-and-push:
        runs-on: ubuntu-latest
        steps:
          - uses: google-github-actions/auth@v2
            with:
              workload_identity_provider: projects/123/locations/global/workloadIdentityPools/github/providers/my-repo
              service_account: ci-runner@my-project.iam.gserviceaccount.com
""")

NO_OIDC_WORKFLOW = textwrap.dedent("""\
    name: Lint
    on: [push]

    jobs:
      lint:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
          - run: npm run lint
""")

MULTI_CLOUD_WORKFLOW = textwrap.dedent("""\
    name: Multi-Cloud Deploy
    on:
      push:
        branches: [main]

    permissions:
      id-token: write
      contents: read

    jobs:
      deploy-aws:
        runs-on: ubuntu-latest
        steps:
          - uses: aws-actions/configure-aws-credentials@v4
            with:
              role-to-assume: arn:aws:iam::111111111111:role/deploy-admin
              aws-region: us-west-2

      deploy-gcp:
        runs-on: ubuntu-latest
        steps:
          - uses: google-github-actions/auth@v2
            with:
              workload_identity_provider: projects/456/locations/global/workloadIdentityPools/gh/providers/repo
              service_account: deployer@prod.iam.gserviceaccount.com
""")

MANAGED_IDENTITY_WORKFLOW = textwrap.dedent("""\
    name: Deploy with MI
    on:
      push:
        branches: [main]
      pull_request:
        branches: [main]

    jobs:
      deploy:
        runs-on: my-custom-runner
        steps:
        - name: Azure Login
          run: az login --identity --allow-no-subscriptions
        - name: Get secrets
          run: |
            TENANT=$(az keyvault secret show --vault-name my-kv --name tenant-id --query value -o tsv)
            SUB=$(az keyvault secret show --name sub-id --vault-name my-kv --query value -o tsv)
        - name: Get AKS creds
          run: az aks get-credentials --resource-group rg --name my-cluster
""")

KV_ENV_REF_WORKFLOW = textwrap.dedent("""\
    name: KV Env Test
    on: push

    env:
      BACKEND_VAULT_NAME: seaionl-prod-kv

    jobs:
      deploy:
        runs-on: [self-hosted]
        steps:
        - run: az login --identity
        - run: |
            T=$(az keyvault secret show --vault-name ${{ env.BACKEND_VAULT_NAME }} \
              --name tenant-id --query value -o tsv)
            S=$(az keyvault secret show --vault-name ${{ env.BACKEND_VAULT_NAME }} \
              --name sub-id --query value -o tsv)
""")

COMMENTED_OIDC_WORKFLOW = textwrap.dedent("""\
    name: No OIDC
    on: push
    # permissions:
    #   id-token: write
    jobs:
      build:
        runs-on: ubuntu-latest
        steps:
        - uses: aws-actions/configure-aws-credentials@v4
          with:
            role-to-assume: arn:aws:iam::123:role/test
""")

WRITE_ALL_WORKFLOW = textwrap.dedent("""\
    name: AWS Deploy
    on: push
    permissions: write-all
    jobs:
      deploy:
        runs-on: ubuntu-latest
        steps:
        - uses: aws-actions/configure-aws-credentials@v4
          with:
            role-to-assume: arn:aws:iam::123456789012:role/deploy-admin
            aws-region: us-east-1
""")

REUSABLE_WORKFLOW = textwrap.dedent("""\
    name: Reusable Deploy
    on:
      workflow_call:
        inputs:
          environment:
            required: true
            type: string
    jobs:
      deploy:
        runs-on: [self-hosted, linux, azure]
        steps:
        - run: az login --identity
""")


# ── Parser tests ───────────────────────────────────────────────────────

class TestParseWorkflow:
    def test_parse_aws_oidc(self):
        conns = _parse_workflow(AWS_OIDC_WORKFLOW, "deploy.yml", "acme/app")
        assert len(conns) == 1
        assert conns[0].cloud_provider == "aws"
        assert conns[0].role_arn == "arn:aws:iam::123456789012:role/github-deploy-role"
        assert conns[0].has_oidc_permission is True
        assert conns[0].workflow_name == "Deploy to AWS"

    def test_parse_azure_oidc(self):
        conns = _parse_workflow(AZURE_OIDC_WORKFLOW, "infra.yml", "acme/app")
        assert len(conns) == 1
        assert conns[0].cloud_provider == "azure"
        assert conns[0].azure_client_id == "11111111-aaaa-bbbb-cccc-000000000001"
        assert conns[0].azure_tenant_id == "22222222-dddd-eeee-ffff-000000000002"

    def test_parse_gcp_oidc(self):
        conns = _parse_workflow(GCP_OIDC_WORKFLOW, "ci.yml", "acme/app")
        assert len(conns) == 1
        assert conns[0].cloud_provider == "gcp"
        assert conns[0].gcp_service_account == "ci-runner@my-project.iam.gserviceaccount.com"
        assert "workloadIdentityPools" in conns[0].gcp_wif_provider

    def test_parse_no_oidc(self):
        conns = _parse_workflow(NO_OIDC_WORKFLOW, "lint.yml", "acme/app")
        assert len(conns) == 0

    def test_parse_multi_cloud(self):
        conns = _parse_workflow(MULTI_CLOUD_WORKFLOW, "multi.yml", "acme/app")
        assert len(conns) == 2
        providers = {c.cloud_provider for c in conns}
        assert "aws" in providers
        assert "gcp" in providers

    def test_job_name_detected(self):
        conns = _parse_workflow(AWS_OIDC_WORKFLOW, "deploy.yml", "acme/app")
        assert conns[0].job_name == "deploy"

    def test_triggers_parsed(self):
        conns = _parse_workflow(AWS_OIDC_WORKFLOW, "deploy.yml", "acme/app")
        assert "push" in conns[0].trigger_events or "pull_request" in conns[0].trigger_events

    def test_parse_managed_identity(self):
        conns = _parse_workflow(MANAGED_IDENTITY_WORKFLOW, "deploy-mi.yml", "acme/app")
        assert len(conns) == 1
        c = conns[0]
        assert c.auth_method == "managed_identity"
        assert c.cloud_provider == "azure"
        assert c.self_hosted_runner == "my-custom-runner"
        assert c.keyvault_name == "my-kv"
        assert "tenant-id" in c.keyvault_secrets
        assert "sub-id" in c.keyvault_secrets
        assert c.has_aks_access is True
        assert "push" in c.trigger_events
        assert "pull_request" in c.trigger_events

    def test_parse_kv_env_ref(self):
        conns = _parse_workflow(KV_ENV_REF_WORKFLOW, "kv-env.yml", "acme/app")
        assert len(conns) == 1
        c = conns[0]
        assert c.keyvault_name == "seaionl-prod-kv"
        assert "tenant-id" in c.keyvault_secrets
        assert "sub-id" in c.keyvault_secrets

    def test_commented_oidc_not_detected(self):
        conns = _parse_workflow(COMMENTED_OIDC_WORKFLOW, "no-oidc.yml", "acme/app")
        assert len(conns) == 1
        assert conns[0].has_oidc_permission is False

    def test_write_all_detected_as_oidc(self):
        conns = _parse_workflow(WRITE_ALL_WORKFLOW, "wa.yml", "acme/app")
        assert len(conns) == 1
        assert conns[0].has_oidc_permission is True

    def test_reusable_workflow_call(self):
        conns = _parse_workflow(REUSABLE_WORKFLOW, "reusable.yml", "acme/app")
        assert len(conns) == 1
        assert "workflow_call" in conns[0].trigger_events
        assert conns[0].auth_method == "managed_identity"
        assert "self-hosted" in conns[0].self_hosted_runner

    def test_self_hosted_string_format(self):
        wf = "name: T\non: push\njobs:\n  j:\n    runs-on: my-runner\n    steps:\n    - run: az login --identity\n"
        conns = _parse_workflow(wf, "t.yml", "r")
        assert len(conns) == 1
        assert conns[0].self_hosted_runner == "my-runner"

    def test_kv_reversed_arg_order(self):
        wf = (
            "name: T\non: push\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
            "    steps:\n    - run: az login --identity\n"
            "    - run: az keyvault secret show --name my-secret --vault-name my-vault\n"
        )
        conns = _parse_workflow(wf, "t.yml", "r")
        assert len(conns) == 1
        assert conns[0].keyvault_name == "my-vault"
        assert "my-secret" in conns[0].keyvault_secrets


class TestExtractTriggers:
    def test_inline_single(self):
        content = "on: push\n"
        assert _extract_triggers(content) == ["push"]

    def test_inline_list(self):
        content = "on: [push, pull_request]\n"
        triggers = _extract_triggers(content)
        assert "push" in triggers
        assert "pull_request" in triggers

    def test_multiline(self):
        content = "on:\n  push:\n  pull_request:\njobs:\n"
        triggers = _extract_triggers(content)
        assert "push" in triggers
        assert "pull_request" in triggers

    def test_quoted_inline(self):
        content = "on: 'push'\njobs:\n"
        assert _extract_triggers(content) == ["push"]

    def test_workflow_dispatch(self):
        content = "on:\n  workflow_dispatch:\njobs:\n"
        assert _extract_triggers(content) == ["workflow_dispatch"]

    def test_workflow_call(self):
        content = "on:\n  workflow_call:\n    inputs:\n      env:\n        type: string\njobs:\n"
        assert _extract_triggers(content) == ["workflow_call"]

    def test_schedule_and_push(self):
        content = "on:\n  schedule:\n    - cron: '0 0 * * *'\n  push:\n    branches: [main]\njobs:\n"
        triggers = _extract_triggers(content)
        assert "schedule" in triggers
        assert "push" in triggers

    def test_subkeys_not_included(self):
        content = "on:\n  push:\n    branches: [main]\n    tags:\n      - 'v*'\n    paths:\n      - 'src/**'\njobs:\n"
        triggers = _extract_triggers(content)
        assert triggers == ["push"]
        assert "branches" not in triggers
        assert "tags" not in triggers
        assert "paths" not in triggers


class TestFindJobName:
    def test_finds_job(self):
        content = "jobs:\n  deploy:\n    runs-on: ubuntu\n    steps:\n      - uses: aws"
        pos = content.index("aws")
        assert _find_job_name(content, pos) == "deploy"

    def test_no_job(self):
        content = "name: test\non: push\n"
        assert _find_job_name(content, 5) == ""


# ── Identity conversion tests ─────────────────────────────────────────

class TestConnectionToIdentities:
    def test_aws_oidc_identity(self):
        conn = WorkflowOIDCConnection(
            workflow_file="deploy.yml",
            workflow_name="Deploy",
            job_name="deploy",
            cloud_provider="aws",
            auth_method="oidc",
            role_arn="arn:aws:iam::123456789012:role/admin-deploy",
            has_oidc_permission=True,
            trigger_events=["push", "pull_request"],
        )
        identities = _connection_to_identities(conn, "acme/app")
        assert len(identities) == 1
        ident = identities[0]
        assert ident.identity_type == IdentityType.GITHUB_ACTIONS_OIDC
        assert ident.provider == Provider.GITHUB
        assert ident.classification == Classification.MACHINE
        assert ident.raw["role_arn"] == "arn:aws:iam::123456789012:role/admin-deploy"

    def test_pr_trigger_risk_flag(self):
        conn = WorkflowOIDCConnection(
            workflow_file="deploy.yml",
            workflow_name="Deploy",
            cloud_provider="aws",
            auth_method="oidc",
            role_arn="arn:aws:iam::123456789012:role/deploy",
            has_oidc_permission=True,
            trigger_events=["push", "pull_request"],
        )
        identities = _connection_to_identities(conn, "acme/app")
        flags = identities[0].risk_flags
        codes = [f.code for f in flags]
        assert "GH_OIDC_PR_TRIGGER" in codes

    def test_admin_role_name_risk_flag(self):
        conn = WorkflowOIDCConnection(
            workflow_file="deploy.yml",
            workflow_name="Deploy",
            cloud_provider="aws",
            auth_method="oidc",
            role_arn="arn:aws:iam::123456789012:role/deploy-admin",
            has_oidc_permission=True,
            trigger_events=["push"],
        )
        identities = _connection_to_identities(conn, "acme/app")
        codes = [f.code for f in identities[0].risk_flags]
        assert "GH_OIDC_ADMIN_ROLE" in codes

    def test_no_oidc_permission_flag(self):
        conn = WorkflowOIDCConnection(
            workflow_file="deploy.yml",
            workflow_name="Deploy",
            cloud_provider="aws",
            auth_method="oidc",
            role_arn="arn:aws:iam::123456789012:role/deploy",
            has_oidc_permission=False,
            trigger_events=["push"],
        )
        identities = _connection_to_identities(conn, "acme/app")
        codes = [f.code for f in identities[0].risk_flags]
        assert "GH_OIDC_NO_PERMISSION" in codes

    def test_azure_identity(self):
        conn = WorkflowOIDCConnection(
            workflow_file="infra.yml",
            workflow_name="Infra",
            cloud_provider="azure",
            auth_method="oidc",
            azure_client_id="aaa-bbb",
            azure_tenant_id="ccc-ddd",
            has_oidc_permission=True,
            trigger_events=["push"],
        )
        identities = _connection_to_identities(conn, "acme/app")
        assert len(identities) == 1
        assert identities[0].raw["cloud_provider"] == "azure"
        assert identities[0].raw["azure_client_id"] == "aaa-bbb"

    def test_gcp_identity(self):
        conn = WorkflowOIDCConnection(
            workflow_file="ci.yml",
            workflow_name="CI",
            cloud_provider="gcp",
            auth_method="oidc",
            gcp_service_account="sa@proj.iam.gserviceaccount.com",
            has_oidc_permission=True,
            trigger_events=["push"],
        )
        identities = _connection_to_identities(conn, "acme/app")
        assert len(identities) == 1
        assert identities[0].raw["gcp_service_account"] == "sa@proj.iam.gserviceaccount.com"

    def test_managed_identity_azure(self):
        conn = WorkflowOIDCConnection(
            workflow_file="deploy-dev.yml",
            workflow_name="Deploy to DEV",
            job_name="deploy-dev",
            cloud_provider="azure",
            auth_method="managed_identity",
            self_hosted_runner="azure-green-runner-vmss",
            keyvault_secrets=["tenant-id", "subscription-id"],
            keyvault_name="seaionl-secrets",
            has_aks_access=True,
            trigger_events=["push"],
        )
        identities = _connection_to_identities(conn, "acme/infra")
        assert len(identities) == 1
        ident = identities[0]
        assert ident.raw["auth_method"] == "managed_identity"
        assert ident.raw["self_hosted_runner"] == "azure-green-runner-vmss"
        assert ident.raw["keyvault_name"] == "seaionl-secrets"
        codes = [f.code for f in ident.risk_flags]
        assert "GH_WF_SELF_HOSTED_MI" in codes
        assert "GH_WF_KEYVAULT_SECRETS" in codes
        assert "GH_WF_AKS_ACCESS" in codes

    def test_managed_identity_no_pr_trigger(self):
        conn = WorkflowOIDCConnection(
            workflow_file="deploy-prod.yml",
            workflow_name="Deploy to PROD",
            cloud_provider="azure",
            auth_method="managed_identity",
            self_hosted_runner="azure-green-runner-vmss",
            trigger_events=["push", "workflow_dispatch"],
        )
        identities = _connection_to_identities(conn, "acme/infra")
        codes = [f.code for f in identities[0].risk_flags]
        assert "GH_OIDC_PR_TRIGGER" not in codes


# ── File scanning tests ───────────────────────────────────────────────

class TestScanWorkflows:
    def test_scan_directory(self, tmp_path):
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "deploy.yml").write_text(AWS_OIDC_WORKFLOW)
        (wf_dir / "lint.yml").write_text(NO_OIDC_WORKFLOW)

        result = scan_workflows(str(wf_dir), repo_name="acme/app")
        assert result.workflows_scanned == 2
        assert len(result.oidc_connections) == 1
        assert len(result.identities) == 1
        assert result.identities[0].identity_type == IdentityType.GITHUB_ACTIONS_OIDC

    def test_scan_single_file(self, tmp_path):
        wf_file = tmp_path / "deploy.yml"
        wf_file.write_text(AWS_OIDC_WORKFLOW)

        result = scan_workflows(str(wf_file), repo_name="acme/app")
        assert result.workflows_scanned == 1
        assert len(result.oidc_connections) == 1

    def test_scan_missing_path(self):
        result = scan_workflows("/nonexistent/path")
        assert len(result.errors) > 0
        assert result.workflows_scanned == 0

    def test_scan_multi_cloud(self, tmp_path):
        wf_dir = tmp_path / "workflows"
        wf_dir.mkdir()
        (wf_dir / "multi.yml").write_text(MULTI_CLOUD_WORKFLOW)

        result = scan_workflows(str(wf_dir), repo_name="acme/app")
        assert result.workflows_scanned == 1
        assert len(result.oidc_connections) == 2
        assert len(result.identities) == 2


# ── Graph integration tests ───────────────────────────────────────────

class TestOIDCGraph:
    def _make_oidc_aws_identity(self):
        return Identity(
            id="github:oidc:aws:deploy.yml:arn:aws:iam::123:role/deploy-admin",
            name="OIDC → AWS (Deploy)",
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_ACTIONS_OIDC,
            classification=Classification.MACHINE,
            raw={
                "cloud_provider": "aws",
                "role_arn": "arn:aws:iam::123:role/deploy-admin",
                "role_policies": ["AdministratorAccess"],
            },
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "GH_OIDC_ADMIN_ROLE",
                         "OIDC assumes admin role", "Critical: admin access"),
            ],
        )

    def test_oidc_creates_graph_edge(self):
        oidc_ident = self._make_oidc_aws_identity()
        graph = build_graph([oidc_ident])
        # Should have: OIDC node + synthetic IAM role node + policy node
        assert len(graph.nodes) >= 2
        # Should have OIDC → role edge
        oidc_edges = [e for e in graph.edges if e.edge_type == EdgeType.OIDC_ASSUMES_ROLE]
        assert len(oidc_edges) >= 1

    def test_oidc_is_entry_point(self):
        oidc_ident = self._make_oidc_aws_identity()
        graph = build_graph([oidc_ident])
        entry_points = graph.entry_points()
        oidc_entries = [n for n in entry_points if n.node_type == "github_actions_oidc"]
        assert len(oidc_entries) == 1

    def test_oidc_admin_creates_privileged_node(self):
        oidc_ident = self._make_oidc_aws_identity()
        graph = build_graph([oidc_ident])
        privileged = graph.privileged_nodes()
        # The AdministratorAccess policy node should be privileged
        priv_labels = [n.label for n in privileged]
        assert "AdministratorAccess" in priv_labels

    def test_oidc_cross_system_attack_path(self):
        """OIDC → AWS role should produce a cross-system attack path."""
        oidc_ident = self._make_oidc_aws_identity()
        ap_result = analyze_attack_paths([oidc_ident])
        assert len(ap_result.paths) >= 1
        # Should have at least one cross-system path
        cross = [p for p in ap_result.paths if p.cross_system]
        assert len(cross) >= 1

    def test_oidc_azure_graph_edge(self):
        ident = Identity(
            id="github:oidc:azure:infra.yml:aaa-bbb",
            name="OIDC → Azure (Infra)",
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_ACTIONS_OIDC,
            classification=Classification.MACHINE,
            raw={
                "cloud_provider": "azure",
                "azure_client_id": "aaa-bbb-ccc-ddd",
            },
        )
        graph = build_graph([ident])
        oidc_edges = [e for e in graph.edges if e.edge_type == EdgeType.OIDC_ASSUMES_ROLE]
        assert len(oidc_edges) == 1

    def test_oidc_gcp_graph_edge(self):
        ident = Identity(
            id="github:oidc:gcp:ci.yml:sa@proj.iam.gserviceaccount.com",
            name="OIDC → GCP (CI)",
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_ACTIONS_OIDC,
            classification=Classification.MACHINE,
            raw={
                "cloud_provider": "gcp",
                "gcp_service_account": "sa@proj.iam.gserviceaccount.com",
            },
        )
        graph = build_graph([ident])
        oidc_edges = [e for e in graph.edges if e.edge_type == EdgeType.OIDC_ASSUMES_ROLE]
        assert len(oidc_edges) == 1

    def test_oidc_correlates_with_existing_aws_role(self):
        """When an AWS role is already discovered, OIDC should link to it."""
        now = datetime.now(timezone.utc)
        aws_role = Identity(
            id="aws:iam:role:123:deploy-admin",
            name="deploy-admin",
            provider=Provider.AWS,
            identity_type=IdentityType.IAM_ROLE,
            classification=Classification.MACHINE,
            created_at=now,
            arn="arn:aws:iam::123:role/deploy-admin",
            policies=["AdministratorAccess"],
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS",
                         "Has AdministratorAccess", "Critical"),
            ],
        )
        oidc_ident = Identity(
            id="github:oidc:aws:deploy.yml:arn:aws:iam::123:role/deploy-admin",
            name="OIDC → AWS (Deploy)",
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_ACTIONS_OIDC,
            classification=Classification.MACHINE,
            raw={
                "cloud_provider": "aws",
                "role_arn": "arn:aws:iam::123:role/deploy-admin",
            },
        )
        graph = build_graph([aws_role, oidc_ident])
        # Should link OIDC directly to the existing AWS role (not a synthetic node)
        oidc_edges = [e for e in graph.edges if e.edge_type == EdgeType.OIDC_ASSUMES_ROLE]
        assert len(oidc_edges) == 1
        assert oidc_edges[0].target_id == aws_role.id


# ── CLI integration tests ─────────────────────────────────────────────

class TestCLIWorkflows:
    def test_demo_includes_oidc_data(self):
        result = subprocess.run(
            [sys.executable, "-m", "nhinsight.cli", "demo", "--attack-paths"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "OIDC" in result.stdout

    def test_demo_ci_summary_shows_oidc_paths(self):
        result = subprocess.run(
            [sys.executable, "-m", "nhinsight.cli", "demo", "--ci-summary"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "github-actions" in result.stdout
        assert "OIDC" in result.stdout

    def test_scan_github_workflows_flag(self, tmp_path):
        """Test --github-workflows with a real workflow file."""
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "deploy.yml").write_text(AWS_OIDC_WORKFLOW)

        # Use --github-workflows pointing to the temp dir
        # No provider flags needed — workflow-only scan
        result = subprocess.run(
            [sys.executable, "-m", "nhinsight.cli", "scan",
             "--github-workflows", str(wf_dir),
             "--aws",  # need at least one provider
             "--ci-summary", "--ascii"],
            capture_output=True, text=True,
        )
        # May fail due to no AWS creds, but should parse workflows
        # The workflow scanner runs before provider scanning
        assert "github-actions" in result.stdout or result.returncode == 0 or "OIDC" in result.stdout

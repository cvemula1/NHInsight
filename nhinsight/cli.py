# MIT License — Copyright (c) 2026 cvemula1
# CLI entry point for NHInsight

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone

from nhinsight import __version__
from nhinsight.analyzers.classification import classify_identities
from nhinsight.analyzers.risk import analyze_risk
from nhinsight.core.config import NHInsightConfig
from nhinsight.core.models import ScanResult
from nhinsight.core.output import print_result

_MAIN_EPILOG = """\
examples:
  nhinsight demo                              Show sample data (no credentials)
  nhinsight scan --aws                        Scan AWS IAM
  nhinsight scan --gcp --attack-paths         Scan GCP + attack path analysis
  nhinsight scan --all -f json -o out.json    Scan everything, JSON output
  nhinsight scan --aws --explain              Scan with AI explanations
  nhinsight report --demo -o report.md        Generate demo report
  nhinsight version                           Print version

docs: https://github.com/cvemula1/NHInsight
"""

_SCAN_EPILOG = """\
examples:
  nhinsight scan --aws                                Scan AWS IAM
  nhinsight scan --azure --azure-tenant-id TENANT     Scan Azure with tenant
  nhinsight scan --gcp --gcp-project my-proj          Scan GCP project
  nhinsight scan --github --github-org acme           Scan GitHub org
  nhinsight scan --k8s --kube-context prod            Scan Kubernetes cluster
  nhinsight scan --all --attack-paths                 Scan all + attack paths
  nhinsight scan --aws --gcp --k8s --attack-paths     Multi-provider scan
  nhinsight scan --aws -f sarif -o results.sarif      SARIF for GitHub Security
  nhinsight scan --aws --explain                      AI-powered explanations

environment variables:
  AWS_PROFILE / AWS_DEFAULT_REGION          AWS credentials
  AZURE_TENANT_ID / AZURE_SUBSCRIPTION_ID  Azure credentials
  GCP_PROJECT / GOOGLE_CLOUD_PROJECT       GCP project (or gcloud ADC)
  GITHUB_TOKEN / GITHUB_ORG                GitHub access
  KUBECONFIG / KUBE_CONTEXT                Kubernetes cluster
  OPENAI_API_KEY                           LLM explanations (--explain)
  NHINSIGHT_STALE_DAYS                     Override stale threshold
  NHINSIGHT_ROTATION_MAX_DAYS              Override rotation threshold
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nhinsight",
        description="NHInsight — find and flag risky non-human identities across cloud, Kubernetes, and GitHub",
        epilog=_MAIN_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", title="commands")

    # ── scan command ───────────────────────────────────────────────
    scan_p = sub.add_parser(
        "scan",
        help="Discover and analyze NHIs across cloud providers",
        description="Scan one or more cloud providers for non-human identities, "
                    "flag risks, and optionally trace attack paths.",
        epilog=_SCAN_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Provider selection
    prov_group = scan_p.add_argument_group("providers", "select which providers to scan")
    prov_group.add_argument("--aws", action="store_true", help="Scan AWS IAM")
    prov_group.add_argument("--azure", action="store_true", help="Scan Azure AD / Entra ID")
    prov_group.add_argument("--gcp", action="store_true", help="Scan GCP IAM")
    prov_group.add_argument("--github", action="store_true", help="Scan GitHub org")
    prov_group.add_argument("--k8s", action="store_true", help="Scan Kubernetes cluster")
    prov_group.add_argument("--all", action="store_true", help="Scan all available providers")

    # AWS options
    aws_group = scan_p.add_argument_group("aws options")
    aws_group.add_argument("--aws-profile", metavar="PROFILE", help="AWS named profile")
    aws_group.add_argument("--aws-region", metavar="REGION", help="AWS region")

    # Azure options
    az_group = scan_p.add_argument_group("azure options")
    az_group.add_argument("--azure-tenant-id", metavar="ID", help="Azure AD / Entra ID tenant ID")
    az_group.add_argument("--azure-subscription-id", metavar="ID", help="Azure subscription ID")

    # GCP options
    gcp_group = scan_p.add_argument_group("gcp options")
    gcp_group.add_argument("--gcp-project", metavar="PROJECT", help="GCP project ID")

    # GitHub options
    gh_group = scan_p.add_argument_group("github options")
    gh_group.add_argument("--github-org", metavar="ORG", help="GitHub organization to scan")
    gh_group.add_argument("--github-base-url", metavar="URL", help="GitHub Enterprise base URL")

    # Kubernetes options
    k8s_group = scan_p.add_argument_group("kubernetes options")
    k8s_group.add_argument("--kubeconfig", metavar="PATH", help="Path to kubeconfig file")
    k8s_group.add_argument("--kube-context", metavar="CTX", help="Kubernetes context to use")
    k8s_group.add_argument("--kube-namespace", metavar="NS", help="Namespace (default: all)")

    # Analysis options
    analysis_group = scan_p.add_argument_group("analysis")
    analysis_group.add_argument("--attack-paths", action="store_true",
                                help="Trace privilege escalation chains across providers (e.g. K8s SA → cloud admin)")
    analysis_group.add_argument("--mermaid", action="store_true",
                                help="Output attack paths as Mermaid diagrams (implies --attack-paths)")
    analysis_group.add_argument("--ci-summary", action="store_true",
                                help="Output a compact markdown summary for CI/PR usage (implies --attack-paths)")
    analysis_group.add_argument("--github-workflows", metavar="PATH", nargs="?",
                                const=".github/workflows",
                                help="Scan GitHub Actions workflow files for OIDC cloud connections "
                                     "(default path: .github/workflows)")
    analysis_group.add_argument("--stale-days", type=int, default=90, metavar="N",
                                help="Days without use before flagging as stale (default: 90)")
    analysis_group.add_argument("--explain", action="store_true",
                                help="Add AI-powered explanations (requires OPENAI_API_KEY)")

    # Output options
    out_group = scan_p.add_argument_group("output")
    out_group.add_argument("--format", "-f", choices=["table", "json", "sarif"], default="table",
                           help="Output format (default: table)")
    out_group.add_argument("--output", "-o", metavar="FILE",
                           help="Write output to file instead of stdout")
    out_group.add_argument("--ascii", action="store_true",
                           help="ASCII-safe output (no emoji); auto-enabled in CI environments")
    out_group.add_argument("--verbose", "-v", action="store_true", help="Verbose logging")
    out_group.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                           help="Exit with code 1 if any identity has this severity or higher "
                                "(useful for CI gating, e.g. --fail-on high)")

    # ── demo command ───────────────────────────────────────────────
    demo_p = sub.add_parser(
        "demo",
        help="Show a demo scan with sample data (no credentials needed)",
        description="Show a demo report with sample data from all 5 providers. "
                    "No credentials needed.",
    )
    demo_p.add_argument("--format", "-f",
                        choices=["table", "json", "sarif", "markdown", "md"],
                        default="table", help="Output format (default: table)")
    demo_p.add_argument("--output", "-o", metavar="FILE", help="Write output to file")
    demo_p.add_argument("--attack-paths", action="store_true",
                        help="Include attack path analysis in demo output")
    demo_p.add_argument("--mermaid", action="store_true",
                        help="Output attack paths as Mermaid diagrams (implies --attack-paths)")
    demo_p.add_argument("--ci-summary", action="store_true",
                        help="Output a compact markdown summary for CI/PR usage (implies --attack-paths)")
    demo_p.add_argument("--github-workflows", action="store_true",
                        help="Include GitHub Actions OIDC demo data in output")
    demo_p.add_argument("--ascii", action="store_true",
                        help="ASCII-safe output (no emoji); auto-enabled in CI environments")

    # ── report command ─────────────────────────────────────────────
    report_p = sub.add_parser(
        "report",
        help="Generate a formatted report",
        description="Generate a formatted report from a scan or demo data.",
    )
    report_p.add_argument("--demo", action="store_true",
                          help="Generate report from demo data")
    report_p.add_argument("--format", "-f",
                          choices=["markdown", "md", "json", "sarif"],
                          default="markdown", help="Report format (default: markdown)")
    report_p.add_argument("--output", "-o", metavar="FILE", help="Write report to file")

    # ── graph command ──────────────────────────────────────────────
    graph_p = sub.add_parser(
        "graph",
        help="Render attack path graphs from saved JSON output",
        description="Read NHInsight JSON output and render attack path diagrams. "
                    "Useful for generating Mermaid diagrams from previously saved scans.",
    )
    graph_p.add_argument("--input", "-i", metavar="FILE", required=True,
                         help="Path to NHInsight JSON output file")
    graph_p.add_argument("--output", "-o", metavar="FILE",
                         help="Write Mermaid output to file (default: stdout)")
    graph_p.add_argument("--split", action="store_true",
                         help="Render each attack path as a separate diagram")

    # ── version command ────────────────────────────────────────────
    sub.add_parser("version", help="Show version")

    return parser


def _run_scan(args: argparse.Namespace) -> None:
    """Execute a scan across requested providers."""
    config = NHInsightConfig.from_env()

    # Override config with CLI args
    if getattr(args, "aws_profile", None):
        config.aws_profile = args.aws_profile
    if getattr(args, "aws_region", None):
        config.aws_region = args.aws_region
    if getattr(args, "azure_tenant_id", None):
        config.azure_tenant_id = args.azure_tenant_id
    if getattr(args, "azure_subscription_id", None):
        config.azure_subscription_id = args.azure_subscription_id
    if getattr(args, "github_org", None):
        config.github_org = args.github_org
    if getattr(args, "github_base_url", None):
        config.github_base_url = args.github_base_url
    if getattr(args, "gcp_project", None):
        config.gcp_project = args.gcp_project
    if getattr(args, "kubeconfig", None):
        config.kubeconfig = args.kubeconfig
    if getattr(args, "kube_context", None):
        config.kube_context = args.kube_context
    if getattr(args, "kube_namespace", None):
        config.kube_namespace = args.kube_namespace
    if args.stale_days:
        config.stale_days = args.stale_days
    if args.explain:
        config.explain = True

    # Determine which providers to scan
    providers = []
    if args.all:
        providers = ["aws", "azure", "gcp", "github", "k8s"]
    else:
        if args.aws:
            providers.append("aws")
        if args.azure:
            providers.append("azure")
        if getattr(args, "gcp", False):
            providers.append("gcp")
        if args.github:
            providers.append("github")
        if args.k8s:
            providers.append("k8s")

    has_workflows = bool(getattr(args, "github_workflows", None))
    if not providers and not has_workflows:
        print("\n  No providers selected.\n")
        print("  \033[1mQuick examples:\033[0m")
        print("    nhinsight scan --aws                  Scan AWS IAM")
        print("    nhinsight scan --all --attack-paths   Scan everything")
        print("    nhinsight scan --github-workflows     Scan GH Actions only")
        print("    nhinsight demo                        Try with sample data first")
        print()
        print("  Providers: --aws  --azure  --gcp  --github  --k8s  --all\n")
        sys.exit(1)

    # Collect identities from each provider
    result = ScanResult(scan_time=datetime.now(timezone.utc))
    all_identities = []

    for provider_name in providers:
        try:
            if provider_name == "aws":
                from nhinsight.providers.aws import AWSProvider
                provider = AWSProvider(config)
                if not provider.is_available():
                    result.errors.append("AWS credentials not available. Configure AWS CLI or set AWS_PROFILE.")
                    continue
                identities = provider.discover()
                all_identities.extend(identities)
                result.providers_scanned.append("aws")

            elif provider_name == "azure":
                from nhinsight.providers.azure import AzureProvider
                provider = AzureProvider(config)
                if not provider.is_available():
                    result.errors.append(
                        "Azure credentials not available. "
                        "Run 'az login' or set AZURE_TENANT_ID."
                    )
                    continue
                identities = provider.discover()
                all_identities.extend(identities)
                result.providers_scanned.append("azure")

            elif provider_name == "github":
                from nhinsight.providers.github import GitHubProvider
                provider = GitHubProvider(config)
                if not provider.is_available():
                    result.errors.append(
                        "GitHub token not available. Set GITHUB_TOKEN or use --github-org."
                    )
                    continue
                identities = provider.discover()
                all_identities.extend(identities)
                result.providers_scanned.append("github")

            elif provider_name == "gcp":
                from nhinsight.providers.gcp import GCPProvider
                provider = GCPProvider(config)
                if not provider.is_available():
                    result.errors.append(
                        "GCP credentials not available. "
                        "Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS."
                    )
                    continue
                identities = provider.discover()
                all_identities.extend(identities)
                result.providers_scanned.append("gcp")

            elif provider_name == "k8s":
                from nhinsight.providers.kubernetes import KubernetesProvider
                provider = KubernetesProvider(config)
                if not provider.is_available():
                    result.errors.append(
                        "Kubernetes cluster not reachable. Check kubeconfig or use --kube-context."
                    )
                    continue
                identities = provider.discover()
                all_identities.extend(identities)
                result.providers_scanned.append("kubernetes")

        except Exception as e:
            result.errors.append(f"{provider_name}: {e}")

    # GitHub Actions workflow scanning (if requested)
    wf_path = getattr(args, "github_workflows", None)
    if wf_path:
        from nhinsight.analyzers.workflow_scanner import scan_workflows
        wf_result = scan_workflows(wf_path)
        if wf_result.identities:
            all_identities.extend(wf_result.identities)
        if wf_result.errors:
            result.errors.extend(wf_result.errors)
        if wf_result.oidc_connections:
            result.providers_scanned.append("github-actions")

    # Analyze
    classify_identities(all_identities)
    analyze_risk(all_identities, config)

    # LLM explanations (if requested)
    if config.explain and config.openai_api_key:
        from nhinsight.explain.llm import explain_finding
        for ident in all_identities:
            if ident.risk_flags:
                explanation = explain_finding(ident, config)
                if explanation:
                    ident.raw["ai_explanation"] = explanation

    result.identities = all_identities

    # Determine ASCII-safe mode (explicit flag or auto-detect CI)
    from nhinsight.core.ci_summary import is_ci
    ascii_safe = getattr(args, "ascii", False) or is_ci()

    # Output
    out = sys.stdout
    if args.output:
        out = open(args.output, "w")

    # --ci-summary replaces the normal output with a compact markdown summary
    wants_ci = getattr(args, "ci_summary", False)

    if not wants_ci:
        print_result(result, fmt=args.format, out=out, ascii_safe=ascii_safe)

    # Attack path analysis (if requested)
    # --mermaid and --ci-summary both imply --attack-paths
    wants_attack = (
        getattr(args, "attack_paths", False)
        or getattr(args, "mermaid", False)
        or wants_ci
    )
    ap_result = None
    if wants_attack and all_identities:
        from nhinsight.analyzers.attack_paths import analyze_attack_paths
        from nhinsight.core.output import print_attack_paths

        ap_result = analyze_attack_paths(all_identities)

        if not wants_ci:
            print_attack_paths(ap_result, out=out, ascii_safe=ascii_safe)

        if getattr(args, "mermaid", False):
            from nhinsight.core.mermaid import render_attack_paths, render_summary_table
            render_summary_table(ap_result, out=out)
            render_attack_paths(ap_result, out=out)

    # CI summary output (compact markdown for $GITHUB_STEP_SUMMARY / PR comments)
    if wants_ci:
        from nhinsight.core.ci_summary import print_ci_summary, write_github_step_summary
        print_ci_summary(result, ap_result, out=out, ascii_safe=ascii_safe)
        # Also write to $GITHUB_STEP_SUMMARY if available
        write_github_step_summary(result, ap_result, ascii_safe=True)

    if args.output:
        out.close()
        print(f"Results written to {args.output}")

    # --fail-on: exit 1 if any identity meets or exceeds the threshold severity
    fail_on = getattr(args, "fail_on", None)
    if fail_on:
        from nhinsight.core.models import Severity
        threshold_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }
        threshold = threshold_map[fail_on]
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
        failing_sevs = set(severity_order[:severity_order.index(threshold) + 1])
        count = sum(
            1 for i in result.identities if i.highest_severity in failing_sevs
        )
        if count:
            print(f"\n[FAIL] {count} identit{'y' if count == 1 else 'ies'} "
                  f"at {fail_on.upper()} severity or above (--fail-on {fail_on})")
            sys.exit(1)


def _build_demo_data() -> ScanResult:
    """Build realistic demo data for all three providers."""
    from datetime import timedelta

    from nhinsight.core.models import (
        Classification,
        Identity,
        IdentityType,
        Provider,
        RiskFlag,
        ScanResult,
        Severity,
    )

    now = datetime.now(timezone.utc)

    # ── AWS demo identities ─────────────────────────────────────────
    aws_identities = [
        Identity(
            id="aws:iam:user:123456789012:deploy-bot",
            name="deploy-bot",
            provider=Provider.AWS,
            identity_type=IdentityType.IAM_USER,
            classification=Classification.MACHINE,
            arn="arn:aws:iam::123456789012:user/deploy-bot",
            created_at=now - timedelta(days=847),
            policies=["AdministratorAccess"],
            raw={"has_console_access": False, "has_mfa": False},
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS",
                         "Has AdministratorAccess policy attached",
                         "Critical: machine identity with full AWS access. "
                         "Replace with a scoped policy granting only required permissions."),
            ],
        ),
        Identity(
            id="aws:iam:key:123456789012:AKIA3EXAMPLE",
            name="deploy-bot/AKIA3EXAMPLE12345",
            provider=Provider.AWS,
            identity_type=IdentityType.ACCESS_KEY,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=412),
            last_used=now - timedelta(hours=2),
            created_by="deploy-bot",
            raw={"key_id": "AKIA3EXAMPLE12345", "status": "Active"},
            risk_flags=[
                RiskFlag(Severity.HIGH, "AWS_KEY_NOT_ROTATED",
                         "Access key is 412 days old (max 365)",
                         "High: key exceeds rotation policy by 47 days. "
                         "Rotate immediately and update all consumers."),
            ],
        ),
        Identity(
            id="aws:iam:user:123456789012:tiller",
            name="tiller",
            provider=Provider.AWS,
            identity_type=IdentityType.IAM_USER,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=1095),
            last_used=now - timedelta(days=200),
            policies=["AmazonS3FullAccess", "AmazonEC2FullAccess"],
            raw={"has_console_access": False, "has_mfa": False},
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS",
                         "Has AmazonS3FullAccess policy attached",
                         "Critical: overprivileged and unused for 200 days. "
                         "High risk of credential theft with full S3 access."),
                RiskFlag(Severity.MEDIUM, "STALE_IDENTITY",
                         "Not used in 200 days (threshold: 90)",
                         "Medium: identity inactive 2x longer than threshold. "
                         "Deactivate immediately, delete after confirming no dependencies."),
            ],
        ),
        Identity(
            id="aws:iam:user:123456789012:alice.smith",
            name="alice.smith",
            provider=Provider.AWS,
            identity_type=IdentityType.IAM_USER,
            classification=Classification.HUMAN,
            created_at=now - timedelta(days=365),
            last_used=now - timedelta(hours=1),
            policies=["ViewOnlyAccess"],
            raw={"has_console_access": True, "has_mfa": True},
            risk_flags=[],
        ),
        Identity(
            id="aws:iam:role:123456789012:admin-escape-hatch",
            name="admin-escape-hatch",
            provider=Provider.AWS,
            identity_type=IdentityType.IAM_ROLE,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=730),
            policies=["AdministratorAccess"],
            raw={"trusted_principals": ["*"], "path": "/"},
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "AWS_WILDCARD_TRUST",
                         "Role trust policy allows any AWS principal (*)",
                         "Critical: any AWS account worldwide can assume this role. "
                         "Restrict trust policy to specific account IDs or services."),
                RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS",
                         "Has AdministratorAccess policy attached",
                         "Critical: wildcard trust + admin access = any attacker gets full "
                         "account control. This is the highest-risk finding in this scan."),
            ],
        ),
        Identity(
            id="aws:iam:user:123456789012:bob.jones",
            name="bob.jones",
            provider=Provider.AWS,
            identity_type=IdentityType.IAM_USER,
            classification=Classification.HUMAN,
            created_at=now - timedelta(days=200),
            last_used=now - timedelta(hours=3),
            policies=["PowerUserAccess"],
            raw={"has_console_access": True, "has_mfa": False},
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "AWS_ADMIN_ACCESS",
                         "Has PowerUserAccess policy attached",
                         "Critical: human user with near-admin access and no MFA. "
                         "If credentials are phished, attacker gets broad AWS access."),
                RiskFlag(Severity.HIGH, "AWS_NO_MFA",
                         "Console access enabled without MFA",
                         "High: password-only login for a privileged user. "
                         "Enable MFA immediately to prevent credential-based attacks."),
            ],
        ),
    ]

    # ── GitHub demo identities ──────────────────────────────────────
    github_identities = [
        Identity(
            id="github:app:acme-corp:renovate",
            name="renovate (app)",
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_APP,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=300),
            owner="acme-corp",
            permissions=["contents:write", "pull_requests:write"],
            raw={},
            risk_flags=[],
        ),
        Identity(
            id="github:app:acme-corp:custom-admin-bot",
            name="custom-admin-bot (app)",
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_APP,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=180),
            owner="acme-corp",
            permissions=["administration:admin", "members:write", "actions:write"],
            raw={},
            risk_flags=[
                RiskFlag(Severity.HIGH, "GH_APP_DANGEROUS_PERMS",
                         "Dangerous write perms: administration:admin, members:write",
                         "High: this app can modify org settings and membership. "
                         "If compromised, attacker controls the entire GitHub org."),
            ],
        ),
        Identity(
            id="github:deploy_key:acme-corp/api:prod-deploy",
            name="prod-deploy-key → acme-corp/api",
            provider=Provider.GITHUB,
            identity_type=IdentityType.DEPLOY_KEY,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=450),
            owner="acme-corp/api",
            permissions=["repo:write"],
            raw={"read_only": False, "repo": "acme-corp/api"},
            risk_flags=[
                RiskFlag(Severity.MEDIUM, "GH_DEPLOY_KEY_WRITE",
                         "Deploy key has write access",
                         "Medium: write deploy key can push code to the repo. "
                         "Switch to read-only unless CI/CD requires git push."),
                RiskFlag(Severity.MEDIUM, "STALE_IDENTITY",
                         "Not used in 150 days (threshold: 90)",
                         "Medium: unused deploy key with write access is a dormant risk. "
                         "Revoke and recreate if needed later."),
            ],
            last_used=now - timedelta(days=150),
        ),
        Identity(
            id="github:deploy_key:acme-corp/frontend:cd-key",
            name="cd-readonly-key → acme-corp/frontend",
            provider=Provider.GITHUB,
            identity_type=IdentityType.DEPLOY_KEY,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=60),
            last_used=now - timedelta(hours=6),
            owner="acme-corp/frontend",
            permissions=["repo:read"],
            raw={"read_only": True},
            risk_flags=[],
        ),
        Identity(
            id="github:hook:org:acme-corp:slack",
            name="org-webhook → https://hooks.slack.com/...",
            provider=Provider.GITHUB,
            identity_type=IdentityType.WEBHOOK,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=500),
            owner="acme-corp",
            raw={"active": True, "events": ["push", "pull_request"]},
            risk_flags=[],
        ),
        Identity(
            id="github:hook:org:acme-corp:old-jenkins",
            name="org-webhook → https://jenkins.old.internal/...",
            provider=Provider.GITHUB,
            identity_type=IdentityType.WEBHOOK,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=900),
            owner="acme-corp",
            raw={"active": False, "events": ["push"]},
            risk_flags=[
                RiskFlag(Severity.LOW, "GH_WEBHOOK_INACTIVE",
                         "Webhook is inactive",
                         "Low: stale webhook pointing to old Jenkins instance. "
                         "Delete to reduce attack surface and avoid confusion."),
            ],
        ),
        Identity(
            id="github:pat:acme-corp:ci-token",
            name="ci-deploy-token",
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_PAT,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=400),
            last_used=now - timedelta(days=1),
            permissions=["admin:org", "repo"],
            raw={},
            risk_flags=[
                RiskFlag(Severity.HIGH, "GH_ADMIN_SCOPE",
                         "Token has admin scope: admin:org",
                         "High: token can manage org settings, teams, and members. "
                         "Downscope to only required permissions."),
                RiskFlag(Severity.MEDIUM, "GH_REPO_WRITE",
                         "Token has full repo access (read + write + admin)",
                         "Medium: full repo scope grants read, write, and admin on all repos. "
                         "Migrate to fine-grained PAT with per-repo access."),
            ],
        ),
    ]

    # ── Kubernetes demo identities ──────────────────────────────────
    k8s_identities = [
        Identity(
            id="k8s:sa:prod:kube-system:tiller-deploy",
            name="kube-system/tiller-deploy",
            provider=Provider.KUBERNETES,
            identity_type=IdentityType.SERVICE_ACCOUNT,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=800),
            policies=["ClusterRole/cluster-admin"],
            raw={"automount_token": True, "orphaned": True, "pod_count": 0,
                 "deployments": [], "used_as_default_by_deployments": []},
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "K8S_CLUSTER_ADMIN",
                         "ServiceAccount bound to cluster-admin",
                         "Critical: cluster-admin with automounted token and no running pods. "
                         "Any pod using this SA gets full cluster control."),
                RiskFlag(Severity.HIGH, "K8S_AUTOMOUNT_PRIVILEGED",
                         "Automount token enabled on privileged ServiceAccount",
                         "High: token is auto-injected into every pod using this SA. "
                         "Set automountServiceAccountToken: false and mount explicitly."),
                RiskFlag(Severity.MEDIUM, "K8S_ORPHANED_SA",
                         "No running pods reference this ServiceAccount",
                         "Medium: orphaned SA with cluster-admin is a dormant escalation path. "
                         "Delete the SA and its ClusterRoleBinding."),
            ],
        ),
        Identity(
            id="k8s:sa:prod:default:default",
            name="default/default",
            provider=Provider.KUBERNETES,
            identity_type=IdentityType.SERVICE_ACCOUNT,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=600),
            raw={"automount_token": True, "orphaned": False, "pod_count": 5,
                 "deployments": ["api-server", "worker", "cron-job"],
                 "used_as_default_by_deployments": ["api-server", "worker", "cron-job"]},
            risk_flags=[
                RiskFlag(Severity.MEDIUM, "K8S_DEFAULT_SA",
                         "Using the default ServiceAccount in default namespace",
                         "Medium: 3 workloads share the default SA, so any RBAC granted "
                         "to one is inherited by all. Create per-deployment SAs."),
                RiskFlag(Severity.MEDIUM, "K8S_DEPLOY_DEFAULT_SA",
                         "3 deployment(s) using default SA: api-server, worker, cron-job",
                         "Medium: lateral movement risk — compromising one workload "
                         "gives access to permissions of all three."),
            ],
        ),
        Identity(
            id="k8s:sa:prod:payments:checkout-svc",
            name="payments/checkout-svc",
            provider=Provider.KUBERNETES,
            identity_type=IdentityType.SERVICE_ACCOUNT,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=90),
            last_used=now - timedelta(minutes=5),
            owner="payments-team",
            permissions=["aws-irsa:arn:aws:iam::123456789012:role/checkout-svc"],
            policies=["Role/payments-role"],
            raw={"automount_token": False, "orphaned": False, "pod_count": 3,
                 "irsa_role_arn": "arn:aws:iam::123456789012:role/checkout-svc",
                 "deployments": ["checkout"], "used_as_default_by_deployments": []},
            risk_flags=[],
        ),
        Identity(
            id="k8s:sa:prod:monitoring:old-prometheus",
            name="monitoring/old-prometheus",
            provider=Provider.KUBERNETES,
            identity_type=IdentityType.SERVICE_ACCOUNT,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=400),
            last_used=now - timedelta(days=180),
            raw={"automount_token": True, "orphaned": True, "pod_count": 0,
                 "secret_count": 2, "irsa_role_arn": "",
                 "workload_identity_gcp": "", "workload_identity_azure": "",
                 "labels": {"app": "prometheus", "cloud": "aws"},
                 "deployments": [], "used_as_default_by_deployments": []},
            risk_flags=[
                RiskFlag(Severity.MEDIUM, "K8S_ORPHANED_SA",
                         "No running pods reference this ServiceAccount",
                         "Medium: orphaned SA still has 2 secrets attached. "
                         "If secrets are leaked, they grant access with no audit trail."),
                RiskFlag(Severity.MEDIUM, "K8S_NO_WORKLOAD_IDENTITY",
                         "SA has secrets but no IRSA/Workload Identity configured",
                         "Medium: using static AWS credentials instead of IRSA. "
                         "Static secrets don't auto-rotate and are harder to audit."),
                RiskFlag(Severity.MEDIUM, "STALE_IDENTITY",
                         "Not used in 180 days (threshold: 90)",
                         "Medium: no workload has used this SA in 6 months. "
                         "Delete after confirming Prometheus migration is complete."),
            ],
        ),
        Identity(
            id="k8s:secret:prod:app:db-credentials",
            name="app/db-credentials",
            provider=Provider.KUBERNETES,
            identity_type=IdentityType.K8S_SECRET,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=300),
            raw={"secret_type": "Opaque",
                 "data_keys": ["DB_PASSWORD", "DB_HOST", "API_KEY"],
                 "managed_by": ""},
            risk_flags=[
                RiskFlag(Severity.MEDIUM, "K8S_SECRET_CREDENTIALS",
                         "Opaque secret contains credential-like keys: DB_PASSWORD, API_KEY",
                         "Medium: plaintext credentials in etcd. Anyone with secret-read RBAC "
                         "can extract them. Migrate to external-secrets-operator or Vault."),
            ],
        ),
        Identity(
            id="k8s:secret:prod:ingress:wildcard-tls",
            name="ingress/wildcard-tls",
            provider=Provider.KUBERNETES,
            identity_type=IdentityType.K8S_SECRET,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=200),
            raw={"secret_type": "kubernetes.io/tls",
                 "data_keys": ["tls.crt", "tls.key"],
                 "managed_by": ""},
            risk_flags=[
                RiskFlag(Severity.LOW, "K8S_TLS_UNMANAGED",
                         "TLS secret not managed by cert-manager or similar tool",
                         "Low: manual TLS cert with no auto-renewal. "
                         "Risk of unexpected outage when certificate expires."),
            ],
        ),
        Identity(
            id="k8s:secret:prod:kube-system:dashboard-token-abc",
            name="kube-system/dashboard-token-abc",
            provider=Provider.KUBERNETES,
            identity_type=IdentityType.K8S_SECRET,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=700),
            raw={"secret_type": "kubernetes.io/service-account-token",
                 "data_keys": ["token", "ca.crt", "namespace"],
                 "managed_by": "", "service_account": "dashboard"},
            risk_flags=[
                RiskFlag(Severity.HIGH, "K8S_LEGACY_SA_TOKEN",
                         "Legacy long-lived ServiceAccount token secret",
                         "High: pre-1.24 SA token that never expires. If leaked, grants "
                         "persistent access. Delete and migrate to bound tokens (TokenRequest API)."),
            ],
        ),
        Identity(
            id="k8s:secret:prod:ingress:api-tls",
            name="ingress/api-tls",
            provider=Provider.KUBERNETES,
            identity_type=IdentityType.K8S_SECRET,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=30),
            raw={"secret_type": "kubernetes.io/tls",
                 "data_keys": ["tls.crt", "tls.key"],
                 "managed_by": "cert-manager"},
            risk_flags=[],
        ),
    ]

    # ── Azure demo identities ───────────────────────────────────────
    azure_identities = [
        Identity(
            id="azure:sp:11111111-aaaa-bbbb-cccc-000000000001",
            name="aks-cluster-sp",
            provider=Provider.AZURE,
            identity_type=IdentityType.AZURE_SP,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=600),
            policies=[
                "Contributor @ /subscriptions/aaaaaaaa-0000-1111-2222-333333333333",
            ],
            raw={"app_id": "11111111-aaaa-bbbb-cccc-000000000001",
                 "object_id": "sp-obj-001", "sp_type": "Application",
                 "enabled": True, "tags": [], "app_owner_org": "tenant-001"},
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "AZURE_SP_DANGEROUS_ROLE",
                         "SP has Contributor at subscription scope",
                         "Critical: Contributor at subscription level grants create/delete "
                         "on all resources. Scope to the AKS resource group."),
            ],
        ),
        Identity(
            id="azure:sp:22222222-aaaa-bbbb-cccc-000000000002",
            name="terraform-deployer",
            provider=Provider.AZURE,
            identity_type=IdentityType.AZURE_SP,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=400),
            policies=[
                "Owner @ /subscriptions/aaaaaaaa-0000-1111-2222-333333333333",
            ],
            raw={"app_id": "22222222-aaaa-bbbb-cccc-000000000002",
                 "object_id": "sp-obj-002", "sp_type": "Application",
                 "enabled": True, "tags": [], "app_owner_org": "tenant-001"},
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "AZURE_SP_DANGEROUS_ROLE",
                         "SP has Owner at subscription scope",
                         "Critical: Owner can manage all resources AND assign RBAC roles. "
                         "Highest privilege in Azure — replace with Contributor + scoped RBAC."),
            ],
        ),
        Identity(
            id="azure:sp:33333333-aaaa-bbbb-cccc-000000000003",
            name="legacy-ci-pipeline",
            provider=Provider.AZURE,
            identity_type=IdentityType.AZURE_SP,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=900),
            last_used=now - timedelta(days=200),
            policies=[
                "Contributor @ /subscriptions/aaaaaaaa-0000-1111-2222-333333333333"
                "/resourceGroups/legacy-rg",
            ],
            raw={"app_id": "33333333-aaaa-bbbb-cccc-000000000003",
                 "object_id": "sp-obj-003", "sp_type": "Application",
                 "enabled": False, "tags": [], "app_owner_org": "tenant-001"},
            risk_flags=[
                RiskFlag(Severity.MEDIUM, "AZURE_SP_ELEVATED_ROLE",
                         "SP has Contributor role",
                         "Medium: Contributor at resource group level. "
                         "Review if this scope is still needed."),
                RiskFlag(Severity.MEDIUM, "AZURE_SP_DISABLED_WITH_ROLES",
                         "Disabled SP still has active RBAC role assignments",
                         "Medium: disabled SP retains Contributor on legacy-rg. "
                         "Remove role assignments to prevent re-enablement risk."),
                RiskFlag(Severity.MEDIUM, "STALE_IDENTITY",
                         "Not used in 200 days (threshold: 90)",
                         "Medium: last activity was 200 days ago. "
                         "Delete SP after confirming CI pipeline migration is complete."),
            ],
        ),
        Identity(
            id="azure:mi:44444444-aaaa-bbbb-cccc-000000000004",
            name="aks-agentpool-mi",
            provider=Provider.AZURE,
            identity_type=IdentityType.AZURE_MANAGED_IDENTITY,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=300),
            last_used=now - timedelta(minutes=10),
            policies=[
                "Network Contributor @ /subscriptions/aaaaaaaa-0000-1111-2222-333333333333"
                "/resourceGroups/aks-rg",
            ],
            raw={"app_id": "44444444-aaaa-bbbb-cccc-000000000004",
                 "object_id": "mi-obj-004", "mi_type": "system-assigned",
                 "resource_id": "/subscriptions/.../providers/Microsoft.ContainerService"
                                "/managedClusters/prod-aks",
                 "tags": []},
            risk_flags=[],
        ),
        Identity(
            id="azure:mi:55555555-aaaa-bbbb-cccc-000000000005",
            name="keyvault-reader-mi",
            provider=Provider.AZURE,
            identity_type=IdentityType.AZURE_MANAGED_IDENTITY,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=120),
            last_used=now - timedelta(hours=1),
            policies=[
                "Key Vault Secrets User @ /subscriptions/aaaaaaaa-0000-1111-2222-333333333333"
                "/resourceGroups/aks-rg/providers/Microsoft.KeyVault/vaults/prod-kv",
            ],
            raw={"app_id": "55555555-aaaa-bbbb-cccc-000000000005",
                 "object_id": "mi-obj-005", "mi_type": "user-assigned",
                 "resource_id": "/subscriptions/.../providers/Microsoft.ManagedIdentity"
                                "/userAssignedIdentities/keyvault-reader-mi",
                 "tags": []},
            risk_flags=[],
        ),
        Identity(
            id="azure:app_secret:22222222:secret-001",
            name="terraform-deployer/secret:tf-ci-***",
            provider=Provider.AZURE,
            identity_type=IdentityType.AZURE_APP_SECRET,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=500),
            owner="terraform-deployer",
            raw={"app_id": "22222222-aaaa-bbbb-cccc-000000000002",
                 "app_name": "terraform-deployer",
                 "cred_id": "secret-001", "hint": "tf-ci-***",
                 "expires_at": (now + timedelta(days=15)).isoformat()},
            risk_flags=[
                RiskFlag(Severity.HIGH, "AZURE_SECRET_NOT_ROTATED",
                         "Client secret is 500 days old (max 365)",
                         "High: secret exceeds rotation policy by 135 days. "
                         "Rotate immediately. Prefer managed identity or federated credentials."),
                RiskFlag(Severity.MEDIUM, "AZURE_CRED_EXPIRING_SOON",
                         "Credential expires in 15 days",
                         "Medium: secret expiring soon. Rotate before expiry to avoid "
                         "Terraform pipeline outage."),
            ],
        ),
        Identity(
            id="azure:app_secret:33333333:secret-002",
            name="legacy-ci-pipeline/secret:old-key-***",
            provider=Provider.AZURE,
            identity_type=IdentityType.AZURE_APP_SECRET,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=800),
            owner="legacy-ci-pipeline",
            raw={"app_id": "33333333-aaaa-bbbb-cccc-000000000003",
                 "app_name": "legacy-ci-pipeline",
                 "cred_id": "secret-002", "hint": "old-key-***",
                 "expires_at": (now - timedelta(days=60)).isoformat()},
            risk_flags=[
                RiskFlag(Severity.HIGH, "AZURE_CRED_EXPIRED",
                         "Credential expired 60 days ago",
                         "High: expired secret on a disabled SP. Delete both the "
                         "secret and the SP to eliminate the dormant credential."),
                RiskFlag(Severity.HIGH, "AZURE_SECRET_NOT_ROTATED",
                         "Client secret is 800 days old (max 365)",
                         "High: secret is 2x older than rotation policy. "
                         "If SP is decommissioned, delete the credential entirely."),
            ],
        ),
        Identity(
            id="azure:app_cert:11111111:cert-001",
            name="aks-cluster-sp/cert:aks-auth-cert",
            provider=Provider.AZURE,
            identity_type=IdentityType.AZURE_APP_CERT,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=365),
            owner="aks-cluster-sp",
            raw={"app_id": "11111111-aaaa-bbbb-cccc-000000000001",
                 "app_name": "aks-cluster-sp",
                 "cred_id": "cert-001", "cert_name": "aks-auth-cert",
                 "usage": "Verify",
                 "expires_at": (now + timedelta(days=180)).isoformat()},
            risk_flags=[],
        ),
    ]

    # ── GCP demo identities ──────────────────────────────────────────
    gcp_identities = [
        Identity(
            id="gcp:sa:my-project:terraform-deployer@my-project.iam.gserviceaccount.com",
            name="terraform-deployer",
            provider=Provider.GCP,
            identity_type=IdentityType.GCP_SERVICE_ACCOUNT,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=500),
            last_used=now - timedelta(hours=6),
            policies=["roles/owner"],
            raw={
                "email": "terraform-deployer@my-project.iam.gserviceaccount.com",
                "display_name": "Terraform Deployer",
                "unique_id": "100000000000000001",
                "disabled": False,
                "project_id": "my-project",
                "gcp_managed": False,
            },
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "GCP_SA_DANGEROUS_ROLE",
                         "Service account has roles/owner",
                         "Critical: roles/owner grants full control of the GCP project. "
                         "Replace with custom role scoped to Terraform-managed resources."),
            ],
        ),
        Identity(
            id="gcp:sa_key:my-project:abc123def456",
            name="terraform-deployer/key:abc123de",
            provider=Provider.GCP,
            identity_type=IdentityType.GCP_SA_KEY,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=400),
            created_by="terraform-deployer@my-project.iam.gserviceaccount.com",
            raw={
                "key_id": "abc123def456",
                "key_type": "USER_MANAGED",
                "key_origin": "GOOGLE_PROVIDED",
                "sa_email": "terraform-deployer@my-project.iam.gserviceaccount.com",
                "project_id": "my-project",
                "disabled": False,
            },
            risk_flags=[
                RiskFlag(Severity.HIGH, "GCP_KEY_NOT_ROTATED",
                         "SA key is 400 days old (max 365)",
                         "High: key exceeds rotation policy. Rotate and prefer "
                         "Workload Identity Federation over long-lived keys."),
            ],
        ),
        Identity(
            id="gcp:sa:my-project:ci-runner@my-project.iam.gserviceaccount.com",
            name="ci-runner",
            provider=Provider.GCP,
            identity_type=IdentityType.GCP_SERVICE_ACCOUNT,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=300),
            last_used=now - timedelta(hours=1),
            policies=["roles/editor", "roles/container.admin"],
            raw={
                "email": "ci-runner@my-project.iam.gserviceaccount.com",
                "display_name": "CI Runner",
                "unique_id": "100000000000000002",
                "disabled": False,
                "project_id": "my-project",
                "gcp_managed": False,
            },
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "GCP_SA_DANGEROUS_ROLE",
                         "Service account has roles/editor",
                         "Critical: roles/editor grants near-full access. "
                         "Use least-privilege custom roles for CI pipelines."),
                RiskFlag(Severity.HIGH, "GCP_SA_DANGEROUS_ROLE",
                         "Service account has roles/container.admin",
                         "High: container.admin grants full GKE cluster control. "
                         "Scope to specific clusters/namespaces."),
            ],
        ),
        Identity(
            id="gcp:sa:my-project:legacy-batch@my-project.iam.gserviceaccount.com",
            name="legacy-batch",
            provider=Provider.GCP,
            identity_type=IdentityType.GCP_SERVICE_ACCOUNT,
            classification=Classification.MACHINE,
            created_at=now - timedelta(days=900),
            last_used=now - timedelta(days=180),
            policies=["roles/storage.admin"],
            raw={
                "email": "legacy-batch@my-project.iam.gserviceaccount.com",
                "display_name": "",
                "unique_id": "100000000000000003",
                "disabled": True,
                "project_id": "my-project",
                "gcp_managed": False,
            },
            risk_flags=[
                RiskFlag(Severity.HIGH, "GCP_SA_DANGEROUS_ROLE",
                         "Service account has roles/storage.admin",
                         "High: storage.admin grants full control over all GCS buckets."),
                RiskFlag(Severity.MEDIUM, "GCP_SA_DISABLED_WITH_ROLES",
                         "Disabled service account still has IAM role bindings",
                         "Medium: remove IAM bindings from disabled SAs."),
                RiskFlag(Severity.MEDIUM, "STALE_IDENTITY",
                         "Not used in 180 days (threshold: 90)",
                         "Medium: disabled and stale. Delete after confirming no dependencies."),
            ],
        ),
    ]

    # ── GitHub Actions OIDC demo identities ──────────────────────────
    oidc_identities = [
        Identity(
            id="github:oidc:aws:deploy.yml:arn:aws:iam::123456789012:role/github-deploy-admin",
            name="OIDC → AWS (Deploy to Prod)",
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_ACTIONS_OIDC,
            classification=Classification.MACHINE,
            raw={
                "workflow_file": "deploy.yml",
                "workflow_name": "Deploy to Prod",
                "job_name": "deploy",
                "cloud_provider": "aws",
                "role_arn": "arn:aws:iam::123456789012:role/github-deploy-admin",
                "role_policies": ["AdministratorAccess"],
                "trigger_events": ["push", "pull_request"],
                "has_oidc_permission": True,
            },
            risk_flags=[
                RiskFlag(Severity.CRITICAL, "GH_OIDC_ADMIN_ROLE",
                         "OIDC workflow assumes AWS role with AdministratorAccess",
                         "Critical: GitHub Actions workflow 'Deploy to Prod' uses OIDC to assume "
                         "a role with AdministratorAccess. A compromised workflow or malicious PR "
                         "could gain full AWS account control."),
                RiskFlag(Severity.HIGH, "GH_OIDC_PR_TRIGGER",
                         "OIDC cloud auth triggered on pull_request events",
                         "High: any contributor can trigger this workflow via a PR, "
                         "obtaining AWS admin credentials. Restrict to push events only."),
            ],
        ),
        Identity(
            id="github:oidc:azure:infra.yml:11111111-aaaa-bbbb-cccc-000000000001",
            name="OIDC → Azure (Infra Deploy)",
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_ACTIONS_OIDC,
            classification=Classification.MACHINE,
            raw={
                "workflow_file": "infra.yml",
                "workflow_name": "Infra Deploy",
                "job_name": "terraform",
                "cloud_provider": "azure",
                "azure_client_id": "11111111-aaaa-bbbb-cccc-000000000001",
                "azure_tenant_id": "tenant-001",
                "trigger_events": ["push"],
                "has_oidc_permission": True,
            },
            risk_flags=[
                RiskFlag(Severity.HIGH, "GH_OIDC_AZURE_CONTRIBUTOR",
                         "OIDC workflow federates to Azure SP with Contributor at subscription",
                         "High: workflow 'Infra Deploy' assumes aks-cluster-sp which has "
                         "Contributor at subscription scope. Scope the SP role to a resource group."),
            ],
        ),
        Identity(
            id="github:oidc:gcp:ci.yml:ci-runner@my-project.iam.gserviceaccount.com",
            name="OIDC → GCP (CI Pipeline)",
            provider=Provider.GITHUB,
            identity_type=IdentityType.GITHUB_ACTIONS_OIDC,
            classification=Classification.MACHINE,
            raw={
                "workflow_file": "ci.yml",
                "workflow_name": "CI Pipeline",
                "job_name": "build-and-push",
                "cloud_provider": "gcp",
                "gcp_service_account": "ci-runner@my-project.iam.gserviceaccount.com",
                "gcp_wif_provider": "projects/123/locations/global/workloadIdentityPools/github/providers/my-repo",
                "trigger_events": ["push", "pull_request"],
                "has_oidc_permission": True,
            },
            risk_flags=[
                RiskFlag(Severity.HIGH, "GH_OIDC_PR_TRIGGER",
                         "OIDC cloud auth triggered on pull_request events",
                         "High: PR authors can trigger GCP access via Workload Identity "
                         "Federation. Use environment protection rules or restrict triggers."),
            ],
        ),
    ]

    # ── Build combined result ──────────────────────────────────────
    all_ids = (aws_identities + azure_identities + gcp_identities
               + github_identities + k8s_identities + oidc_identities)
    return ScanResult(
        identities=all_ids,
        providers_scanned=["aws", "azure", "gcp", "github", "kubernetes", "github-actions"],
        scan_time=now,
    )


def _print_demo_table(result: ScanResult) -> None:
    """Print the polished per-provider demo with combined summary."""
    from nhinsight.core.models import Severity
    from nhinsight.core.output import (
        BOLD,
        CYAN,
        GREEN,
        RED,
        RESET,
        YELLOW,
    )

    print(f"\n  {BOLD}╔══════════════════════════════════════════════════════════╗{RESET}")
    print(f"  {BOLD}║  NHInsight — Non-Human Identity Report (demo)           ║{RESET}")
    print(f"  {BOLD}╚══════════════════════════════════════════════════════════╝{RESET}\n")

    # Per-provider sections
    provider_labels = {
        "aws": ("AWS IAM — Account: 123456789012", "aws"),
        "azure": ("Azure AD — Tenant: acme-corp.onmicrosoft.com", "azure"),
        "gcp": ("GCP IAM — Project: my-project", "gcp"),
        "github": ("GitHub — Org: acme-corp", "github"),
        "kubernetes": ("Kubernetes — Cluster: prod-cluster", "kubernetes"),
    }

    for pkey, (label, prov) in provider_labels.items():
        ids = [i for i in result.identities if i.provider.value == prov]
        if not ids:
            continue

        from nhinsight.core.models import ScanResult as SR
        sub = SR(identities=ids, providers_scanned=[pkey], scan_time=result.scan_time)

        print(f"  {BOLD}┌──────────────────────────────────────────────────────────┐{RESET}")
        print(f"  {BOLD}│  {label:<57s}│{RESET}")
        print(f"  {BOLD}└──────────────────────────────────────────────────────────┘{RESET}")
        print_result(sub, fmt="table")

    # ── Combined summary block ───────────────────────────────────
    from nhinsight.core.models import Classification
    nhis = [i for i in result.identities if i.classification != Classification.HUMAN]
    humans = [i for i in result.identities if i.classification == Classification.HUMAN]

    total = len(nhis)
    crit = sum(1 for i in nhis if i.highest_severity.value == "critical")
    high = sum(1 for i in nhis if i.highest_severity.value == "high")
    med = sum(1 for i in nhis if i.highest_severity.value == "medium")
    low = sum(1 for i in nhis if i.highest_severity.value == "low")
    healthy = sum(1 for i in nhis if i.highest_severity.value == "info")

    # Short, specific remediation for each urgent fix
    urgent_lines = []
    for ident in nhis:
        for flag in ident.risk_flags:
            if flag.severity in (Severity.CRITICAL, Severity.HIGH):
                # Build a short actionable line
                name = ident.name
                # Extract first imperative from detail
                detail = flag.detail or flag.message
                # Take text after "Critical: " or "High: " prefix
                for prefix in ("Critical: ", "High: "):
                    if detail.startswith(prefix):
                        detail = detail[len(prefix):]
                        break
                # First sentence only
                action = detail.split(". ")[0]
                # Capitalize
                if action and action[0].islower():
                    action = action[0].upper() + action[1:]
                urgent_lines.append((flag.severity, f"{name} — {action}"))

    order = {Severity.CRITICAL: 0, Severity.HIGH: 1}
    urgent_lines.sort(key=lambda x: order.get(x[0], 99))
    urgent_lines = urgent_lines[:3]

    print(f"\n  {BOLD}{'─' * 60}{RESET}")
    print(f"  {BOLD}COMBINED SUMMARY{RESET}")
    print(f"  {BOLD}{'─' * 60}{RESET}")
    print(f"  NHIs discovered:  {BOLD}{total}{RESET}"
          + (f"  (+{len(humans)} related humans)" if humans else ""))
    print(f"  {RED}Critical:{RESET} {crit}   "
          f"{RED}High:{RESET} {high}   "
          f"{YELLOW}Medium:{RESET} {med}   "
          f"{CYAN}Low:{RESET} {low}   "
          f"{GREEN}Healthy:{RESET} {healthy}")
    print()
    if urgent_lines:
        print(f"  {RED}{BOLD}Urgent fixes:{RESET}")
        for i, (_, line) in enumerate(urgent_lines, 1):
            print(f"  {i}. {line}")
    print(f"  {BOLD}{'─' * 60}{RESET}\n")

    # Post-demo suggestions
    print(f"  {BOLD}Try it on your infrastructure:{RESET}")
    print("    nhinsight scan --aws              Scan AWS IAM")
    print("    nhinsight scan --all              Scan all providers")
    print("    nhinsight scan --aws --explain    AI-powered explanations")
    print("    nhinsight scan --all -f sarif     SARIF for GitHub Security tab")
    print()


def _run_graph(args: argparse.Namespace) -> None:
    """Load saved JSON output and render Mermaid attack path diagrams."""
    import json

    from nhinsight.analyzers.attack_paths import (
        AttackPath,
        AttackPathResult,
        AttackPathStep,
    )
    from nhinsight.core.mermaid import (
        render_attack_paths,
        render_attack_paths_individual,
        render_summary_table,
    )
    from nhinsight.core.models import Severity

    input_path = args.input
    try:
        with open(input_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Error: file not found: {input_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: invalid JSON in {input_path}: {e}")
        sys.exit(1)

    # Reconstruct AttackPathResult from JSON
    # Support both full scan output (with "attack_paths" key) and direct AP output
    ap_data = data if "paths" in data else data.get("attack_paths", data)

    if "paths" not in ap_data:
        print("Error: no attack path data found in JSON. "
              "Run scan with --attack-paths -f json first.")
        sys.exit(1)

    sev_map = {s.value: s for s in Severity}

    paths = []
    for p in ap_data["paths"]:
        steps = [
            AttackPathStep(
                node_id=s["node_id"],
                node_label=s["node_label"],
                node_type=s["node_type"],
                provider=s["provider"],
                edge_type=s.get("edge_type"),
                edge_label=s.get("edge_label", ""),
            )
            for s in p.get("steps", [])
        ]
        paths.append(AttackPath(
            id=p.get("id", "AP-???"),
            steps=steps,
            severity=sev_map.get(p.get("severity", "medium"), Severity.MEDIUM),
            blast_radius=float(p.get("blast_radius", 0)),
            cross_system=p.get("cross_system", False),
            description=p.get("description", ""),
            recommendation=p.get("recommendation", ""),
        ))

    ap_result = AttackPathResult(
        paths=paths,
        graph_stats=ap_data.get("graph", {}),
    )

    out = sys.stdout
    if args.output:
        out = open(args.output, "w")

    render_summary_table(ap_result, out=out)

    if getattr(args, "split", False):
        render_attack_paths_individual(ap_result, out=out)
    else:
        render_attack_paths(ap_result, out=out)

    if args.output:
        out.close()
        print(f"Mermaid output written to {args.output}")


def _output_result(result: ScanResult, fmt: str, output_path: str | None) -> None:
    """Output a ScanResult in the requested format, optionally to a file."""
    if output_path:
        with open(output_path, "w") as f:
            print_result(result, fmt=fmt, out=f)
        print(f"Report written to {output_path}")
    else:
        print_result(result, fmt=fmt)


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        level = logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING
        logging.basicConfig(level=level, format="%(levelname)s: %(message)s")
        _run_scan(args)
    elif args.command == "demo":
        result = _build_demo_data()
        fmt = getattr(args, "format", "table")
        output_path = getattr(args, "output", None)
        wants_ci = getattr(args, "ci_summary", False)

        # Determine ASCII-safe mode
        from nhinsight.core.ci_summary import is_ci
        ascii_safe = getattr(args, "ascii", False) or is_ci()

        if wants_ci:
            # CI summary mode — compact markdown replaces normal output
            from nhinsight.analyzers.attack_paths import analyze_attack_paths
            from nhinsight.core.ci_summary import print_ci_summary, write_github_step_summary
            ap_result = analyze_attack_paths(result.identities)
            out = sys.stdout
            if output_path:
                out = open(output_path, "w")
            print_ci_summary(result, ap_result, out=out, ascii_safe=ascii_safe)
            write_github_step_summary(result, ap_result, ascii_safe=True)
            if output_path:
                out.close()
                print(f"Results written to {output_path}")
        else:
            if fmt == "table" and not output_path:
                _print_demo_table(result)
            else:
                _output_result(result, fmt, output_path)
            # Attack path analysis for demo (--attack-paths or --mermaid)
            wants_attack = getattr(args, "attack_paths", False) or getattr(args, "mermaid", False)
            if wants_attack:
                from nhinsight.analyzers.attack_paths import analyze_attack_paths
                ap_result = analyze_attack_paths(result.identities)
                out = sys.stdout
                if output_path:
                    out = open(output_path, "a")
                if not getattr(args, "mermaid", False):
                    from nhinsight.core.output import print_attack_paths
                    print_attack_paths(ap_result, out=out, ascii_safe=ascii_safe)
                if getattr(args, "mermaid", False):
                    from nhinsight.core.mermaid import render_attack_paths, render_summary_table
                    render_summary_table(ap_result, out=out)
                    render_attack_paths(ap_result, out=out)
                if output_path:
                    out.close()
    elif args.command == "graph":
        _run_graph(args)
    elif args.command == "report":
        if getattr(args, "demo", False):
            result = _build_demo_data()
        else:
            print("Error: --demo is required for now. Live scan reports coming soon.")
            sys.exit(1)
        fmt = getattr(args, "format", "markdown")
        output_path = getattr(args, "output", None)
        _output_result(result, fmt, output_path)
    elif args.command == "version":
        print(f"nhinsight {__version__}")
    else:
        parser.print_help()
        print("\n  \033[1mQuick start:\033[0m")
        print("    nhinsight demo            # sample data, no credentials needed")
        print("    nhinsight scan --aws      # scan your AWS account")
        print()


if __name__ == "__main__":
    main()

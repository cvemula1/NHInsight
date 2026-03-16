<div align="center">

# 🔍 NHInsight

**Find and fix risky non-human identities across your cloud infrastructure**

*The open-source CLI for NHI discovery, risk analysis, and attack path detection*

[![CI](https://github.com/cvemula1/NHInsight/actions/workflows/ci.yml/badge.svg)](https://github.com/cvemula1/NHInsight/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/nhinsight?logo=python&logoColor=white)](https://pypi.org/project/nhinsight/)
[![PyPI](https://img.shields.io/pypi/v/nhinsight?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/nhinsight/)
[![Docker](https://img.shields.io/docker/v/cvemula1/nhinsight?label=docker&logo=docker&logoColor=white&sort=semver)](https://hub.docker.com/r/cvemula1/nhinsight)
[![License](https://img.shields.io/github/license/cvemula1/NHInsight?color=green)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/cvemula1/NHInsight?style=social)](https://github.com/cvemula1/NHInsight)

[![AWS](https://img.shields.io/badge/AWS-IAM-FF9900?logo=amazonaws&logoColor=white)](#aws)
[![Azure](https://img.shields.io/badge/Azure-Entra_ID-0078D4?logo=microsoftazure&logoColor=white)](#azure)
[![GCP](https://img.shields.io/badge/GCP-IAM-4285F4?logo=googlecloud&logoColor=white)](#gcp)
[![GitHub](https://img.shields.io/badge/GitHub-Org-181717?logo=github&logoColor=white)](#github)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-RBAC-326CE5?logo=kubernetes&logoColor=white)](#kubernetes)

---

</div>

> 🎨 **We need a logo!** If you're a designer or have ideas, open an issue with the tag `logo` — we'd love your input. See [#1 Logo Discussion](https://github.com/cvemula1/NHInsight/issues/1).

## The Problem

Non-human identities outnumber humans **45:1** in most orgs. They're the service accounts with admin privs created 3 years ago by someone who left, the access keys nobody rotated, the deploy keys nobody tracks. Most major cloud breaches in recent years traced back to compromised non-human identities.

Enterprise NHI tools charge **$50K+/year**. NHInsight does it for free.

## Installation

```bash
# Core (AWS only)
pip install nhinsight

# With specific providers
pip install nhinsight[azure]            # + Azure AD / Entra ID
pip install nhinsight[gcp]              # + GCP IAM
pip install nhinsight[github]           # + GitHub
pip install nhinsight[kubernetes]       # + Kubernetes
pip install nhinsight[gcp,kubernetes]   # mix and match

# Everything (all 5 providers + AI explanations)
pip install nhinsight[all]

# From source (development)
git clone https://github.com/cvemula1/NHInsight.git
cd NHInsight
pip install -e ".[all,dev]"
```

> **Note:** AWS (`boto3`) is included by default. All other providers are optional — install only what you need, or use `[all]` to get everything.

### Docker

```bash
# Build
docker build -t nhinsight .

# Run demo
docker run --rm nhinsight demo

# Scan AWS (pass credentials via env vars)
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_DEFAULT_REGION \
  nhinsight scan --aws

# Scan GCP (mount ADC credentials)
docker run --rm \
  -e GCP_PROJECT=my-project \
  -v ~/.config/gcloud:/root/.config/gcloud:ro \
  nhinsight scan --gcp

# Scan Azure
docker run --rm \
  -e AZURE_TENANT_ID \
  -e AZURE_CLIENT_ID \
  -e AZURE_CLIENT_SECRET \
  -e AZURE_SUBSCRIPTION_ID \
  nhinsight scan --azure

# Scan Kubernetes (mount kubeconfig)
docker run --rm \
  -v ~/.kube/config:/root/.kube/config:ro \
  nhinsight scan --k8s

# Scan GitHub
docker run --rm \
  -e GITHUB_TOKEN \
  nhinsight scan --github --github-org acme-corp

# Multi-provider + JSON output
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e GCP_PROJECT=my-project \
  -v ~/.config/gcloud:/root/.config/gcloud:ro \
  nhinsight scan --aws --gcp --attack-paths -f json
```

## Quick Start

```bash
# See a demo with sample data (no credentials needed)
nhinsight demo

# Scan your AWS account
nhinsight scan --aws

# Scan multiple providers at once
nhinsight scan --aws --gcp --k8s --attack-paths

# Scan everything available
nhinsight scan --all --attack-paths

# AI-powered explanations
export OPENAI_API_KEY=sk-...
nhinsight scan --aws --explain

# Output as JSON or SARIF (for GitHub Security tab)
nhinsight scan --aws --format json
nhinsight scan --all --format sarif -o results.sarif
```

## Demo Output

```
  NHInsight — Non-Human Identity Report (demo)

  ┌──────────────────────────────────────────────────────────┐
  │  AWS IAM — Account: 123456789012                         │
  │  Azure AD — Tenant: acme-corp.onmicrosoft.com            │
  │  GCP IAM — Project: my-project                           │
  │  GitHub — Org: acme-corp                                 │
  │  Kubernetes — Cluster: prod-cluster                      │
  └──────────────────────────────────────────────────────────┘

  🔴 CRITICAL — deploy-bot (iam_user, aws)
  │  Has AdministratorAccess policy attached

  🔴 CRITICAL — terraform-deployer (gcp_service_account, gcp)
  │  Service account has roles/owner

  🔴 CRITICAL — aks-cluster-sp (azure_sp, azure)
  │  SP has Contributor at subscription scope

  🔴 HIGH — terraform-deployer/key:abc123de (gcp_sa_key, gcp)
  │  SA key is 400 days old (max 365)

  ────────────────────────────────────────────────────────────
  Summary: 25+ NHIs across 5 providers
```

## Providers

| Provider | Status | What It Scans |
|----------|--------|---------------|
| **AWS IAM** | ✅ | Users, roles, access keys, policies, MFA, console access, trust relationships |
| **Azure AD / Entra ID** | ✅ | Service principals, managed identities, app secrets/certs, RBAC role assignments |
| **GCP IAM** | ✅ | Service accounts, SA keys (user-managed), project IAM bindings |
| **GitHub** | ✅ | Apps, deploy keys, org webhooks, repo webhooks, permissions |
| **Kubernetes** | ✅ | ServiceAccounts, RBAC, Secrets, Deployments, IRSA/WI annotations |

## What It Finds

**34 risk codes** across 6 categories:

### AWS

| Risk | Code | Severity |
|------|------|----------|
| Admin/PowerUser policy attached | `AWS_ADMIN_ACCESS` | Critical |
| Role trust allows any principal (`*`) | `AWS_WILDCARD_TRUST` | Critical |
| Access key never rotated (>365 days) | `AWS_KEY_NOT_ROTATED` | High |
| Console access without MFA | `AWS_NO_MFA` | High |
| Inactive key not deleted | `AWS_KEY_INACTIVE` | Medium |

### Azure

| Risk | Code | Severity |
|------|------|----------|
| SP/MI with Owner/Contributor at subscription scope | `AZURE_SP_DANGEROUS_ROLE` | Critical |
| Disabled SP still has RBAC bindings | `AZURE_SP_DISABLED_WITH_ROLES` | Medium |
| App credential expired | `AZURE_CRED_EXPIRED` | High |
| App credential expiring within 30 days | `AZURE_CRED_EXPIRING_SOON` | Medium |
| Secret not rotated (>365 days) | `AZURE_SECRET_NOT_ROTATED` | High |

### GCP

| Risk | Code | Severity |
|------|------|----------|
| SA with roles/owner or roles/editor | `GCP_SA_DANGEROUS_ROLE` | Critical |
| SA with compute.admin, storage.admin, etc. | `GCP_SA_DANGEROUS_ROLE` | High |
| Disabled SA still has IAM bindings | `GCP_SA_DISABLED_WITH_ROLES` | Medium |
| GCP-managed SA with dangerous roles | `GCP_MANAGED_SA_OVERPRIVILEGED` | High |
| SA key not rotated (>365 days) | `GCP_KEY_NOT_ROTATED` | High |
| SA key expired | `GCP_KEY_EXPIRED` | High |
| SA key expiring within 30 days | `GCP_KEY_EXPIRING_SOON` | Medium |

### Kubernetes

| Risk | Code | Severity |
|------|------|----------|
| SA bound to cluster-admin | `K8S_CLUSTER_ADMIN` | Critical |
| Legacy long-lived SA token secret | `K8S_LEGACY_SA_TOKEN` | High |
| Automount token on privileged SA | `K8S_AUTOMOUNT_PRIVILEGED` | High |
| Default SA in use / Orphaned SA / No WI | `K8S_*` | Medium |

### GitHub

| Risk | Code | Severity |
|------|------|----------|
| Token with admin scope | `GH_ADMIN_SCOPE` | High |
| App with dangerous write perms | `GH_APP_DANGEROUS_PERMS` | High |
| Deploy key with write access | `GH_DEPLOY_KEY_WRITE` | Medium |

### Universal

| Risk | Code | Severity |
|------|------|----------|
| Identity unused for 90+ days | `STALE_IDENTITY` | Medium |
| No owner or creator identified | `NO_OWNER` | Low |

## Features

- **5 providers** — AWS, Azure, GCP, GitHub, Kubernetes
- **34 risk checks** — overprivileged, stale, unrotated, ownerless, misconfigured
- **Identity graph** — maps relationships between identities across providers
- **Attack path analysis** — traces entry points to privileged resources, including cross-system chains
- **NIST SP 800-53 scoring** — maps findings to NIST controls, letter grades
- **IGA governance scores** — ownership, rotation, least-privilege, lifecycle hygiene
- **Human vs machine classification** — rule-based, no ML required
- **AI explanations** — optional OpenAI-powered plain-English risk summaries
- **SARIF output** — plug into GitHub Security tab or any SAST tool
- **Zero agents** — API reads only, installs nothing in your infra
- **Runs locally** — no cloud dependency, no telemetry, no phone-home

## Attack Path Analysis

Discover chains of identities and permissions that lead to privileged resources:

```bash
nhinsight scan --aws --k8s --gcp --attack-paths
```

NHInsight builds an identity graph from scan results and traces paths from entry points (keys, tokens, SAs) to privileged targets (admin roles, owner bindings, cluster-admin):

- **Cross-system paths** — K8s SA → IRSA → AWS admin role, K8s SA → GKE WI → GCP owner
- **Blast radius scoring** — 0–100 composite score based on privilege level, cross-system reach, path length
- **Severity** — Critical / High / Medium / Low based on blast radius
- **Fix guidance** — per-edge remediation recommendations

## Authentication

NHInsight only needs **read-only** access. It never modifies anything. Each provider uses its standard SDK credential chain — no custom auth, no agents.

### AWS

Uses the standard [boto3 credential chain](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/credentials.html):

| Method | How |
|--------|-----|
| **Environment variables** | `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` |
| **Named profile** | `export AWS_PROFILE=prod` or `--aws-profile prod` |
| **Instance role / ECS task role** | Automatic on EC2/ECS/Lambda |
| **SSO** | `aws sso login --profile prod` then `--aws-profile prod` |

```bash
# Minimum IAM permissions needed (read-only):
# iam:ListUsers, iam:ListRoles, iam:ListAccessKeys,
# iam:ListMFADevices, iam:GetLoginProfile,
# iam:ListUserPolicies, iam:ListAttachedUserPolicies,
# iam:ListRolePolicies, iam:ListAttachedRolePolicies,
# iam:GetAccessKeyLastUsed

nhinsight scan --aws
nhinsight scan --aws --aws-profile prod --aws-region us-east-1
```

### Azure

Uses [Azure Identity](https://learn.microsoft.com/en-us/python/api/azure-identity/) `DefaultAzureCredential`:

| Method | How |
|--------|-----|
| **Azure CLI** | `az login` (simplest for local dev) |
| **Service Principal** | `AZURE_CLIENT_ID` + `AZURE_CLIENT_SECRET` + `AZURE_TENANT_ID` |
| **Managed Identity** | Automatic on Azure VMs/AKS/Functions |
| **Environment variables** | `AZURE_TENANT_ID` + `AZURE_SUBSCRIPTION_ID` |

```bash
# Required API permissions:
# Microsoft Graph: Application.Read.All, Directory.Read.All
# Azure RBAC: Microsoft.Authorization/roleAssignments/read

az login
nhinsight scan --azure
nhinsight scan --azure --azure-tenant-id TENANT --azure-subscription-id SUB
```

### GCP

Uses [Google Application Default Credentials (ADC)](https://cloud.google.com/docs/authentication/application-default-credentials):

| Method | How |
|--------|-----|
| **gcloud CLI** | `gcloud auth application-default login` (simplest for local dev) |
| **Service Account key** | `export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json` |
| **Workload Identity** | Automatic on GKE/Cloud Run/Cloud Functions |
| **Environment variable** | `export GCP_PROJECT=my-project` or `--gcp-project my-project` |

```bash
# Required IAM roles (read-only):
# roles/iam.serviceAccountViewer (list SAs + keys)
# roles/resourcemanager.projectIamViewer (read IAM policy)

gcloud auth application-default login
nhinsight scan --gcp --gcp-project my-project
```

### GitHub

Uses a [Personal Access Token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) or GitHub App token:

| Method | How |
|--------|-----|
| **PAT (classic)** | `export GITHUB_TOKEN=ghp_...` — needs `read:org`, `repo` scopes |
| **PAT (fine-grained)** | Org-level read access to administration, webhooks, deploy keys |
| **GitHub App** | Install app on org, use installation token |
| **GitHub Enterprise** | `--github-base-url https://github.company.com/api/v3` |

```bash
export GITHUB_TOKEN=ghp_your_token
nhinsight scan --github --github-org acme-corp
nhinsight scan --github --github-org acme --github-base-url https://ghe.company.com/api/v3
```

### Kubernetes

Uses the standard [kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) credential chain:

| Method | How |
|--------|-----|
| **Current context** | Automatic — uses `~/.kube/config` default context |
| **Specific context** | `--kube-context prod-cluster` |
| **Custom kubeconfig** | `--kubeconfig /path/to/kubeconfig` |
| **In-cluster** | Automatic when running inside a pod |
| **Namespace filter** | `--kube-namespace payments` (default: all) |

```bash
# Required RBAC (read-only):
# ServiceAccounts, Secrets, Deployments, Pods: get, list
# ClusterRoleBindings, RoleBindings: get, list

nhinsight scan --k8s
nhinsight scan --k8s --kube-context prod --kube-namespace payments
```

### Multi-Provider

Combine any providers in a single scan:

```bash
# Scan AWS + GCP + K8s with attack path analysis
nhinsight scan --aws --gcp --k8s --attack-paths

# Scan everything available
nhinsight scan --all --attack-paths

# Output to SARIF for GitHub Security tab
nhinsight scan --all -f sarif -o results.sarif
```

## Configuration

All settings can be set via environment variables, CLI flags, or both (CLI flags take precedence):

| Setting | Env Var | CLI Flag | Default |
|---------|---------|----------|---------|
| AWS profile | `AWS_PROFILE` | `--aws-profile` | default chain |
| AWS region | `AWS_DEFAULT_REGION` | `--aws-region` | default chain |
| Azure tenant | `AZURE_TENANT_ID` | `--azure-tenant-id` | — |
| Azure subscription | `AZURE_SUBSCRIPTION_ID` | `--azure-subscription-id` | — |
| GCP project | `GCP_PROJECT` | `--gcp-project` | — |
| GitHub token | `GITHUB_TOKEN` | — | — |
| GitHub org | `GITHUB_ORG` | `--github-org` | — |
| Kubeconfig | `KUBECONFIG` | `--kubeconfig` | `~/.kube/config` |
| K8s context | `KUBE_CONTEXT` | `--kube-context` | current context |
| K8s namespace | `KUBE_NAMESPACE` | `--kube-namespace` | all |
| Stale threshold | `NHINSIGHT_STALE_DAYS` | `--stale-days` | 90 days |
| Rotation threshold | `NHINSIGHT_ROTATION_MAX_DAYS` | — | 365 days |
| AI explanations | `OPENAI_API_KEY` | `--explain` | — |

See [.env.example](.env.example) for a ready-to-copy template.

## CLI Reference

```
nhinsight scan [OPTIONS]          Discover and analyze NHIs
  --aws                           Scan AWS IAM
  --azure                         Scan Azure AD / Entra ID
  --gcp                           Scan GCP IAM
  --github                        Scan GitHub org
  --k8s                           Scan Kubernetes cluster
  --all                           Scan all available providers
  --attack-paths                  Run identity attack path analysis
  --format {table,json,sarif}     Output format (default: table)
  --explain                       Add AI-powered explanations
  --aws-profile PROFILE           AWS named profile
  --aws-region REGION             AWS region
  --azure-tenant-id ID            Azure tenant ID
  --azure-subscription-id ID      Azure subscription ID
  --gcp-project PROJECT           GCP project ID
  --github-org ORG                GitHub organization
  --kubeconfig PATH               Path to kubeconfig
  --kube-context CTX              Kubernetes context
  --kube-namespace NS             Namespace (default: all)
  --stale-days N                  Days without use before flagging (default: 90)
  --output FILE                   Write output to file
  --verbose                       Verbose logging

nhinsight demo                    Show demo scan with sample data
nhinsight version                 Show version
```

## Development

```bash
git clone https://github.com/cvemula1/NHInsight.git
cd NHInsight

# Install with all providers + dev tools
make dev
# or: pip install -e ".[all,dev]"

# Run tests (151 tests, <1 second)
make test

# Lint
make lint

# Run demo (no credentials needed)
make demo
```

### Makefile targets

| Target | What It Does |
|--------|-------------|
| `make dev` | Install editable with all extras + dev deps |
| `make test` | Run pytest |
| `make lint` | Run ruff linter |
| `make demo` | Run demo with sample data |
| `make scan-aws` | Scan AWS IAM |
| `make scan-gcp` | Scan GCP IAM |
| `make scan-azure` | Scan Azure AD |
| `make scan-all` | Scan all providers |
| `make docker` | Build Docker image |
| `make docker-demo` | Run demo in Docker |
| `make clean` | Remove build artifacts |

## Architecture

```
nhinsight/
├── cli.py                      # CLI entry point (argparse)
├── core/
│   ├── models.py               # Identity, RiskFlag, ScanResult, enums
│   ├── config.py               # NHInsightConfig (env vars + CLI flags)
│   └── output.py               # Table, JSON, SARIF formatters
├── providers/
│   ├── base.py                 # Abstract BaseProvider interface
│   ├── aws.py                  # AWS IAM discovery (boto3)
│   ├── azure.py                # Azure AD / Entra ID discovery (Graph + RBAC)
│   ├── gcp.py                  # GCP IAM discovery (google-api-python-client)
│   ├── github.py               # GitHub org discovery (PyGithub)
│   └── kubernetes.py           # Kubernetes discovery (kubernetes client)
├── analyzers/
│   ├── classification.py       # Human vs machine classification
│   ├── risk.py                 # Risk analysis (34 checks)
│   ├── scoring.py              # NIST SP 800-53 + IGA governance scoring
│   ├── graph.py                # Identity graph model (nodes, edges, BFS)
│   └── attack_paths.py         # Attack path detection + blast radius
└── explain/
    └── llm.py                  # Optional LLM explanations (OpenAI)
```

## Roadmap

### v0.1 — Core (shipped)

- [x] AWS IAM provider
- [x] Azure AD / Entra ID provider
- [x] GCP IAM provider
- [x] GitHub provider
- [x] Kubernetes provider
- [x] Risk analysis (34 checks across 5 providers)
- [x] Human vs machine classification
- [x] NIST SP 800-53 compliance scoring
- [x] IGA governance scoring
- [x] Identity graph + attack path analysis
- [x] LLM explanation layer (OpenAI)
- [x] SARIF output for CI/CD
- [x] Docker support

### v0.2 — Policy & Intelligence

- [ ] OPA/Rego policy engine — define custom rules for your org
- [ ] ML-based classification (scikit-learn) — auto-classify human vs machine
- [ ] Anomaly detection (Isolation Forest) — flag unusual identity behavior
- [ ] IAM right-sizing recommendations (LLM + CloudTrail/audit logs)

### v0.3 — Integrations & Alerting

- [ ] Slack notifications — send findings to a channel on scan completion
- [ ] Microsoft Teams alerts — webhook-based alerts for critical findings
- [ ] Jira / ServiceNow ticket creation — auto-create tickets for high/critical risks
- [ ] PagerDuty integration — trigger incidents for critical attack paths
- [ ] Webhook support — generic HTTP webhook for custom integrations

### v0.4 — SOC & Continuous Monitoring

- [ ] SIEM export (Splunk, Elastic, Sentinel) — ship findings to your SIEM
- [ ] Scheduled scans — cron-based continuous NHI monitoring
- [ ] Drift detection — alert when new NHIs appear or risk scores change
- [ ] Dashboard API — REST API for building custom dashboards
- [ ] GitHub Actions + GitLab CI templates — scan on every PR/merge

### v0.5 — Auto-Remediation & AI Agent

- [ ] Auto-rotate credentials — rotate AWS keys, GCP SA keys, Azure secrets with zero downtime
- [ ] Least-privilege policy generation — analyze CloudTrail/audit logs, propose right-sized IAM policies
- [ ] AI remediation agent — agent proposes fix plan, human approves, agent executes and verifies
- [ ] Stale identity cleanup — auto-disable unused identities after configurable grace period
- [ ] PR-based remediation — open pull requests with Terraform/IaC changes for IAM fixes
- [ ] Rollback safety — automatic rollback if a remediation breaks health checks

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Related Projects

- [ChangeTrail](https://github.com/cvemula1/ChangeTrail) — unified timeline of infrastructure changes

## License

MIT — see [LICENSE](LICENSE)

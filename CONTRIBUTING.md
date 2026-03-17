# Contributing to NHInsight

Hey, glad you're here. Setup takes about 2 minutes.

## Quick Setup

```bash
git clone https://github.com/cvemula1/NHInsight.git
cd NHInsight
make dev       # installs all providers + dev tools
make test      # 260 tests, <2 seconds
make demo      # see output without credentials
```

## Development Workflow

1. **Fork** and clone the repo
2. **Create a branch** — `git checkout -b feature/my-thing`
3. **Make changes** — follow the coding conventions below
4. **Run locally** — `make test && make lint` (both must pass)
5. **Submit PR** against `main` with a clear description

### What happens when you open a PR

CI runs automatically on every pull request:

- **Lint** — `ruff` style checks
- **Tests** — full test suite across Python 3.9–3.12
- **Security scan** — Trivy scans the Docker image for vulnerabilities
- **PR blocked** if any HIGH or CRITICAL vulnerability is found

All three checks must pass before a maintainer can merge.

### What happens on merge

- Tests + lint run again on `main`
- Docker image is built and smoke-tested (`version`, `demo`, `scan --help`)
- Trivy scan runs on the built image

### Releases

Releases are triggered by pushing a version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

This automatically:
- Runs the full test suite
- Builds and pushes multi-arch Docker image to Docker Hub (`amd64` + `arm64`)
- Publishes the package to PyPI
- Creates a GitHub Release with changelog

## Coding Conventions

- **License header**: `# MIT License — Copyright (c) 2026 cvemula1` on line 1
- **Future annotations**: `from __future__ import annotations` on line 2
- **Linter**: `ruff` (line-length 120, Python 3.9 target)
- **No custom auth**: use official SDKs (boto3, google-auth, PyGithub, kubernetes, azure-identity)
- **Secrets via env vars**: never hardcode credentials
- **Provider-specific data**: stored in `identity.raw` dict
- **Risk codes**: `PROVIDER_DESCRIPTION` format (e.g., `GCP_SA_DANGEROUS_ROLE`, `AWS_ADMIN_ACCESS`)
- **ID format**: `{provider}:{type}:{scope}:{name}` (e.g., `gcp:sa:my-project:deploy-sa`)

## Adding a New Provider

1. **Models** (`nhinsight/core/models.py`)
   - Add new `IdentityType` values
   - Add new `Provider` enum value

2. **Config** (`nhinsight/core/config.py`)
   - Add provider-specific fields (project ID, region, etc.)
   - Add env var loading in `from_env()`

3. **Provider** (`nhinsight/providers/your_provider.py`)
   - Inherit from `BaseProvider`
   - Implement `is_available()` and `discover()`
   - Use official SDK, no custom auth

4. **Classification** (`nhinsight/analyzers/classification.py`)
   - Add new identity types to `always_machine` set

5. **Risk** (`nhinsight/analyzers/risk.py`)
   - Add `_check_your_provider_risks()` function
   - Wire into `analyze_risk()` dispatcher

6. **Scoring** (`nhinsight/analyzers/scoring.py`)
   - Add risk codes to `NIST_CONTROL_MAP`
   - Add to `CREDENTIAL_IDENTITY_TYPES`, `ADMIN_RISK_CODES`, `ROTATION_RISK_CODES` as needed

7. **Graph** (`nhinsight/analyzers/graph.py`)
   - Add new `EdgeType` values
   - Add entry point types to `ENTRY_POINT_TYPES`
   - Add edge construction logic in `build_graph()`
   - Add privilege detection in `_is_privileged()`

8. **Attack Paths** (`nhinsight/analyzers/attack_paths.py`)
   - Add recommendations in `EDGE_RECOMMENDATIONS`

9. **CLI** (`nhinsight/cli.py`)
   - Add `--provider` flag and `--provider-*` config flags
   - Wire provider in `_run_scan()`
   - Add demo data in `_build_demo_data()`

10. **Tests** (`tests/test_your_provider_*.py`)
    - Risk checks (positive + negative cases)
    - Graph edges and privilege detection
    - Attack path detection

11. **Dependencies** (`pyproject.toml`)
    - Add SDK to `[project.optional-dependencies]`
    - Add to `all` extras group

## Project Structure

```
nhinsight/
├── cli.py                      # CLI + demo data
├── core/
│   ├── models.py               # Identity, RiskFlag, ScanResult
│   ├── config.py               # NHInsightConfig
│   └── output.py               # Table, JSON, SARIF output
├── providers/
│   ├── base.py                 # Abstract BaseProvider
│   ├── aws.py, azure.py, gcp.py, github.py, kubernetes.py
├── analyzers/
│   ├── classification.py       # Human vs machine
│   ├── risk.py                 # 34 risk checks
│   ├── scoring.py              # NIST + IGA scoring
│   ├── graph.py                # Identity graph
│   └── attack_paths.py         # Attack path BFS
└── explain/
    └── llm.py                  # Optional LLM explanations
```

## Running Tests

```bash
make test                    # all tests
python3 -m pytest tests/test_gcp_risk.py -v   # single file
python3 -m pytest -k "test_sa_owner" -v        # single test
```

## Questions?

Open an issue on GitHub.

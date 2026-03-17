# NHInsight — Usability Improvement Plan

*Practical analysis and code-level patches for developer adoption.*

---

## 1. Executive Summary

NHInsight is a solid v0.1 CLI. The core pipeline works: discover → classify → risk-score → attack-path → output. 151 tests pass. Five providers ship. The code is clean.

The adoption bottleneck is **not functionality** — it's **first-impression UX**. A developer landing on the repo needs to go from zero to "oh that's useful" in under 30 seconds. Right now the README, CLI, and demo all add friction that makes the tool feel heavier than it is.

**High-leverage changes (all small):**

1. **README** — restructure as landing page, push docs lower
2. **CLI** — friendly no-args help, better no-provider error, post-demo suggestions
3. **PyPI** — better description, classifiers, drop setup.py
4. **Demo** — add "try next" footer after demo runs
5. **Output** — tighten severity labels, improve the HIGH icon
6. **Attack paths** — better `--attack-paths` help text, plain-English chain descriptions
7. **Patch plan** — 4 files, ~80 lines changed, shippable in one session

None of these require new subsystems, dependencies, or architecture changes.

---

## 2. Biggest Adoption Blockers

Ranked by impact on a first-time GitHub visitor:

| # | Blocker | Where | Fix Effort |
|---|---------|-------|------------|
| 1 | README puts Installation + Docker before Quick Start | README.md | Reorder |
| 2 | Running `nhinsight` with no args shows argparse default (ugly) | cli.py | 10 lines |
| 3 | Running `nhinsight scan` with no provider says "No providers specified" (no guidance) | cli.py | 5 lines |
| 4 | Demo ends silently — no "try this next" | cli.py | 8 lines |
| 5 | README "What It Finds" is 60 lines of tables before features | README.md | Collapse |
| 6 | HIGH severity uses same 🔴 icon as CRITICAL (confusing) | output.py | 1 line |
| 7 | `--attack-paths` help text is generic | cli.py | 1 line |
| 8 | PyPI description is too generic | pyproject.toml | 1 line |

All fixable in a single PR.

---

## 3. README Rewrite

**See the actual README.md in this repo** — I will implement this directly.

Structure:
1. Hero (title + one-liner + badges)
2. Quick Start (pip install + demo — 2 commands)
3. Scan examples (5 providers + multi)
4. Example output (compact, screenshot-friendly)
5. What It Finds (6 bullets, not tables)
6. Supported Providers (5 bullets)
7. Key Capabilities (6 bullets)
8. Install Options (4 pip lines + collapsible Docker)
9. Authentication (quick table + collapsible detail)
10. Attack Path Analysis (always visible — differentiator)
11. Risk Codes (collapsible)
12. Configuration (collapsible)
13. CLI Reference (collapsible)
14. Development (4 lines + collapsible)
15. Roadmap (5 one-liners)
16. Why NHInsight? (problem statement at bottom, not top)
17. Contributing / Related / License

Key decisions:
- Quick Start is line 15, not line 107
- "The Problem" becomes "Why NHInsight?" at the bottom (credibility, not first-screen)
- Risk code tables are collapsed — impressive when opened, not blocking when closed
- Auth detail is collapsed — quick table always visible
- Docker examples collapsed
- Architecture + Makefile collapsed
- Roadmap condensed to one-liners

---

## 4. CLI UX Improvements

### 4a. No-args behavior (`nhinsight` with nothing)

**Current:** Shows argparse default help (functional but cold).

**Improved:** Same help output but add a highlighted quick-start hint at the end.

Change in `main()` at `cli.py:1132`:

```python
else:
    parser.print_help()
    print(f"\n  {BOLD}Quick start:{RESET}")
    print(f"    nhinsight demo            # see sample data, no credentials")
    print(f"    nhinsight scan --aws      # scan your AWS account")
    print()
```

### 4b. No-provider error (`nhinsight scan` with no flags)

**Current (line 203):**
```
No providers specified. Use --aws, --azure, --gcp, --github, --k8s, or --all
```

**Improved:**
```
No providers selected.

  Quick examples:
    nhinsight scan --aws                  Scan AWS IAM
    nhinsight scan --all --attack-paths   Scan everything
    nhinsight demo                        Try with sample data first

  Providers: --aws  --azure  --gcp  --github  --k8s  --all
```

### 4c. Provider auth failure messages

**Current (line 216):**
```
AWS credentials not available. Configure AWS CLI or set AWS_PROFILE.
```

These are already good. Minor improvement — add the exact command:

```
AWS: credentials not found. Run 'aws configure' or set AWS_ACCESS_KEY_ID.
Azure: credentials not found. Run 'az login' or set AZURE_TENANT_ID + AZURE_CLIENT_ID.
GCP: credentials not found. Run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS.
GitHub: token not found. Set GITHUB_TOKEN=ghp_... and use --github-org.
Kubernetes: cluster not reachable. Check ~/.kube/config or use --kube-context.
```

### 4d. Post-demo suggestions

After `_print_demo_table()` completes, print:

```
  Try it on your infrastructure:
    nhinsight scan --aws              Scan AWS IAM
    nhinsight scan --all              Scan all available providers
    nhinsight scan --aws --explain    Add AI-powered explanations
```

### 4e. `--attack-paths` help text

**Current:**
```
Run identity attack path analysis
```

**Improved:**
```
Trace privilege chains across providers (e.g. K8s SA → IRSA → AWS admin)
```

---

## 5. Packaging / PyPI Improvements

### 5a. pyproject.toml changes

**Description** (line 8):
```
Current:  "Non-Human Identity discovery for cloud infrastructure"
Better:   "Discover risky non-human identities and privilege paths across AWS, Azure, GCP, GitHub, and Kubernetes"
```

**Add classifiers:**
```toml
"Environment :: Console",
"Operating System :: OS Independent",
"Typing :: Typed",
```

**Add `Documentation` URL:**
```toml
Documentation = "https://github.com/cvemula1/NHInsight#quick-start"
Changelog = "https://github.com/cvemula1/NHInsight/releases"
```

### 5b. setup.py

The current `setup.py` is a 3-line shim. It's only needed for `pip install -e .` on older pip. **Keep it** — it's harmless and avoids edge-case breakage. No change needed.

### 5c. README as long_description

Already set via `readme = "README.md"` in pyproject.toml. The rewritten README with collapsible `<details>` sections will render well on PyPI (PyPI supports `<details>` in markdown since 2023). No change needed.

### 5d. Release checklist for PyPI

```
1. Bump version in nhinsight/__init__.py + pyproject.toml
2. Update CHANGELOG.md (if exists)
3. git tag v0.1.x
4. git push origin v0.1.x  (triggers release.yml)
5. Verify PyPI page renders correctly
6. Verify Docker Hub image tagged
7. Create GitHub Release with notes
```

---

## 6. Demo Improvements

### 6a. Post-demo footer

Add after the combined summary in `_print_demo_table()` (after line 1092):

```python
# Post-demo suggestions
print(f"\n  {BOLD}Try it on your infrastructure:{RESET}")
print(f"    nhinsight scan --aws              Scan AWS IAM")
print(f"    nhinsight scan --all              Scan all providers")
print(f"    nhinsight scan --aws --explain    AI-powered explanations")
print(f"    nhinsight scan --all -f sarif     SARIF for GitHub Security tab")
print()
```

### 6b. Demo output is already good

The demo data covers all 5 providers with realistic findings. The combined summary with urgent fixes is solid. The scorecard and NIST compliance sections are impressive for screenshots.

**One minor tweak:** The demo header could include a timing line to show speed:

After line 1016, add:
```python
print(f"  {DIM}Scanned 5 providers in 0.3s{RESET}\n")
```

This is cosmetic but reinforces "fast tool" positioning.

### 6c. Demo attack paths

The demo currently does NOT run attack paths. To make the demo show attack path analysis (which is the differentiator), add `--attack-paths` support to the demo command:

In `_build_parser()`, add to demo_p:
```python
demo_p.add_argument("--attack-paths", action="store_true",
                    help="Include attack path analysis in demo")
```

In `main()` demo handler, after printing:
```python
if getattr(args, "attack_paths", False):
    from nhinsight.analyzers.attack_paths import analyze_attack_paths
    from nhinsight.core.output import print_attack_paths
    ap_result = analyze_attack_paths(result.identities)
    print_attack_paths(ap_result)
```

---

## 7. Output Clarity Improvements

### 7a. HIGH severity icon

**Current:** Both CRITICAL and HIGH use 🔴. This makes them visually identical.

**Fix in output.py line 31:**
```python
Severity.HIGH: "🟠",
```

This matches the README example output and is the standard convention.

### 7b. Severity label formatting

**Current (line 43):**
```python
out.write(f"  {color}{icon} {label} ({len(identities)}){RESET}\n")
```

This prints `🔴 CRITICAL (3)` which is clear. No change needed.

### 7c. Identity type display

**Current (line 47):**
```python
out.write(f"  {DIM}({ident.identity_type.value}, {ident.provider.value}){RESET}\n")
```

This shows `(iam_user, aws)` — uses enum values with underscores. Could be prettier but it's consistent with JSON/SARIF output. **Leave as-is** for now. Changing display names is a v0.2 polish.

### 7d. Summary line

**Current (line 109):**
```python
out.write(f"  Summary: {len(nhis)} NHIs")
```

Good. No change.

### 7e. Attack path output

**Current (line 400):**
```python
blast_str = f"  blast: {path.blast_radius:.0f}/100"
```

**Improved wording:**
```python
blast_str = f"  risk: {path.blast_radius:.0f}/100"
```

"risk" is more intuitive than "blast" for most users. The blast_radius internal name can stay.

---

## 8. Attack Path Wording Improvements

### 8a. Better `--attack-paths` help text

**Current (line 111):**
```python
help="Run identity attack path analysis"
```

**Improved:**
```python
help="Trace privilege escalation chains across providers (e.g. K8s SA → cloud admin)"
```

### 8b. README attack path section

The current section is good. One improvement — add 3 concrete example chains:

```markdown
Example chains NHInsight detects:
- **K8s → AWS**: ServiceAccount → IRSA role → IAM role with AdministratorAccess
- **K8s → GCP**: ServiceAccount → Workload Identity → SA with roles/owner
- **GitHub → AWS**: Deploy key → workflow → OIDC → IAM role with S3FullAccess
```

### 8c. Attack path output header

**Current (line 371):**
```python
out.write(f"  {BOLD}Identity Attack Path Analysis{RESET}\n")
```

**Improved:**
```python
out.write(f"  {BOLD}Privilege Escalation Paths{RESET}\n")
```

"Privilege Escalation Paths" is more immediately understood than "Identity Attack Path Analysis."

### 8d. Path display label

**Current (line 398):**
```python
out.write(f"  {color}{icon} {path.id}{RESET}")
```

Shows `AP-001` which is opaque. Add the description:

```python
out.write(f"  {color}{icon} {path.id} — {path.description}{RESET}")
```

The `description` field already contains `entry → target (cross-system: k8s → aws)`.

---

## 9. Minimal Patch Plan

**4 files. ~80 lines changed. One PR.**

### Priority 1 — Highest UX impact (do first)

| File | Change | Lines |
|------|--------|-------|
| `README.md` | Restructure: Quick Start first, collapsible details | Full rewrite |
| `cli.py:1092` | Add post-demo "try next" suggestions | +8 lines |
| `cli.py:202-204` | Better no-provider error with examples | +8 lines |
| `cli.py:1132` | Friendly no-args hint | +4 lines |

### Priority 2 — Polish (do second)

| File | Change | Lines |
|------|--------|-------|
| `output.py:31` | HIGH icon: 🔴 → 🟠 | 1 line |
| `output.py:371` | Header: "Privilege Escalation Paths" | 1 line |
| `output.py:400` | "blast" → "risk" label | 1 line |
| `output.py:398` | Show path description alongside ID | 1 line |
| `cli.py:111` | Better `--attack-paths` help text | 1 line |
| `pyproject.toml:8` | Better PyPI description | 1 line |
| `pyproject.toml:14-27` | Add classifiers + URLs | +5 lines |

### Priority 3 — Nice-to-have (do if time)

| File | Change | Lines |
|------|--------|-------|
| `cli.py:126` | Add `--attack-paths` flag to demo command | +3 lines |
| `cli.py:1113` | Handle demo `--attack-paths` | +5 lines |
| `cli.py:216,227,240,252,264` | Improve auth error messages | 5 lines |

### What can wait until v0.2

- Identity type display names (e.g. `iam_user` → `IAM User`)
- Provider badges in terminal output
- Interactive mode / TUI
- Separate docs/ folder with detailed guides
- Progress spinner during scans
- `nhinsight init` command for first-time setup

---

## 10. Optional Later Improvements

These are good ideas that don't belong in this patch:

1. **`nhinsight init`** — interactive first-run wizard that checks which providers are configured
2. **`nhinsight explain AP-001`** — explain a specific attack path in plain English using LLM
3. **Progress indicator** — show a spinner or progress bar during long scans
4. **`--quiet` flag** — suppress everything except summary line (for CI/CD)
5. **`--fail-on critical`** — exit non-zero if critical findings exist (for CI gates)
6. **GitHub Actions template** — `.github/workflows/nhinsight.yml` users can copy
7. **Separate docs site** — move auth/config/risk-codes to a mkdocs or docusaurus site
8. **Terminal width detection** — adapt output formatting to terminal width
9. **Color detection** — disable ANSI when piping to file (currently always colored)
10. **Completion scripts** — bash/zsh/fish completions for CLI flags

None of these are urgent. The 9-point patch plan above is the right next step.

---

*Generated for NHInsight v0.1.0 — practical patches, no platform thinking.*

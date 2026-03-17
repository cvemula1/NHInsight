# MIT License — Copyright (c) 2026 cvemula1
# Output formatting for NHInsight scan results

from __future__ import annotations

import json
import sys
from typing import TextIO

from nhinsight.core.models import ScanResult, Severity

# ANSI color codes
RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

SEVERITY_COLORS = {
    Severity.CRITICAL: RED,
    Severity.HIGH: RED,
    Severity.MEDIUM: YELLOW,
    Severity.LOW: CYAN,
    Severity.INFO: GREEN,
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "�",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "🟢",
}


def _print_identity_group(identities, sev, out):
    """Print a group of identities at a given severity level."""
    color = SEVERITY_COLORS[sev]
    icon = SEVERITY_ICONS[sev]
    label = sev.value.upper()
    out.write(f"  {color}{icon} {label} ({len(identities)}){RESET}\n")

    for ident in identities:
        out.write(f"  {color}├─{RESET} {BOLD}{ident.name}{RESET}")
        out.write(f"  {DIM}({ident.identity_type.value}, {ident.provider.value}){RESET}\n")

        for flag in ident.risk_flags:
            if flag.severity == sev:
                out.write(f"  {color}│  {RESET}{DIM}{flag.message}{RESET}\n")

    out.write("\n")


def print_table(result: ScanResult, out: TextIO = sys.stdout) -> None:
    """Print scan results as a formatted terminal table."""
    from nhinsight.core.models import Classification

    nhis = [i for i in result.identities if i.classification != Classification.HUMAN]
    humans = [i for i in result.identities if i.classification == Classification.HUMAN]

    out.write(f"\n  {BOLD}NHInsight — Non-Human Identity Report{RESET}\n")
    out.write(f"  {'═' * 56}\n\n")

    if result.providers_scanned:
        out.write(f"  Providers: {', '.join(result.providers_scanned)}\n")
    out.write(f"  Scanned: {len(nhis)} NHIs")
    if humans:
        out.write(f" + {len(humans)} related humans")
    out.write("\n\n")

    if result.errors:
        for err in result.errors:
            out.write(f"  {RED}Error: {err}{RESET}\n")
        out.write("\n")

    # NHIs grouped by severity
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        group = [i for i in nhis if i.highest_severity == sev]
        if group:
            _print_identity_group(group, sev, out)

    # Humans in a separate section (if any have risk flags)
    risky_humans = [h for h in humans if h.risk_flags]
    safe_humans = [h for h in humans if not h.risk_flags]
    if risky_humans or safe_humans:
        out.write(f"  {DIM}{'─' * 56}{RESET}\n")
        out.write(f"  {DIM}Related human identities{RESET}\n\n")
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            group = [h for h in risky_humans if h.highest_severity == sev]
            if group:
                _print_identity_group(group, sev, out)
        if safe_humans:
            out.write(f"  {GREEN}🟢 HEALTHY ({len(safe_humans)}){RESET}\n")
            for h in safe_humans:
                out.write(f"  {GREEN}├─{RESET} {BOLD}{h.name}{RESET}")
                out.write(f"  {DIM}({h.identity_type.value}, {h.provider.value}){RESET}\n")
            out.write("\n")

    # Summary
    nhi_crit = sum(1 for i in nhis if i.highest_severity == Severity.CRITICAL)
    nhi_high = sum(1 for i in nhis if i.highest_severity == Severity.HIGH)
    nhi_med = sum(1 for i in nhis if i.highest_severity == Severity.MEDIUM)
    nhi_low = sum(1 for i in nhis if i.highest_severity == Severity.LOW)
    nhi_ok = sum(1 for i in nhis if i.highest_severity == Severity.INFO)

    out.write(f"  {'─' * 56}\n")
    out.write(f"  Summary: {len(nhis)} NHIs")
    out.write(f" | {RED}{nhi_crit} critical{RESET}")
    out.write(f" | {RED}{nhi_high} high{RESET}")
    out.write(f" | {YELLOW}{nhi_med} medium{RESET}")
    out.write(f" | {CYAN}{nhi_low} low{RESET}")
    out.write(f" | {GREEN}{nhi_ok} healthy{RESET}\n\n")

    # Scorecard (if identities exist)
    if nhis:
        _print_scorecard(nhis, out)


def _print_scorecard(nhis, out: TextIO = sys.stdout) -> None:
    """Print the NHI security scorecard with NIST + governance metrics."""
    from nhinsight.analyzers.scoring import compute_scorecard

    card = compute_scorecard(nhis)

    # Grade color
    grade_colors = {"A": GREEN, "B": GREEN, "C": YELLOW, "D": RED, "F": RED}
    gc = grade_colors.get(card.grade, RESET)

    out.write(f"  {'═' * 56}\n")
    out.write(f"  {BOLD}NHI Security Scorecard{RESET}\n")
    out.write(f"  {'─' * 56}\n\n")

    # Attack Surface Score + Grade
    score_str = f"{card.attack_surface_score:.0f} / 100  ({card.grade})"
    out.write(f"  {BOLD}Attack Surface Score:{RESET}  {gc}{score_str}{RESET}\n")
    out.write(f"  {DIM}Risk Points: {card.risk_score}{RESET}\n\n")

    # CISO Metrics — the 4 board-level numbers
    cm = card.ciso_metrics
    out.write(f"  {BOLD}Key Metrics (CISO Dashboard){RESET}\n")

    own_c = GREEN if cm.pct_with_owner >= 80 else (YELLOW if cm.pct_with_owner >= 50 else RED)
    stl_c = GREEN if cm.pct_stale <= 5 else (YELLOW if cm.pct_stale <= 15 else RED)
    adm_c = GREEN if cm.pct_admin <= 5 else (YELLOW if cm.pct_admin <= 15 else RED)
    sec_c = GREEN if cm.pct_long_lived_secrets <= 5 else (YELLOW if cm.pct_long_lived_secrets <= 15 else RED)

    out.write(f"  ├─ Identities with owner:     {own_c}{cm.pct_with_owner:5.1f}%{RESET}\n")
    out.write(f"  ├─ Stale identities (>90d):   {stl_c}{cm.pct_stale:5.1f}%{RESET}\n")
    out.write(f"  ├─ Admin / dangerous access:  {adm_c}{cm.pct_admin:5.1f}%{RESET}\n")
    out.write(f"  └─ Long-lived secrets:        {sec_c}{cm.pct_long_lived_secrets:5.1f}%{RESET}\n\n")

    # Governance Pillars
    gov = card.governance
    out.write(f"  {BOLD}Governance Score:{RESET}  {_bar(gov.overall)} {gov.overall:.0%}\n")
    out.write(f"  ├─ Ownership:            {_bar(gov.ownership_coverage)} {gov.ownership_coverage:.0%}\n")
    out.write(f"  ├─ Credential rotation:  {_bar(gov.credential_rotation)} {gov.credential_rotation:.0%}\n")
    out.write(f"  ├─ Least privilege:      {_bar(gov.least_privilege)} {gov.least_privilege:.0%}\n")
    out.write(f"  └─ Lifecycle hygiene:    {_bar(gov.lifecycle_hygiene)} {gov.lifecycle_hygiene:.0%}\n\n")

    # NIST Compliance Summary (only show FAIL + PARTIAL)
    fails = [f for f in card.nist_controls.values() if f.status == "FAIL"]
    partials = [f for f in card.nist_controls.values() if f.status == "PARTIAL"]
    passes = [f for f in card.nist_controls.values() if f.status == "PASS"]
    total_ctrl = len(card.nist_controls)

    out.write(f"  {BOLD}NIST SP 800-53 Compliance{RESET}\n")
    out.write(f"  {GREEN}PASS: {len(passes)}{RESET}  ")
    out.write(f"{YELLOW}PARTIAL: {len(partials)}{RESET}  ")
    out.write(f"{RED}FAIL: {len(fails)}{RESET}  (of {total_ctrl} controls)\n")

    if fails:
        out.write(f"\n  {RED}Failed controls:{RESET}\n")
        for f in sorted(fails, key=lambda x: x.identities, reverse=True)[:8]:
            viol = f"({f.identities}/{f.total})"
            out.write(f"  {RED}  ✗ {f.control_id:<10s}{RESET}")
            out.write(f" {f.control_family}  {viol}\n")

    if partials:
        out.write(f"\n  {YELLOW}Partial controls:{RESET}\n")
        for f in sorted(partials, key=lambda x: x.identities, reverse=True)[:5]:
            viol = f"({f.identities}/{f.total})"
            out.write(f"  {YELLOW}  ~ {f.control_id:<10s}{RESET}")
            out.write(f" {f.control_family}  {viol}\n")

    out.write(f"\n  {'─' * 56}\n\n")


def _bar(value: float, width: int = 10) -> str:
    """Render a small progress bar like [████░░░░░░]."""
    filled = int(value * width)
    empty = width - filled
    if value >= 0.75:
        color = GREEN
    elif value >= 0.5:
        color = YELLOW
    else:
        color = RED
    return f"{color}[{'█' * filled}{'░' * empty}]{RESET}"


def print_json(result: ScanResult, out: TextIO = sys.stdout) -> None:
    """Print scan results as JSON, including security scorecard."""
    from nhinsight.analyzers.scoring import compute_scorecard
    from nhinsight.core.models import Classification

    data = result.to_dict()
    nhis = [i for i in result.identities if i.classification != Classification.HUMAN]
    if nhis:
        card = compute_scorecard(nhis)
        data["scorecard"] = card.to_dict()
    out.write(json.dumps(data, indent=2, default=str))
    out.write("\n")


def print_sarif(result: ScanResult, out: TextIO = sys.stdout) -> None:
    """Print scan results in SARIF format for GitHub Security tab."""
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "NHInsight",
                    "version": "0.1.0",
                    "informationUri": "https://github.com/cvemula1/NHInsight",
                    "rules": [],
                }
            },
            "results": [],
        }],
    }

    seen_rules = set()
    run = sarif["runs"][0]

    for ident in result.identities:
        for flag in ident.risk_flags:
            # Add rule if not seen
            if flag.code not in seen_rules:
                seen_rules.add(flag.code)
                run["tool"]["driver"]["rules"].append({
                    "id": flag.code,
                    "shortDescription": {"text": flag.message},
                    "defaultConfiguration": {
                        "level": "error" if flag.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
                    },
                })

            # Add result
            run["results"].append({
                "ruleId": flag.code,
                "level": "error" if flag.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
                "message": {"text": f"{ident.name}: {flag.message}. {flag.detail}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"{ident.provider.value}/{ident.identity_type.value}/{ident.name}",
                        }
                    }
                }],
            })

    out.write(json.dumps(sarif, indent=2))
    out.write("\n")


def _md_identity_block(ident, out):
    """Write a single identity block in markdown."""
    out.write(f"**{ident.name}** — `{ident.identity_type.value}` / "
               f"`{ident.provider.value}`\n\n")
    if ident.risk_flags:
        for flag in ident.risk_flags:
            out.write(f"- **[{flag.severity.value.upper()}] {flag.code}**: {flag.message}\n")
            if flag.detail:
                out.write(f"  - {flag.detail}\n")
        out.write("\n")
    else:
        out.write("- No risk flags\n\n")


def print_markdown(result: ScanResult, out: TextIO = sys.stdout) -> None:
    """Print scan results as a Markdown report."""
    from nhinsight.core.models import Classification

    nhis = [i for i in result.identities if i.classification != Classification.HUMAN]
    humans = [i for i in result.identities if i.classification == Classification.HUMAN]

    out.write("# NHInsight — Non-Human Identity Report\n\n")

    if result.providers_scanned:
        out.write(f"**Providers:** {', '.join(result.providers_scanned)}  \n")
    if result.scan_time:
        out.write(f"**Scan time:** {result.scan_time.strftime('%Y-%m-%d %H:%M UTC')}  \n")
    out.write(f"**Total NHIs:** {len(nhis)}  \n")
    if humans:
        out.write(f"**Related humans:** {len(humans)}  \n")
    out.write("\n")

    # Summary table (NHIs only)
    nhi_crit = sum(1 for i in nhis if i.highest_severity == Severity.CRITICAL)
    nhi_high = sum(1 for i in nhis if i.highest_severity == Severity.HIGH)
    nhi_med = sum(1 for i in nhis if i.highest_severity == Severity.MEDIUM)
    nhi_low = sum(1 for i in nhis if i.highest_severity == Severity.LOW)
    nhi_ok = sum(1 for i in nhis if i.highest_severity == Severity.INFO)

    out.write("## Summary\n\n")
    out.write("| Severity | Count |\n")
    out.write("|----------|-------|\n")
    out.write(f"| Critical | {nhi_crit} |\n")
    out.write(f"| High | {nhi_high} |\n")
    out.write(f"| Medium | {nhi_med} |\n")
    out.write(f"| Low | {nhi_low} |\n")
    out.write(f"| Healthy | {nhi_ok} |\n\n")

    # NHI findings by severity
    out.write("## Findings\n\n")
    sev_icons = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "🟢"}

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
        group = [i for i in nhis if i.highest_severity == sev]
        if not group:
            continue
        icon = sev_icons.get(sev.value, "⚪")
        out.write(f"### {icon} {sev.value.upper()} ({len(group)})\n\n")
        for ident in group:
            _md_identity_block(ident, out)

    # Related humans
    if humans:
        out.write("## Related Human Identities\n\n")
        for h in humans:
            _md_identity_block(h, out)

    # Urgent fixes
    urgent = _get_urgent_fixes(result)
    if urgent:
        out.write("## Urgent Fixes\n\n")
        for i, fix in enumerate(urgent, 1):
            out.write(f"{i}. {fix}\n")
        out.write("\n")

    out.write("---\n")
    out.write("*Generated by [NHInsight](https://github.com/cvemula1/NHInsight)*\n")


def _get_urgent_fixes(result: ScanResult, limit: int = 5) -> list:
    """Extract the top N most urgent fixes from scan results."""
    urgent = []

    # Collect all critical and high findings with actionable messages
    for ident in result.identities:
        for flag in ident.risk_flags:
            if flag.severity in (Severity.CRITICAL, Severity.HIGH):
                urgent.append((flag.severity, ident.name, flag.code, flag.detail or flag.message))

    # Sort: critical first, then high
    order = {Severity.CRITICAL: 0, Severity.HIGH: 1}
    urgent.sort(key=lambda x: order.get(x[0], 99))

    return [f"**{name}** — {detail}" for _, name, _, detail in urgent[:limit]]


def print_attack_paths(ap_result, out: TextIO = sys.stdout) -> None:
    """Print attack path analysis results."""
    paths = ap_result.paths
    stats = ap_result.graph_stats

    out.write(f"\n  {'═' * 56}\n")
    out.write(f"  {BOLD}Privilege Escalation Paths{RESET}\n")
    out.write(f"  {'─' * 56}\n\n")

    out.write(f"  Graph: {stats.get('nodes', 0)} nodes, ")
    out.write(f"{stats.get('edges', 0)} edges, ")
    out.write(f"{stats.get('entry_points', 0)} entry points, ")
    out.write(f"{stats.get('privileged_nodes', 0)} privileged\n\n")

    if not paths:
        out.write(f"  {GREEN}No attack paths detected.{RESET}\n\n")
        return

    crit = len(ap_result.critical_paths)
    high = len(ap_result.high_paths)
    cross = len(ap_result.cross_system_paths)

    out.write(f"  {BOLD}Paths found: {len(paths)}{RESET}")
    out.write(f" | {RED}{crit} critical{RESET}")
    out.write(f" | {RED}{high} high{RESET}")
    out.write(f" | {CYAN}{cross} cross-system{RESET}\n\n")

    # Show top paths (limit to 15)
    for i, path in enumerate(paths[:15]):
        sev = path.severity
        color = SEVERITY_COLORS.get(sev, RESET)
        icon = SEVERITY_ICONS.get(sev, "⚪")

        out.write(f"  {color}{icon} {path.id} — {path.description}{RESET}")
        out.write(f"  {BOLD}{sev.value.upper()}{RESET}")
        blast_str = f"  risk: {path.blast_radius:.0f}/100"
        out.write(f"  {DIM}{blast_str}{RESET}")
        if path.cross_system:
            out.write(f"  {CYAN}⚡ cross-system{RESET}")
        out.write("\n")

        # Steps
        for j, step in enumerate(path.steps):
            is_last = j == len(path.steps) - 1
            connector = "└─" if is_last else "├─"
            arrow = ""
            if step.edge_label:
                arrow = f" {DIM}({step.edge_label}){RESET}"

            prov_tag = f"[{step.provider}]"
            out.write(f"  {color}  {connector}{RESET} ")
            out.write(f"{BOLD}{step.node_label}{RESET}")
            out.write(f"  {DIM}{prov_tag}{RESET}")
            out.write(f"{arrow}\n")

        # Recommendation
        if path.recommendation:
            rec = path.recommendation[:100]
            out.write(f"  {DIM}  💡 {rec}{RESET}\n")

        out.write("\n")

    if len(paths) > 15:
        remaining = len(paths) - 15
        out.write(f"  {DIM}... and {remaining} more paths{RESET}\n\n")

    out.write(f"  {'─' * 56}\n\n")


def print_result(result: ScanResult, fmt: str = "table", out: TextIO = sys.stdout) -> None:
    """Print scan results in the requested format."""
    if fmt == "json":
        print_json(result, out)
    elif fmt == "sarif":
        print_sarif(result, out)
    elif fmt == "markdown" or fmt == "md":
        print_markdown(result, out)
    else:
        print_table(result, out)

"""
Renders the aggregated results (see aggregator.aggregate) to:
  - console: a set of rich tables, for a quick look after a run
  - report/summary.json: the full aggregate, for programmatic consumption
  - report/findings.csv: every individual Finding, flattened, for Excel/Sheets

Kept deliberately simple - if you want a polished, presentable compliance
report (charts, a scored dashboard), export findings.csv/summary.json and
build that with the xlsx or docx skill/tooling rather than growing this
module into a report designer.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd
from rich.console import Console
from rich.table import Table

from .schema import Finding

logger = logging.getLogger(__name__)
console = Console()


def write_report(findings: list[Finding], aggregate: dict[str, Any], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_path = out_dir / "summary.json"
    summary_path.write_text(json.dumps(aggregate, indent=2, default=str))
    logger.info("Wrote %s", summary_path)

    findings_path = out_dir / "findings.csv"
    df = pd.DataFrame([f.to_dict() for f in findings])
    if not df.empty:
        df["raw"] = df["raw"].astype(str)  # keep CSV flat/readable
    df.to_csv(findings_path, index=False)
    logger.info("Wrote %s (%d rows)", findings_path, len(df))


def print_console_summary(aggregate: dict[str, Any]) -> None:
    _print_totals_table(aggregate)
    _print_tool_table(aggregate)
    _print_zt_pillar_table(aggregate)
    _print_framework_table(aggregate, "nist_800_53", "NIST 800-53 rev5 controls")
    _print_framework_table(aggregate, "cis_controls", "CIS Controls v8")

    if aggregate.get("unmapped_techniques"):
        console.print(
            f"\n[yellow]Seen but unmapped ATT&CK techniques (not in data/attack_crosswalk.generated.json "
            f"or data/control_mappings.yaml): {', '.join(aggregate['unmapped_techniques'])}[/yellow]"
        )
    if aggregate.get("fallback_techniques"):
        console.print(
            f"[dim]Sub-techniques resolved via their base technique's mapping "
            f"(no dedicated sub-technique entry in the crosswalk): "
            f"{', '.join(aggregate['fallback_techniques'])}[/dim]"
        )
    if aggregate.get("pillar_gaps"):
        console.print(
            f"[yellow]Zero Trust pillars with NO evidence from any configured tool: "
            f"{', '.join(aggregate['pillar_gaps'])}[/yellow]"
        )


def _print_totals_table(aggregate: dict[str, Any]) -> None:
    table = Table(title="Overall totals")
    table.add_column("Status")
    table.add_column("Count", justify="right")
    for status, count in sorted(aggregate["totals"].items()):
        table.add_row(status, str(count))
    console.print(table)


def _print_tool_table(aggregate: dict[str, Any]) -> None:
    table = Table(title="By source tool")
    table.add_column("Tool")
    table.add_column("Pass", justify="right")
    table.add_column("Fail", justify="right")
    table.add_column("Error", justify="right")
    table.add_column("Unknown", justify="right")
    for tool, counts in sorted(aggregate["by_tool"].items()):
        table.add_row(
            tool,
            str(counts.get("pass", 0)),
            str(counts.get("fail", 0)),
            str(counts.get("error", 0)),
            str(counts.get("unknown", 0)),
        )
    console.print(table)


def _print_zt_pillar_table(aggregate: dict[str, Any]) -> None:
    table = Table(title="Zero Trust Maturity - by pillar")
    table.add_column("Pillar")
    table.add_column("Pass", justify="right")
    table.add_column("Fail", justify="right")
    table.add_column("Tools reporting")
    for pillar, counts in sorted(aggregate["by_zt_pillar"].items()):
        table.add_row(
            pillar,
            str(counts.get("pass", 0)),
            str(counts.get("fail", 0)),
            ", ".join(counts.get("tools_reporting", [])) or "-",
        )
    console.print(table)


def write_ai_report(findings: list, ai_aggregate: dict[str, Any], out_dir: Path) -> None:
    """Same idea as write_report(), for the parallel garak/OWASP pipeline."""
    out_dir.mkdir(parents=True, exist_ok=True)

    summary_path = out_dir / "ai_summary.json"
    summary_path.write_text(json.dumps(ai_aggregate, indent=2, default=str))
    logger.info("Wrote %s", summary_path)

    garak_findings = [f for f in findings if f.source_tool == "garak"]
    findings_path = out_dir / "ai_findings.csv"
    df = pd.DataFrame([f.to_dict() for f in garak_findings])
    if not df.empty:
        df["raw"] = df["raw"].astype(str)
    df.to_csv(findings_path, index=False)
    logger.info("Wrote %s (%d rows)", findings_path, len(df))


def print_ai_console_summary(ai_aggregate: dict[str, Any]) -> None:
    table = Table(title="garak findings - overall totals")
    table.add_column("Status")
    table.add_column("Count", justify="right")
    for status, count in sorted(ai_aggregate["totals"].items()):
        table.add_row(status, str(count))
    console.print(table)

    cat_table = Table(title="OWASP LLM Top 10 - by category")
    cat_table.add_column("Category")
    cat_table.add_column("Pass", justify="right")
    cat_table.add_column("Fail", justify="right")
    cat_table.add_column("Probes")
    for cat_id, counts in sorted(ai_aggregate["by_owasp_category"].items()):
        cat_table.add_row(
            cat_id,
            str(counts.get("pass", 0)),
            str(counts.get("fail", 0)),
            ", ".join(counts.get("probes", [])) or "-",
        )
    console.print(cat_table)

    pillar_table = Table(title="Zero Trust pillars touched by AI red-team findings")
    pillar_table.add_column("Pillar")
    pillar_table.add_column("Pass", justify="right")
    pillar_table.add_column("Fail", justify="right")
    for pillar, counts in sorted(ai_aggregate["by_zt_pillar"].items()):
        pillar_table.add_row(pillar, str(counts.get("pass", 0)), str(counts.get("fail", 0)))
    console.print(pillar_table)

    if ai_aggregate.get("unmapped_probes"):
        console.print(
            f"\n[yellow]garak probes seen but not in garak_probe_tags.generated.json "
            f"(re-run extract_garak_probe_tags.py?): {', '.join(ai_aggregate['unmapped_probes'])}[/yellow]"
        )
    if ai_aggregate.get("uncovered_categories"):
        console.print(
            f"[dim]OWASP categories with no findings routed to them yet "
            f"(LLM03 Supply Chain is always expected here - see SOURCES.md): "
            f"{', '.join(ai_aggregate['uncovered_categories'])}[/dim]"
        )


def _print_framework_table(aggregate: dict[str, Any], framework_key: str, title: str) -> None:
    data = aggregate["by_framework"].get(framework_key, {})
    if not data:
        return
    table = Table(title=title)
    table.add_column("Control")
    table.add_column("Pass", justify="right")
    table.add_column("Fail", justify="right")
    for control_id, counts in sorted(data.items()):
        table.add_row(control_id, str(counts.get("pass", 0)), str(counts.get("fail", 0)))
    console.print(table)

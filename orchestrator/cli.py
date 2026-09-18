"""Command-line entry point: `python main.py <command> ...`"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import click

from .aggregator import aggregate, load_mappings
from .ai_aggregator import aggregate_ai, load_owasp_mapping
from .connectors.vanta import VantaClient, build_resources
from .parsers import (
    parse_atomic_dir,
    parse_caldera_dir,
    parse_garak_dir,
    parse_openscap_dir,
    parse_pingcastle_dir,
    parse_prowler_dir,
)
from .report import print_ai_console_summary, print_console_summary, write_ai_report, write_report

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")


@click.group()
def cli() -> None:
    """Compliance orchestrator - aggregation side (execution is Ansible's job)."""


@cli.command()
@click.option(
    "--results-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("results"),
    show_default=True,
    help="Directory Ansible wrote raw tool output into.",
)
@click.option(
    "--overlay",
    "overlay_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("data/control_mappings.yaml"),
    show_default=True,
    help="Curated Zero Trust pillar / ISO 27001 overlay.",
)
@click.option(
    "--crosswalk",
    "crosswalk_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Generated ATT&CK->NIST->CIS crosswalk (default: data/attack_crosswalk.generated.json). "
    "Run `python3 data/build_crosswalk.py` first if it doesn't exist yet.",
)
@click.option(
    "--out",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("report"),
    show_default=True,
    help="Directory to write summary.json and findings.csv into.",
)
def aggregate_cmd(results_dir: Path, overlay_path: Path, crosswalk_path: Path | None, out: Path) -> None:
    """Parse all tool output under RESULTS_DIR and write a rolled-up report."""
    from .aggregator import DEFAULT_CROSSWALK_PATH

    mapping_data = load_mappings(overlay_path, crosswalk_path or DEFAULT_CROSSWALK_PATH)

    findings = []
    findings += parse_caldera_dir(results_dir)
    findings += parse_atomic_dir(results_dir)
    findings += parse_prowler_dir(results_dir)
    findings += parse_openscap_dir(results_dir)
    findings += parse_pingcastle_dir(results_dir)

    if not findings:
        click.echo(
            f"No findings parsed from {results_dir}. Have you run the Ansible "
            f"playbooks yet? (ansible-playbook ansible/playbooks/site.yml)"
        )
        return

    agg = aggregate(findings, mapping_data)
    write_report(findings, agg, out)
    print_console_summary(agg)


# click expects the command registered under the name the CLI is invoked
# with; keep "aggregate" as the visible subcommand name.
cli.add_command(aggregate_cmd, name="aggregate")


@cli.command()
@click.option(
    "--summary",
    "summary_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=Path("report/summary.json"),
    show_default=True,
    help="Output of `python main.py aggregate` to push.",
)
@click.option("--client-id", envvar="VANTA_CLIENT_ID", default=None, help="Or set VANTA_CLIENT_ID.")
@click.option("--client-secret", envvar="VANTA_CLIENT_SECRET", default=None, help="Or set VANTA_CLIENT_SECRET.")
@click.option("--resource-id", envvar="VANTA_RESOURCE_ID", default=None, help="Or set VANTA_RESOURCE_ID.")
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Build and print the resources that would be pushed, without calling Vanta or needing credentials.",
)
def push_vanta_cmd(summary_path: Path, client_id: str | None, client_secret: str | None, resource_id: str | None, dry_run: bool) -> None:
    """Push a completed aggregate() summary to Vanta as Custom Resources.

    Requires a one-time Custom Resource + Custom Test set up in the Vanta UI
    first - see README.md "GRC hand-off (Vanta)". --dry-run works with no
    credentials and no network call, useful for checking the payload shape.
    """
    aggregate_data = json.loads(summary_path.read_text())
    resources = build_resources(aggregate_data)

    if dry_run:
        click.echo(json.dumps(resources, indent=2))
        click.echo(f"\n{len(resources)} resources built (dry run - nothing sent).")
        return

    missing = [name for name, val in [("--client-id", client_id), ("--client-secret", client_secret), ("--resource-id", resource_id)] if not val]
    if missing:
        raise click.UsageError(
            f"Missing {', '.join(missing)} (or the matching VANTA_* env var). Use --dry-run to preview without them."
        )

    client = VantaClient(client_id=client_id, client_secret=client_secret, resource_id=resource_id)
    result = client.push(resources)
    click.echo(json.dumps(result, indent=2))


cli.add_command(push_vanta_cmd, name="push-vanta")


@cli.command()
@click.option(
    "--results-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=Path("results"),
    show_default=True,
    help="Directory Ansible wrote raw tool output into (looks under results/garak/).",
)
@click.option(
    "--probe-tags",
    "probe_tags_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Generated garak probe->OWASP tag file (default: data/ai_redteam/garak_probe_tags.generated.json).",
)
@click.option(
    "--categories",
    "categories_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="OWASP LLM Top 10 category/pillar reference (default: data/ai_redteam/owasp_llm_top10_2025.yaml).",
)
@click.option(
    "--out",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path("report/ai"),
    show_default=True,
    help="Directory to write ai_summary.json and ai_findings.csv into.",
)
def aggregate_ai_cmd(results_dir: Path, probe_tags_path: Path | None, categories_path: Path | None, out: Path) -> None:
    """Parse garak output under RESULTS_DIR and roll it up against OWASP LLM Top 10.

    Kept separate from `aggregate` on purpose - see
    data/ai_redteam/SOURCES.md for why AI red-team findings get their own
    report rather than being merged into the NIST/CIS/ATT&CK one.
    """
    from .ai_aggregator import DEFAULT_CATEGORIES_PATH, DEFAULT_PROBE_TAGS_PATH

    mapping_data = load_owasp_mapping(
        probe_tags_path or DEFAULT_PROBE_TAGS_PATH,
        categories_path or DEFAULT_CATEGORIES_PATH,
    )

    findings = parse_garak_dir(results_dir)

    if not findings:
        click.echo(
            f"No garak findings parsed from {results_dir}/garak. Have you run "
            f"`ansible-playbook ansible/playbooks/run_garak.yml` yet?"
        )
        return

    agg = aggregate_ai(findings, mapping_data)
    write_ai_report(findings, agg, out)
    print_ai_console_summary(agg)


cli.add_command(aggregate_ai_cmd, name="aggregate-ai")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
